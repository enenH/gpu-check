param(
    [string]$SdkRoot = 'D:\Android\SDK',
    [string]$NativeBinary,
    [string]$OutputRoot
)

$ErrorActionPreference = 'Stop'
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
if (-not $NativeBinary) { $NativeBinary = Join-Path $projectRoot 'build\cgroup-device-test\bin\cgroup_audit' }
if (-not $OutputRoot) { $OutputRoot = Join-Path $projectRoot 'build\cgroup-device-test\app-probe' }
$NativeBinary = [System.IO.Path]::GetFullPath($NativeBinary)
$OutputRoot = [System.IO.Path]::GetFullPath($OutputRoot)
$buildTools = Join-Path $SdkRoot 'build-tools\35.0.1'
$androidJar = Join-Path $SdkRoot 'platforms\android-35\android.jar'
$debugKeystore = Join-Path $env:USERPROFILE '.android\debug.keystore'

foreach ($required in @($NativeBinary, $androidJar, $debugKeystore,
        (Join-Path $buildTools 'aapt2.exe'), (Join-Path $buildTools 'd8.bat'),
        (Join-Path $buildTools 'zipalign.exe'), (Join-Path $buildTools 'apksigner.bat'))) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "Missing input: $required" }
}

$classesDir = Join-Path $OutputRoot 'classes'
$dexDir = Join-Path $OutputRoot 'dex'
New-Item -ItemType Directory -Force -Path $OutputRoot, $classesDir, $dexDir | Out-Null
$javaSource = Join-Path $PSScriptRoot 'src\com\gpucheck\cgroupaudit\AuditInstrumentation.java'
& javac -encoding UTF-8 -source 8 -target 8 -classpath $androidJar -d $classesDir $javaSource
if ($LASTEXITCODE -ne 0) { throw 'javac failed' }
$classFiles = @(Get-ChildItem -LiteralPath $classesDir -Filter '*.class' -Recurse | ForEach-Object FullName)
& (Join-Path $buildTools 'd8.bat') --release --min-api 26 --lib $androidJar --output $dexDir @classFiles
if ($LASTEXITCODE -ne 0) { throw 'd8 failed' }

$unsigned = Join-Path $OutputRoot 'unsigned-unaligned.apk'
$aligned = Join-Path $OutputRoot 'unsigned-aligned.apk'
$signed = Join-Path $OutputRoot 'CgroupAuditTest.apk'
& (Join-Path $buildTools 'aapt2.exe') link -o $unsigned --manifest (Join-Path $PSScriptRoot 'AndroidManifest.xml') -I $androidJar --min-sdk-version 26 --target-sdk-version 35 --version-code 1 --version-name '1.0'
if ($LASTEXITCODE -ne 0) { throw 'aapt2 link failed' }

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::Open($unsigned, [System.IO.Compression.ZipArchiveMode]::Update)
try {
    [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, (Join-Path $dexDir 'classes.dex'), 'classes.dex') | Out-Null
    [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $NativeBinary, 'lib/arm64-v8a/libcgroup_audit.so') | Out-Null
} finally {
    $zip.Dispose()
}
& (Join-Path $buildTools 'zipalign.exe') -P 16 -f 4 $unsigned $aligned
if ($LASTEXITCODE -ne 0) { throw 'zipalign failed' }
& (Join-Path $buildTools 'apksigner.bat') sign --ks $debugKeystore --ks-key-alias androiddebugkey --ks-pass pass:android --key-pass pass:android --out $signed $aligned
if ($LASTEXITCODE -ne 0) { throw 'apksigner sign failed' }
& (Join-Path $buildTools 'apksigner.bat') verify $signed
if ($LASTEXITCODE -ne 0) { throw 'apksigner verify failed' }
& (Join-Path $buildTools 'aapt2.exe') dump permissions $signed
if ($LASTEXITCODE -ne 0) { throw 'aapt2 permissions verification failed' }
Write-Output $signed
