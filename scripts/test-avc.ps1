param(
    [string]$JavaHome = $env:JAVA_HOME,
    [string]$SdkRoot = 'D:\Android\SDK',
    [string]$DeviceLog = ''
)
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($JavaHome)) { $JavaHome = 'D:\Android\Android Studio Last\jbr' }
$projectRoot = Split-Path -Parent $PSScriptRoot
$outputDirectory = Join-Path $projectRoot 'build\avc-tests'
$androidJar = Join-Path $SdkRoot 'platforms\android-35\android.jar'
$compilerPath = Join-Path $JavaHome 'bin\javac.exe'
$runtimePath = Join-Path $JavaHome 'bin\java.exe'
$source = Join-Path $projectRoot 'app\src\main\java\com\gpucheck\app\AvcEvidence.java'
$tests = Join-Path $projectRoot 'tests\AvcEvidenceTest.java'
New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
& $compilerPath -encoding UTF-8 -cp $androidJar -d $outputDirectory $source $tests
if ($LASTEXITCODE -ne 0) { throw "AVC test compilation failed: $LASTEXITCODE" }
$testArguments = @('-ea', '-cp', "$outputDirectory;$androidJar", 'com.gpucheck.app.AvcEvidenceTest')
if ($DeviceLog) { $testArguments += $DeviceLog }
& $runtimePath @testArguments
if ($LASTEXITCODE -ne 0) { throw "AVC tests failed: $LASTEXITCODE" }
