param([string]$JavaHome = $env:JAVA_HOME)
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($JavaHome)) { $JavaHome = 'D:\Android\Android Studio Last\jbr' }
$projectRoot = Split-Path -Parent $PSScriptRoot
$outputDirectory = Join-Path $projectRoot 'build\overlay-tests'
New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
$sourceRoot = Join-Path $projectRoot 'app\src\main\java\com\gpucheck\app'
& (Join-Path $JavaHome 'bin\javac.exe') -encoding UTF-8 -d $outputDirectory (Join-Path $sourceRoot 'LayerReplyDecoder.java') (Join-Path $sourceRoot 'LayerNamePolicy.java') (Join-Path $sourceRoot 'LayerTextParser.java') (Join-Path $projectRoot 'tests\OverlayPolicyTest.java')
if ($LASTEXITCODE -ne 0) { throw 'Overlay test compilation failed' }
& (Join-Path $JavaHome 'bin\java.exe') -ea -cp $outputDirectory com.gpucheck.app.OverlayPolicyTest
if ($LASTEXITCODE -ne 0) { throw 'Overlay policy tests failed' }
