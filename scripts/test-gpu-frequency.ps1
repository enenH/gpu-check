param([string]$JavaHome = $env:JAVA_HOME)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($JavaHome)) {
    $JavaHome = 'D:\Android\Android Studio Last\jbr'
}
$compilerPath = Join-Path $JavaHome 'bin\javac.exe'
$runtimePath = Join-Path $JavaHome 'bin\java.exe'
if (!(Test-Path -LiteralPath $compilerPath) -or !(Test-Path -LiteralPath $runtimePath)) {
    throw "JDK not found at '$JavaHome'. Set JAVA_HOME or pass -JavaHome."
}
$projectRoot = Split-Path -Parent $PSScriptRoot
$outputDirectory = Join-Path $projectRoot 'build\gpu-frequency-tests'
$source = Join-Path $projectRoot 'app\src\main\java\com\gpucheck\app\GpuHighFrequency.java'
$testSource = Join-Path $projectRoot 'tests\GpuHighFrequencyTest.java'
New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
& $compilerPath -encoding UTF-8 -d $outputDirectory $source $testSource
if ($LASTEXITCODE -ne 0) { throw "GPU frequency test compilation failed: $LASTEXITCODE" }
& $runtimePath -ea -cp $outputDirectory com.gpucheck.app.GpuHighFrequencyTest
if ($LASTEXITCODE -ne 0) { throw "GPU frequency tests failed: $LASTEXITCODE" }
