param([string]$JavaHome = $env:JAVA_HOME)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($JavaHome)) { $JavaHome = Join-Path $projectRoot 'build/toolchain/jdk-17.0.21+9' }
$outputDirectory = Join-Path $projectRoot 'build/slot-frequency-tests'
New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
& (Join-Path $JavaHome 'bin/javac.exe') -encoding UTF-8 -d $outputDirectory (Join-Path $projectRoot 'app/src/main/java/com/gpucheck/app/GpuSlotFrequency.java') (Join-Path $projectRoot 'tests/GpuSlotFrequencyTest.java')
if ($LASTEXITCODE -ne 0) { throw 'GPU slot frequency policy compilation failed' }
& (Join-Path $JavaHome 'bin/java.exe') -cp $outputDirectory GpuSlotFrequencyTest
if ($LASTEXITCODE -ne 0) { throw 'GPU slot frequency policy tests failed' }
