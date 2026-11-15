param([string]$Compiler = 'D:\Android\SDK\ndk\llvm-mingw-20220323-ucrt-x86_64\bin\clang++.exe')
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$outputDirectory = Join-Path $projectRoot 'build\gpuexec-multi-test'
New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
$executable = Join-Path $outputDirectory 'core-test.exe'
& $Compiler -std=c++17 -O2 -Wall -Wextra -Werror -pedantic -static (Join-Path $projectRoot 'tests\gpu_exec_core_test.cpp') -o $executable
if ($LASTEXITCODE -ne 0) { throw 'GPU execution test compilation failed' }
& $executable
if ($LASTEXITCODE -ne 0) { throw "GPU execution tests failed: $LASTEXITCODE" }
