param(
    [string]$JavaHome = $env:JAVA_HOME
)

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
$outputDirectory = Join-Path $projectRoot 'build\policy-tests'
$policySource = Join-Path $projectRoot 'app\src\main\java\com\gpucheck\app\RiskPolicy.java'
$testSource = Join-Path $projectRoot 'tests\RiskPolicyTest.java'
$candidateSource = Join-Path $projectRoot 'app\src\main\java\com\gpucheck\app\CandidatePolicy.java'
$candidateTestSource = Join-Path $projectRoot 'tests\CandidatePolicyTest.java'
$avcSource = Join-Path $projectRoot 'app\src\main\java\com\gpucheck\app\AvcRiskPolicy.java'
$avcTestSource = Join-Path $projectRoot 'tests\AvcRiskPolicyTest.java'
New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null

& $compilerPath -encoding UTF-8 -d $outputDirectory $policySource $testSource $candidateSource $candidateTestSource $avcSource $avcTestSource
if ($LASTEXITCODE -ne 0) { throw "Policy test compilation failed with exit code $LASTEXITCODE." }
& $runtimePath -ea -cp $outputDirectory com.gpucheck.app.RiskPolicyTest
if ($LASTEXITCODE -ne 0) { throw "Policy tests failed with exit code $LASTEXITCODE." }
& $runtimePath -ea -cp $outputDirectory com.gpucheck.app.CandidatePolicyTest
if ($LASTEXITCODE -ne 0) { throw "Candidate policy tests failed with exit code $LASTEXITCODE." }
& $runtimePath -ea -cp $outputDirectory com.gpucheck.app.AvcRiskPolicyTest
if ($LASTEXITCODE -ne 0) { throw "AVC risk policy tests failed with exit code $LASTEXITCODE." }
