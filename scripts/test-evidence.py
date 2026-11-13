#!/usr/bin/env python3
"""Host regression suite; requires a JDK, C++17 compiler, and an org.json JAR."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-jar", required=True, type=Path,
                        help="org.json runtime JAR (not the stub classes in android.jar)")
    args = parser.parse_args()
    json_jar = args.json_jar.resolve(strict=True)
    root = Path(__file__).resolve().parents[1]
    output = root / "build" / "evidence-tests"
    output.mkdir(parents=True, exist_ok=True)
    java = shutil.which("java")
    compiler = shutil.which(os.environ.get("CXX", "g++"))
    if not java or not compiler:
        parser.error("A JDK and a C++17 compiler (CXX or g++) must be available")
    javac = shutil.which("javac")
    javac_command = [javac] if javac else [java, "-m", "jdk.compiler/com.sun.tools.javac.Main"]
    names = ["RiskPolicy", "CandidatePolicy", "AvcRiskPolicy", "CpuGpuLifecycle",
             "CgroupWatchPolicy", "MonitoredProcessFilter", "RootProcessFilter", "GpuHighFrequency", "SelfGpuFilter",
             "LayerNamePolicy", "LayerReplyDecoder", "LayerTextParser", "ReportExport", "DomainEvidence"]
    tests = ["RiskPolicyTest", "CandidatePolicyTest", "AvcRiskPolicyTest", "CpuGpuLifecycleTest",
             "CgroupWatchPolicyTest", "RootProcessFilterTest", "GpuHighFrequencyTest",
             "SelfGpuFilterTest", "OverlayPolicyTest", "ReportExportTest", "DomainEvidenceTest"]
    sources = [root / "app/src/main/java/com/gpucheck/app" / (name + ".java") for name in names]
    sources += [root / "tests" / (name + ".java") for name in tests]
    subprocess.run(javac_command + ["-encoding", "UTF-8", "-source", "11", "-target", "11", "-cp", str(json_jar),
                                    "-d", str(output)] + list(map(str, sources)), check=True)
    for name in tests:
        subprocess.run([java, "-ea", "-cp", os.pathsep.join([str(output), str(json_jar)]),
                        "com.gpucheck.app." + name], check=True)
    for test in ["GpuSampleTest", "MetadataScheduleTest"]:
        binary = output / (test + (".exe" if os.name == "nt" else ""))
        subprocess.run([compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror", "-O2",
                        str(root / "tests" / (test + ".cpp")), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    main()
