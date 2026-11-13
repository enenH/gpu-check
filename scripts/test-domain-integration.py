#!/usr/bin/env python3
"""Synthetic RiskEngine integration, not an Android runtime/device test."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--android-jar', required=True, type=Path)
p.add_argument('--json-jar', required=True, type=Path)
args = p.parse_args()
android = args.android_jar.resolve(strict=True)
json = args.json_jar.resolve(strict=True)
root = Path(__file__).resolve().parents[1]
out = root / 'build/domain-integration'
out.mkdir(parents=True, exist_ok=True)
stub = out / 'stub-src/android/os/Process.java'
stub.parent.mkdir(parents=True, exist_ok=True)
# Only the app identity is modeled. No socket, syscall or collector method runs.
stub.write_text('package android.os; public final class Process {'
                'public static int myPid(){return 900000;}'
                'public static int myUid(){return 10234;} }\n')
java = shutil.which('java')
javac = shutil.which('javac')
compile_command = [javac] if javac else [java, '-m', 'jdk.compiler/com.sun.tools.javac.Main']
subprocess.run(compile_command + ['-encoding', 'UTF-8', '-source', '11', '-target', '11',
               '-cp', str(android), '-sourcepath', str(root / 'app/src/main/java'), '-d', str(out),
               str(stub), str(root / 'tests/RiskEngineDomainTest.java')], check=True)
subprocess.run([java, '-ea', '-cp', os.pathsep.join(map(str, [out, json, android])),
                'com.gpucheck.app.RiskEngineDomainTest'], check=True)
