#!/usr/bin/env python3
"""Build and run the host cgroup scanner regressions with deterministic fake IO.

No Android device, cgroup mount access, or elevated privileges are required.
Use --sanitize to also run the same scenarios with AddressSanitizer and UBSan.
The test source and binaries are not included in the APK.
On ptrace-based hosts, set ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 for that run.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cxx", default=os.environ.get("CXX", "g++"), help="Host C++17 compiler")
    parser.add_argument("--sanitize", action="store_true", help="Also run AddressSanitizer and UBSan")
    parser.add_argument("--output", type=Path, default=ROOT / "build" / "cgroup-native-tests")
    args = parser.parse_args()
    compiler = shutil.which(args.cxx)
    if compiler is None:
        parser.error(f"C++ compiler not found: {args.cxx}")
    args.output.mkdir(parents=True, exist_ok=True)
    configurations = [("cgroup-watch-test", ["-O2"])]
    if args.sanitize:
        configurations.append(("cgroup-watch-test-sanitized", [
            "-O1", "-g", "-fno-omit-frame-pointer", "-fsanitize=address,undefined",
            "-fno-sanitize-recover=all",
        ]))
    for name, flags in configurations:
        binary = (args.output / name).resolve()
        command = [compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror", *flags,
                   str(ROOT / "tests" / "cgroup_watch_test.cpp"), "-o", str(binary)]
        print(f"Building {name}", flush=True)
        subprocess.run(command, cwd=ROOT, check=True, timeout=120)
        environment = os.environ.copy()
        if "-fsanitize=address,undefined" in flags:
            environment.setdefault("ASAN_OPTIONS", "halt_on_error=1")
            environment.setdefault("UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1")
        subprocess.run([str(binary)], cwd=ROOT, env=environment, check=True, timeout=60)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
