#!/usr/bin/env python3
"""Run the OEM process integration runner on the explicitly selected OnePlus.

The test APK executes as the target app UID. ADB installs/starts the test and
exports receipts only; no shell PID, UID, process name or privileged result is
provided to the detector. Build first with:
  gradlew.bat assembleDebug assembleDebugAndroidTest -PgpuCheckTestRunner=com.gpucheck.app.OemProcessInstrumentation
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "com.gpucheck.app"
RUNNER = "com.gpucheck.app.test/com.gpucheck.app.OemProcessInstrumentation"
ARTIFACTS = ("oem-process-summary.json", "oem-process-real.jsonl", "oem-process-ui.jsonl", "oem-process-active.png",
             "oem-process-processes.png", "oem-process-evidence.png")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", default="830dcfd7", help="ADB serial; only the OnePlus CPH2415 is accepted")
    parser.add_argument("--output", type=Path, default=ROOT / "build" / "oem-process-device-test")
    parser.add_argument("--duration", type=int, default=25)
    parser.add_argument("--checks-only", action="store_true", help="Only explicitly synthetic protocol/merger/thread checks")
    parser.add_argument("--require-oplus", action="store_true", help="Require a usable Oplus result, not just a capability result")
    parser.add_argument("--skip-install", action="store_true")
    args = parser.parse_args()
    if args.serial != "830dcfd7":
        parser.error("This task is authorized for OnePlus serial 830dcfd7 only")
    if not 10 <= args.duration <= 120:
        parser.error("--duration must be 10..120 seconds")
    args.output.mkdir(parents=True, exist_ok=True)

    def adb(*arguments: str, check: bool = True, timeout: int = 40) -> subprocess.CompletedProcess[bytes]:
        command = ["adb", "-s", args.serial, *arguments]
        outcome = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        if check and outcome.returncode:
            raise RuntimeError(f"ADB failed ({outcome.returncode}): {' '.join(command)}\n"
                               + outcome.stderr.decode("utf-8", errors="replace")
                               + outcome.stdout.decode("utf-8", errors="replace"))
        return outcome

    model = adb("shell", "getprop", "ro.product.model").stdout.decode().strip()
    if model != "CPH2415":
        raise RuntimeError(f"Unexpected device model {model!r}; no install or launch performed")
    if not args.skip_install:
        for apk in (ROOT / "app/build/outputs/apk/debug/app-debug.apk",
                    ROOT / "app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk"):
            if not apk.is_file():
                raise FileNotFoundError(f"Build missing: {apk}")
            print(adb("install", "-r", str(apk), timeout=90).stdout.decode(), end="", flush=True)

    # Clear only the receipts belonging to this runner so a failed launch
    # cannot be mistaken for a previous successful run.
    adb("shell", "run-as", PACKAGE, "rm", "-f", *(f"files/{name}" for name in ARTIFACTS))
    before = adb("shell", "ps", "-A", "-o", "PID,UID,NAME", check=False)
    (args.output / "independent-shell-ps-before.txt").write_bytes(before.stdout + before.stderr)
    command = ["shell", "am", "instrument", "-w", "-r", "-e", "duration_seconds", str(args.duration)]
    if args.checks_only:
        command.extend(["-e", "checks_only", "true"])
    if args.require_oplus:
        command.extend(["-e", "require_oplus", "true"])
    command.append(RUNNER)
    outcome = adb(*command, check=False, timeout=args.duration + 120)
    (args.output / "instrumentation.txt").write_bytes(outcome.stdout + outcome.stderr)
    print(outcome.stdout.decode("utf-8", errors="replace"), end="", flush=True)
    after = adb("shell", "ps", "-A", "-o", "PID,UID,NAME", check=False)
    (args.output / "independent-shell-ps-after.txt").write_bytes(after.stdout + after.stderr)
    exported = []
    for artifact in ARTIFACTS:
        response = adb("exec-out", "run-as", PACKAGE, "cat", f"files/{artifact}", check=False)
        if response.returncode == 0:
            (args.output / artifact).write_bytes(response.stdout)
            exported.append(artifact)
        elif artifact == "oem-process-summary.json":
            raise RuntimeError("No current summary receipt could be exported: "
                               + response.stdout.decode("utf-8", errors="replace"))
    summary = json.loads((args.output / "oem-process-summary.json").read_text(encoding="utf-8"))
    receipt = {"serial": args.serial, "model": model, "instrumentationExitCode": outcome.returncode,
               "result": summary.get("result"), "exported": exported,
               "externalPsWasDetectorInput": False, "rootUsedByRunnerOrExport": False}
    (args.output / "host-receipt.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(receipt, ensure_ascii=False, indent=2))
    return 0 if outcome.returncode == 0 and summary.get("result") == "PASS" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
