"""Observe the user's real dfm_plus through the normal App, then retire only that instance."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import queue
import shlex
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
COMPONENT = "com.gpucheck.app.test/com.gpucheck.app.ServiceDeviceInstrumentation"


def adb(serial: str, *args: str, timeout: int = 25, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(["adb", "-s", serial, *args], capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"adb exit={result.returncode}: {result.stdout[:1200]!r} {result.stderr[:1200]!r}")
    return result


def root(serial: str, command: str, **kwargs) -> subprocess.CompletedProcess:
    return adb(serial, "shell", "su -c " + shlex.quote(command), **kwargs)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", default="830dcfd7")
    parser.add_argument("--label", default="dfm")
    parser.add_argument("--binary", type=Path,
                        default=Path(r"D:\WorkDir\clion4\dfm-plus-gongyi\user\cmake-build-debug\dfm_plus"))
    args = parser.parse_args()
    if not args.label.replace("-", "").isalnum():
        parser.error("label must contain letters, digits and hyphens only")
    output = ROOT / "build/live-device-test" / args.label
    output.mkdir(parents=True, exist_ok=True)
    if (output / "instrumentation.txt").exists():
        raise RuntimeError("Evidence directory is already used; choose a new label")
    remote = "/data/local/tmp/gpucheck_dfm_plus_" + args.label
    helper = "/data/local/tmp/gpucheck_identity_" + args.label
    pushed = []
    monitor = None
    target = None
    started = None
    terminated = False
    exit_result = None
    messages: queue.Queue[str | None] = queue.Queue()
    seen_captures = set()
    next_snapshot = 0.0
    transcript_error = None
    summary = {"serial": args.serial, "source": str(args.binary),
               "sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
               "remote": remote, "arguments": ["-t", "--game", "dfm"],
               "detectorReceivedTargetPid": False}

    def identity_command(action: str) -> str:
        assert target is not None
        return " ".join(shlex.quote(x) for x in [helper, action, str(target["pid"]), remote, target["startTimeTicks"]])

    def capture_logs() -> None:
        if target is None:
            return
        result = adb(args.serial, "logcat", "-d", "-v", "epoch", "--pid", str(target["pid"]), "-t", "1000", check=False)
        (output / "dfm-logcat.txt").write_bytes(result.stdout)

    try:
        for local, destination in [(args.binary, remote), (ROOT / "build/live-device-test/bin/process_identity", helper)]:
            adb(args.serial, "push", str(local), destination, timeout=90)
            pushed.append(destination)
            adb(args.serial, "shell", "chmod", "755", destination)
        preexisting = root(args.serial, shlex.quote(helper) + " find " + shlex.quote(remote))
        if preexisting.stdout.strip():
            raise RuntimeError("A process already uses this exact test path; refusing to disturb it")
        transcript_error = (output / "instrumentation.stderr.txt").open("wb")
        monitor = subprocess.Popen(["adb", "-s", args.serial, "shell", "am", "instrument", "-w", "-r",
                                    "-e", "duration_seconds", "52", COMPONENT],
                                   stdout=subprocess.PIPE, stderr=transcript_error)

        def drain() -> None:
            assert monitor is not None and monitor.stdout is not None
            with (output / "instrumentation.txt").open("wb") as transcript:
                for raw in iter(monitor.stdout.readline, b""):
                    transcript.write(raw); transcript.flush()
                    messages.put(raw.decode("utf-8", errors="replace").strip())
            messages.put(None)

        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        deadline = time.monotonic() + 110
        done = False
        with (output / "dfm-identities.jsonl").open("wb") as identities:
            while not done and time.monotonic() < deadline:
                try:
                    line = messages.get(timeout=0.2)
                    if line is None:
                        done = True
                    else:
                        print(line, flush=True)
                        if "stage=MONITOR_READY" in line and started is None:
                            started = time.monotonic()
                            summary["launchedEpochMs"] = int(time.time() * 1000)
                            launch = root(args.serial, shlex.quote(remote) + " -t --game dfm")
                            (output / "launch.txt").write_bytes(launch.stdout + launch.stderr)
                            for _ in range(10):
                                found = root(args.serial, shlex.quote(helper) + " find " + shlex.quote(remote))
                                values = [json.loads(row) for row in found.stdout.splitlines() if row.strip()]
                                if len(values) == 1:
                                    target = values[0]
                                    identities.write(found.stdout); identities.flush()
                                    summary["target"] = target
                                    print(f"DFM daemon verified: PID {target['pid']}, starttime {target['startTimeTicks']}", flush=True)
                                    break
                                time.sleep(0.3)
                            if target is None:
                                raise RuntimeError("Could not identify one daemon at the unique executable path")
                except queue.Empty:
                    pass
                if started is None or target is None:
                    continue
                elapsed = time.monotonic() - started
                if not terminated and elapsed >= next_snapshot:
                    observed = root(args.serial, identity_command("inspect"), check=False)
                    if observed.returncode == 0:
                        identities.write(observed.stdout); identities.flush()
                    else:
                        summary["earlyExitObserved"] = {"elapsedSeconds": elapsed, "identityProbeExit": observed.returncode}
                    next_snapshot = elapsed + 6
                for name, moment in [("dfm-live", 12), ("dfm-before-stop", 28), ("dfm-exited", 41)]:
                    if name not in seen_captures and elapsed >= moment:
                        shot = adb(args.serial, "exec-out", "screencap", "-p", check=False)
                        if shot.stdout.startswith(b"\x89PNG"):
                            (output / (name + ".png")).write_bytes(shot.stdout)
                        seen_captures.add(name)
                if not terminated and elapsed >= 34:
                    capture_logs()
                    exit_result = root(args.serial, identity_command("term"), check=False)
                    (output / "dfm-termination.json").write_bytes(exit_result.stdout)
                    summary["terminationCommandExit"] = exit_result.returncode
                    summary["terminationMode"] = "identity_checked_pidfd_SIGTERM"
                    terminated = True
            if not done:
                raise TimeoutError("Real Service instrumentation timed out")
        monitor.wait(timeout=5); reader.join(timeout=5)
        capture_logs()
        for name in ["service-real.jsonl", "service-ui.jsonl", "service-device-summary.json",
                     "service-ui-active.png", "service-ui-stopped.png", "service-ui-background.png"]:
            captured = adb(args.serial, "exec-out", "run-as", "com.gpucheck.app", "cat", "files/" + name, check=False)
            if captured.returncode == 0:
                (output / name).write_bytes(captured.stdout)
        if "result=PASS" not in (output / "instrumentation.txt").read_text(encoding="utf-8", errors="replace"):
            raise RuntimeError("Service test did not pass")
        log = (output / "dfm-logcat.txt").read_text(encoding="utf-8", errors="replace")
        summary["gameInitialized"] = "Game initialized:" in log
        summary["enteredRenderLoop"] = "Entering render loop" in log
        if not summary["enteredRenderLoop"] or not summary["gameInitialized"]:
            raise RuntimeError("DFM did not prove a successful game bind and render loop; see its log")
        if exit_result is None or exit_result.returncode:
            raise RuntimeError("DFM termination was not verified")
        print("Real DFM evidence saved to " + str(output), flush=True)
    finally:
        if target is not None and not terminated:
            stopped = root(args.serial, identity_command("term"), check=False)
            (output / "cleanup-termination.json").write_bytes(stopped.stdout)
        if monitor is not None and monitor.poll() is None:
            adb(args.serial, "shell", "am", "force-stop", "com.gpucheck.app", check=False)
            monitor.terminate(); monitor.wait(timeout=5)
        if transcript_error is not None:
            transcript_error.close()
        summary["finishedEpochMs"] = int(time.time() * 1000)
        (output / "dfm-test-summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
        # A daemon whose exit was not confirmed must retain its executable for diagnosis.
        if target is None or (exit_result is not None and exit_result.returncode == 0):
            for path in pushed:
                adb(args.serial, "shell", "rm", "-f", path, check=False)


if __name__ == "__main__":
    main()
