"""Run the actual foreground App and two bounded external root CPU fixtures.

Root is used exclusively by external test fixtures, never by the monitored App.
No target PID is passed to the detector or instrumentation.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import queue
import shlex
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
COMPONENT = "com.gpucheck.app.test/com.gpucheck.app.ServiceDeviceInstrumentation"


def adb(serial: str, *args: str, timeout: int = 20, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(["adb", "-s", serial, *args], capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"adb exit={result.returncode}: {result.stdout[:1000]!r} {result.stderr[:1000]!r}")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", default="830dcfd7")
    parser.add_argument("--label", required=True)
    parser.add_argument("--capture-only", action="store_true")
    args = parser.parse_args()
    if not args.label.replace("-", "").isalnum():
        parser.error("label must contain letters, digits and hyphens only")
    output = ROOT / "build/live-device-test" / args.label
    output.mkdir(parents=True, exist_ok=False)
    fixture = ROOT / "build/live-device-test/bin/gpu_process_fixture"
    remote = "/data/local/tmp/gpucheck_live_fixture_" + args.label
    streams = []
    children = []
    monitor = None
    pushed = False
    started = None
    captures = set()
    messages: queue.Queue[str | None] = queue.Queue()
    try:
        adb(args.serial, "push", str(fixture), remote)
        pushed = True
        adb(args.serial, "shell", "chmod 755 " + shlex.quote(remote))
        arguments = ["am", "instrument", "-w", "-r", "-e", "duration_seconds", "52"]
        if args.capture_only:
            arguments += ["-e", "capture_only", "true"]
        arguments += [COMPONENT]
        error_file = (output / "instrumentation.stderr.txt").open("wb")
        streams.append(error_file)
        monitor = subprocess.Popen(["adb", "-s", args.serial, "shell", *arguments],
                                   stdout=subprocess.PIPE, stderr=error_file)

        def drain() -> None:
            assert monitor is not None and monitor.stdout is not None
            with (output / "instrumentation.txt").open("wb") as transcript:
                for raw in iter(monitor.stdout.readline, b""):
                    transcript.write(raw)
                    transcript.flush()
                    messages.put(raw.decode("utf-8", errors="replace").strip())
            messages.put(None)

        thread = threading.Thread(target=drain, daemon=True)
        thread.start()
        deadline = time.monotonic() + 105
        ended = False
        while not ended and time.monotonic() < deadline:
            try:
                line = messages.get(timeout=0.2)
                if line is None:
                    ended = True
                else:
                    print(line, flush=True)
                    if "stage=MONITOR_READY" in line and started is None:
                        started = time.monotonic()
                        for mode in ("high", "low"):
                            log = (output / f"fixture-{mode}.jsonl").open("wb")
                            err = (output / f"fixture-{mode}.stderr.txt").open("wb")
                            streams += [log, err]
                            command = "su -c " + shlex.quote(shlex.quote(remote) + " " + mode)
                            children.append(subprocess.Popen(["adb", "-s", args.serial, "shell", command],
                                                             stdout=log, stderr=err))
                        print("External fixtures started after the App baseline; no PID supplied to App.", flush=True)
            except queue.Empty:
                pass
            if started is not None:
                elapsed = time.monotonic() - started
                for name, at in [("busy", 7), ("idle", 17), ("resumed", 27), ("exited", 39)]:
                    if name not in captures and elapsed >= at:
                        capture = adb(args.serial, "exec-out", "screencap", "-p", check=False)
                        if capture.returncode == 0 and capture.stdout.startswith(b"\x89PNG"):
                            (output / (name + ".png")).write_bytes(capture.stdout)
                        captures.add(name)
        if not ended:
            raise TimeoutError("Service instrumentation did not finish within 105 seconds")
        assert monitor is not None
        monitor.wait(timeout=5)
        thread.join(timeout=5)
        if started is None:
            raise RuntimeError("App did not publish MONITOR_READY; fixtures were not started")
        for child in children:
            child.wait(timeout=45)
        for name in ["service-real.jsonl", "service-ui.jsonl", "service-device-summary.json",
                     "service-ui-active.png", "service-ui-stopped.png", "service-ui-background.png"]:
            result = adb(args.serial, "exec-out", "run-as", "com.gpucheck.app", "cat", "files/" + name, check=False)
            if result.returncode == 0:
                (output / name).write_bytes(result.stdout)
        transcript = (output / "instrumentation.txt").read_text(encoding="utf-8", errors="replace")
        acceptable = "result=PASS" in transcript or (args.capture_only and "result=CAPTURED" in transcript)
        if not acceptable:
            raise RuntimeError("Instrumentation did not pass; raw evidence was retained")
        print("Evidence saved to " + str(output), flush=True)
    finally:
        # The fixtures are bounded to 36 seconds; do not signal unrelated processes.
        for child in children:
            try:
                child.wait(timeout=45)
            except subprocess.TimeoutExpired:
                child.terminate()
                child.wait(timeout=5)
        if monitor is not None and monitor.poll() is None:
            adb(args.serial, "shell", "am", "force-stop", "com.gpucheck.app", check=False)
            monitor.terminate()
            monitor.wait(timeout=5)
        for stream in streams:
            stream.close()
        if pushed:
            adb(args.serial, "shell", "rm", "-f", remote, check=False)


if __name__ == "__main__":
    main()
