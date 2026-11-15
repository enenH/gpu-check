"""OnePlus real DFM overlay on/off acceptance. Build/install both APKs and guard first."""
from pathlib import Path
import argparse
import hashlib
import json
import queue
import shlex
import subprocess
import sys
import threading
import time
import uuid

PROJECT = Path(__file__).resolve().parents[1]
COMPONENT = "com.gpucheck.app.test/com.gpucheck.app.ServiceDeviceInstrumentation"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", default="830dcfd7")
    parser.add_argument("--out", type=Path, default=PROJECT / "build/slot-frequency-device-test")
    parser.add_argument("--source", type=Path,
                        default=Path(r"D:\WorkDir\clion4\dfm-plus-gongyi\user\cmake-build-debug\dfm_plus"))
    parser.add_argument("--guard", type=Path, default=PROJECT / "build/slot-frequency-device-test/gpu_overlay_guard")
    parser.add_argument("--duration", type=int, default=60)
    args = parser.parse_args()
    if not 45 <= args.duration <= 180:
        parser.error("--duration must be between 45 and 180 seconds")
    for binary in (args.source, args.guard):
        if not binary.is_file():
            parser.error("binary is missing: " + str(binary))
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    token = uuid.uuid4().hex[:10]
    name = "gpf" + token
    remote = "/data/local/tmp/" + name
    remote_guard = "/data/local/tmp/gpg" + token
    metadata = {"serial": args.serial, "source": str(args.source.resolve()),
                "sha256": hashlib.sha256(args.source.read_bytes()).hexdigest(),
                "arguments": ["-t", "--game", "dfm"], "remote": remote, "guard": remote_guard,
                "detectorReceivedTargetPidOrSlot": False, "events": [], "complete": False}
    monitor = guard = None
    messages, guard_messages = queue.Queue(), queue.Queue()
    target_pid = None
    target_stopped = False
    guard_ready = False
    launch_attempted = False
    ready_at = started_at = stopped_at = None
    captures = set()
    error = None

    def event(kind, **fields):
        value = {"event": kind, "hostEpochMs": int(time.time() * 1000), "hostMonotonicNs": time.monotonic_ns()}
        value.update(fields)
        metadata["events"].append(value)
        return value

    def adb(*arguments, check=True, timeout=25):
        result = subprocess.run(["adb", "-s", args.serial, *arguments], capture_output=True, timeout=timeout)
        if check and result.returncode:
            raise RuntimeError(str(arguments) + ": " + (result.stderr + result.stdout).decode(errors="replace"))
        return result

    def root(command, **options):
        return adb("shell", "su -c " + shlex.quote(command), **options)

    def save(filename, result):
        (out / filename).write_bytes(result.stdout)
        return result.stdout.decode(errors="replace")

    def listen(process, filename, channel):
        with (out / filename).open("wb") as stream:
            for line in iter(process.stdout.readline, b""):
                stream.write(line)
                stream.flush()
                channel.put(line.decode(errors="replace").strip())
        channel.put(None)

    def pids():
        return adb("shell", "pidof", name, check=False).stdout.decode().split()

    def capture(phase):
        if phase in captures:
            return
        captures.add(phase)
        event("capture_" + phase)
        save("display-" + phase + ".txt", adb("shell", "dumpsys", "display", check=False))
        save("layers-" + phase + ".txt", root("dumpsys SurfaceFlinger --list", check=False))
        image = adb("exec-out", "screencap", "-p", check=False).stdout
        if image.startswith(b"\x89PNG"):
            (out / (phase + ".png")).write_bytes(image)

    def acquire_guard(pid, log_name="guard.jsonl"):
        nonlocal guard, guard_ready
        command = shlex.quote(remote_guard) + " " + str(pid) + " " + shlex.quote(remote)
        guard = subprocess.Popen(["adb", "-s", args.serial, "shell", "su -c " + shlex.quote(command)],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=(out / "guard-stderr.txt").open("ab"))
        threading.Thread(target=listen, args=(guard, log_name, guard_messages), daemon=True).start()
        line = guard_messages.get(timeout=8)
        if line is None:
            raise RuntimeError("Guard exited before verifying the new executable")
        receipt = json.loads(line)
        if receipt.get("event") != "ready" or not receipt.get("executableVerified") or receipt.get("pid") != pid:
            raise RuntimeError("Guard did not verify the exact new executable/PID")
        metadata["events"].append(receipt)
        guard_ready = True

    def stop_target():
        nonlocal target_stopped, stopped_at
        if target_stopped or not guard_ready:
            return
        event("overlay_stop_requested", pid=target_pid)
        if guard.stdin and not guard.stdin.closed:
            try:
                guard.stdin.write(b"stop\n")
                guard.stdin.flush()
            except BrokenPipeError:
                pass
            finally:
                guard.stdin.close()
        receipt = None
        limit = time.monotonic() + 9
        while time.monotonic() < limit:
            try:
                line = guard_messages.get(timeout=min(1, max(.01, limit - time.monotonic())))
            except queue.Empty:
                continue
            if line is None:
                break
            value = json.loads(line)
            metadata["events"].append(value)
            if value.get("event") == "finished":
                receipt = value
                break
        target_stopped = bool(receipt and receipt.get("exited"))
        if not target_stopped:
            raise RuntimeError("Held pidfd did not confirm overlay exit")
        guard.wait(timeout=5)
        stopped_at = time.monotonic()
        event("overlay_stopped", pid=target_pid)
        print("Overlay stopped through verified held pidfd", flush=True)

    try:
        if pids():
            raise RuntimeError("Unique test executable already exists")
        adb("push", str(args.source), remote, timeout=90)
        adb("push", str(args.guard), remote_guard, timeout=90)
        adb("shell", "chmod", "755", remote, remote_guard)
        capture("before")
        command = ["adb", "-s", args.serial, "shell", "am", "instrument", "-w", "-r",
                   "-e", "duration_seconds", str(args.duration), "-e", "capture_only", "false",
                   "-e", "require_gpu_frequency", "true", "-e", "require_gpu_frequency_cycle", "true",
                   "-e", "require_gpu_exec", "true", COMPONENT]
        event("instrumentation_started")
        monitor = subprocess.Popen(command, stdout=subprocess.PIPE,
                                   stderr=(out / "instrumentation-stderr.txt").open("wb"))
        threading.Thread(target=listen, args=(monitor, "instrumentation.txt", messages), daemon=True).start()
        deadline = time.monotonic() + args.duration + 50
        done = False
        while not done and time.monotonic() < deadline:
            try:
                line = messages.get(timeout=.1)
                if line is None:
                    done = True
                else:
                    print(line, flush=True)
                    if "stage=MONITOR_READY" in line and ready_at is None:
                        ready_at = time.monotonic()
                        event("monitor_ready")
                        capture("baseline")
                    elif "stage=GPU_FREQUENCY_ALERT_DETECTED" in line:
                        event("ui_frequency_alert_observed")
                    elif "stage=GPU_FREQUENCY_ALERT_CLEARED" in line:
                        event("ui_frequency_alert_cleared")
            except queue.Empty:
                pass
            if done or ready_at is None:
                continue
            if not launch_attempted and time.monotonic() - ready_at >= 8:
                launch_attempted = True
                event("overlay_launch_requested")
                save("launch.txt", root(shlex.quote(remote) + " -t --game dfm"))
                started_at = time.monotonic()
                for _ in range(25):
                    found = pids()
                    if len(found) == 1:
                        target_pid = int(found[0])
                        break
                    if len(found) > 1:
                        raise RuntimeError("Unique overlay name unexpectedly matches multiple processes")
                    time.sleep(.2)
                if target_pid is None:
                    raise RuntimeError("DFM overlay daemon did not stay alive")
                metadata["pid"] = target_pid
                acquire_guard(target_pid)
                event("overlay_started", pid=target_pid)
                print("Verified overlay PID " + str(target_pid), flush=True)
            if started_at is not None:
                active_seconds = time.monotonic() - started_at
                if active_seconds >= 10 and not target_stopped:
                    capture("active")
                if active_seconds >= 25 and not target_stopped:
                    stop_target()
            if stopped_at is not None and time.monotonic() - stopped_at >= 3:
                capture("after")
        if not done:
            raise TimeoutError("Instrumentation did not finish within its bounded test duration")
        monitor.wait(timeout=5)
        if guard_ready and not target_stopped:
            stop_target()
        exports = ["service-real.jsonl", "service-ui.jsonl", "service-device-summary.json",
                   "service-ui-active.png", "service-ui-stopped.png", "service-ui-background.png",
                   "gpu-frequency-alert.png", "gpu-frequency-cleared.png"]
        for filename in exports:
            result = adb("exec-out", "run-as", "com.gpucheck.app", "cat", "files/" + filename, check=False)
            if result.returncode == 0:
                save(filename, result)
            else:
                metadata.setdefault("missingExports", []).append(filename)
        summary = json.loads((out / "service-device-summary.json").read_text(encoding="utf-8"))
        metadata["summaryResult"] = summary.get("result")
        metadata["complete"] = (target_stopped and summary.get("result") == "PASS"
                                and summary.get("gpuFrequencyClearedAfterAlert") is True
                                and summary.get("gpuFrequencyVisibleFrames", 0) > 0
                                and summary.get("gpuFrequencyAlertReports", 0) > 0)
        if not metadata["complete"]:
            raise RuntimeError("Real GPU frequency cycle did not pass: " + summary.get("error", str(summary.get("result"))))
        print(json.dumps({"result": "PASS", "output": str(out), "pid": target_pid,
                          "frequencyReports": summary.get("gpuFrequencyCompleteReports"),
                          "visibleFrames": summary.get("gpuFrequencyVisibleFrames")}), flush=True)
    except BaseException as caught:
        error = caught
        metadata["error"] = repr(caught)
    finally:
        try:
            if guard_ready and not target_stopped:
                stop_target()
            elif launch_attempted and not target_stopped:
                found = pids()
                if len(found) == 1:
                    target_pid = int(found[0])
                    # Recover cleanup with a fresh exact-executable check, never a name-wide kill.
                    guard_messages = queue.Queue()
                    acquire_guard(target_pid, "guard-cleanup.jsonl")
                    stop_target()
        except Exception as cleanup_error:
            metadata["cleanupError"] = repr(cleanup_error)
            if error is None:
                error = cleanup_error
        if guard is not None and guard.poll() is None and guard.stdin and not guard.stdin.closed:
            guard.stdin.close()
        if monitor is not None and monitor.poll() is None:
            adb("shell", "am", "force-stop", "com.gpucheck.app", check=False)
            try:
                monitor.wait(timeout=8)
            except subprocess.TimeoutExpired:
                monitor.terminate()
        try:
            if not pids():
                adb("shell", "rm", "-f", remote, remote_guard, check=False)
                metadata["remoteFilesRemoved"] = True
            else:
                metadata["remoteFilesRemoved"] = False
        except Exception as cleanup_error:
            metadata["fileCleanupError"] = repr(cleanup_error)
        event("experiment_finished")
        (out / "experiment.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")
    if error is not None:
        print("FAIL: " + repr(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
