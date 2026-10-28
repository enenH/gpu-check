"""Read-only cgroup membership experiment on explicitly selected adb devices.

The native sampler only creates/reaps its own optional live/zombie fixtures.
The optional ordinary-app phase installs an isolated, permission-free test APK.
All raw evidence is retained; this does not change the GPU Check application.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import time
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "build" / "cgroup-device-test"
PACKAGE = "com.gpucheck.cgroupaudit"
COMPONENT = PACKAGE + "/" + PACKAGE + ".AuditInstrumentation"


def adb(serial: str, *args: str, timeout: int = 90, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(["adb", "-s", serial, *args], capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"adb {serial} {args}, exit={result.returncode}: "
                           f"{result.stdout[:1200].decode(errors='replace')} "
                           f"{result.stderr[:1200].decode(errors='replace')}")
    return result


def shell(serial: str, command: str, *, root: bool = False, timeout: int = 90,
          check: bool = True) -> subprocess.CompletedProcess:
    if serial.startswith("altdb-"):
        # This alternative adb transport can lose the status of very short commands.
        # Keep the channel open briefly, then return the command's actual status.
        command += "\ncgroup_audit_status=$?\nsleep 0.1\nexit $cgroup_audit_status"
    if root:
        command = "su -c " + shlex.quote(command)
    return adb(serial, "shell", command, timeout=timeout, check=check)


def save_capture(path: Path, result: subprocess.CompletedProcess) -> None:
    path.write_bytes(result.stdout)
    path.with_suffix(path.suffix + ".stderr").write_bytes(result.stderr)


def capture(serial: str, output: Path, remote: str, *, root: bool,
            fixtures: bool = False, targets: str | None = None) -> dict:
    command = shlex.quote(remote)
    if fixtures:
        command += " --fixtures"
    if targets:
        command += " --targets-file " + shlex.quote(targets)
    result = shell(serial, command, root=root, timeout=120)
    save_capture(output, result)
    data = json.loads(result.stdout)
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise RuntimeError(f"Unexpected audit schema in {output}")
    print(f"[{serial}] {output.name}: {len(data['proc_before']['pids'])} proc entries, "
          f"{len(data['mounts'])} mounts", flush=True)
    return data


def write_targets(output: Path, snapshot: dict) -> None:
    lines = []
    for row in snapshot["proc_before"]["pids"]:
        uid = row["status"].get("uid", -1)
        starttime = row["stat"].get("starttime", 0)
        if (uid >= 0 and row["stat"]["errno"] == 0 and row["stat"].get("parse_errno", 0) == 0
                and row["status"].get("parse_errno", 0) == 0):
            lines.append(f"{row['pid']}\t{uid}\t{starttime}\n")
    output.write_text("".join(lines), encoding="ascii")


def app_capture(serial: str, output: Path, *, targets: str | None = None) -> dict:
    args = ["am", "instrument", "-w", "-r", "-e", "fixtures", "true"]
    if targets:
        args += ["-e", "targets_file", targets]
    args += [COMPONENT]
    result = shell(serial, " ".join(shlex.quote(arg) for arg in args), timeout=120)
    save_capture(output.with_suffix(".instrumentation.txt"), result)
    response = result.stdout.decode(errors="replace")
    if "result=PASS" not in response:
        raise RuntimeError(f"Instrumentation did not pass: {response}")
    for name, destination in [("audit.json", output), ("audit.err", output.with_suffix(".native-stderr"))]:
        result = shell(serial, "cat " + shlex.quote(f"/data/user/0/{PACKAGE}/files/{name}"), root=True)
        save_capture(destination, result)
    data = json.loads(output.read_bytes())
    print(f"[{serial}] {output.name}: uid={data['meta']['uid']}, "
          f"{len(data['proc_before']['pids'])} proc entries", flush=True)
    return data


def run_device(serial: str, label: str, phase: str, apk: Path | None) -> None:
    output = BASE / label
    output.mkdir(parents=True, exist_ok=True)
    remote = f"/data/local/tmp/cgroup-audit-{label}"
    remote_targets = remote + ".targets.tsv"
    binary = BASE / "bin" / "cgroup_audit"
    if not binary.is_file():
        raise FileNotFoundError(binary)
    (output / "device.json").write_text(json.dumps({"serial": serial, "label": label,
                                                    "host_time": time.strftime("%Y-%m-%dT%H:%M:%S%z")},
                                                   indent=2), encoding="utf-8")
    metadata = "\n".join([
        "id", "getprop ro.product.model", "getprop ro.build.version.release",
        "getprop ro.build.version.sdk", "uname -a", "cat /proc/cgroups",
        "cat /proc/self/mountinfo", "cat /proc/self/cgroup",
        "cat /proc/sys/kernel/pid_max", "getenforce",
    ])
    installed_here = False
    try:
        hashes = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                  for path in [binary, ROOT / "scripts" / "cgroup_audit.cpp", Path(__file__).resolve()]}
        if apk is not None:
            hashes[str(apk)] = hashlib.sha256(apk.read_bytes()).hexdigest()
            with ZipFile(apk) as archive:
                packaged_native = archive.read("lib/arm64-v8a/libcgroup_audit.so")
            if packaged_native != binary.read_bytes():
                raise RuntimeError("APK native sampler differs from the shell/root sampler; rebuild the APK")
        (output / (phase + "-artifact-hashes.json")).write_text(json.dumps(hashes, indent=2), encoding="utf-8")
        adb(serial, "push", str(binary), remote)
        shell(serial, "chmod 755 " + shlex.quote(remote), root=True)
        save_capture(output / (phase + "-environment.txt"), shell(serial, metadata, root=True))
        if phase == "root":
            for index in range(1, 4):
                capture(serial, output / f"root-{index:02d}.json", remote, root=True, fixtures=True)
            before = capture(serial, output / "shell-bracket-before.json", remote, root=True)
            write_targets(output / "shell-targets.tsv", before)
            adb(serial, "push", str(output / "shell-targets.tsv"), remote_targets)
            capture(serial, output / "shell.json", remote, root=False, fixtures=True, targets=remote_targets)
            capture(serial, output / "shell-bracket-after.json", remote, root=True)
        elif phase == "app":
            if apk is None or not apk.is_file():
                raise FileNotFoundError(apk)
            existing = shell(serial, "pm path " + PACKAGE, check=False)
            if b"package:" in existing.stdout:
                raise RuntimeError(f"Refusing to replace an already installed {PACKAGE}; inspect it first")
            install = adb(serial, "install", "-t", str(apk), timeout=120)
            save_capture(output / "app-install.txt", install)
            installed_here = True
            app_capture(serial, output / "app-autonomous.json")
            before = capture(serial, output / "app-bracket-before.json", remote, root=True)
            write_targets(output / "app-targets.tsv", before)
            adb(serial, "push", str(output / "app-targets.tsv"), remote_targets)
            private_file = f"/data/user/0/{PACKAGE}/files/targets.tsv"
            file_owner = shell(serial, "stat -c %u " + shlex.quote(f"/data/user/0/{PACKAGE}/files"), root=True)
            uid = int(file_owner.stdout.strip())
            for command in ["cp " + shlex.quote(remote_targets) + " " + shlex.quote(private_file),
                            f"chown {uid}:{uid} " + shlex.quote(private_file),
                            "chmod 600 " + shlex.quote(private_file),
                            "restorecon " + shlex.quote(private_file)]:
                shell(serial, command, root=True)
            app_capture(serial, output / "app-known-targets.json", targets=private_file)
            capture(serial, output / "app-bracket-after.json", remote, root=True)
        else:
            raise ValueError(phase)
    finally:
        if installed_here:
            save_capture(output / "app-uninstall.txt", adb(serial, "uninstall", PACKAGE, check=False))
        # Only the exact two files created for this device's run are removed.
        cleanup = shell(serial, "rm -f " + shlex.quote(remote) + " " + shlex.quote(remote_targets), check=False)
        save_capture(output / (phase + "-cleanup.txt"), cleanup)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", action="append", required=True, metavar="LABEL=SERIAL")
    parser.add_argument("--phase", choices=["root", "app"], required=True)
    parser.add_argument("--apk", type=Path)
    args = parser.parse_args()
    pairs = [entry.split("=", 1) for entry in args.device]
    for pair in pairs:
        if len(pair) != 2 or not pair[0].replace("-", "").isalnum():
            parser.error("--device must be LABEL=SERIAL, with an alphanumeric/hyphen label")
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(pairs)) as executor:
        futures = [executor.submit(run_device, serial, label, args.phase, args.apk) for label, serial in pairs]
        for future in futures:
            future.result()


if __name__ == "__main__":
    main()
