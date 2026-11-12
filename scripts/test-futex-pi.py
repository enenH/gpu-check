"""Bounded FUTEX_TRYLOCK_PI experiment; installs/removes an isolated test APK.

Root is used only for a separate comparison and independent /proc evidence.
The identical native binary also runs as shell and as a zero-permission app.
No production APK, device settings, or target-owned memory is changed.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "com.gpucheck.futexaudit"
COMPONENT = PACKAGE + "/" + PACKAGE + ".FutexInstrumentation"


def run(command, *, timeout=60, check=True, env=None):
    result = subprocess.run([str(x) for x in command], capture_output=True,
                            timeout=timeout, env=env)
    if check and result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}): {command}\n"
                           + result.stdout.decode(errors="replace")
                           + result.stderr.decode(errors="replace"))
    return result


def write_capture(path, result):
    path.write_bytes(result.stdout)
    path.with_suffix(path.suffix + ".stderr").write_bytes(result.stderr)


def records(data):
    return [json.loads(line) for line in data.splitlines() if line.strip()]


def sample(rows, count):
    rows = sorted(rows, key=lambda row: row["tid"])
    if len(rows) <= count:
        return rows
    return [rows[i * (len(rows) - 1) // (count - 1)] for i in range(count)]


def build(args, output):
    native = output / "bin" / "futex_pi_probe"
    native.parent.mkdir(parents=True, exist_ok=True)
    compiler = Path(args.ndk) / "toolchains/llvm/prebuilt/windows-x86_64/bin/clang.exe"
    run([compiler, "--target=aarch64-linux-android26", "-std=c11", "-O2", "-g",
         "-Wall", "-Wextra", "-Werror", "-fPIE", "-pie", "-pthread",
         ROOT / "tests/device/futex_pi_probe.c", "-o", native])
    source = ROOT / "tests/device/futex-pi-app"
    app = output / "app"
    classes, dex = app / "classes", app / "dex"
    classes.mkdir(parents=True, exist_ok=True)
    dex.mkdir(parents=True, exist_ok=True)
    sdk = Path(args.sdk)
    android = sdk / "platforms/android-35/android.jar"
    build_tools = sdk / "build-tools/35.0.1"
    java = Path(args.java_home)
    env = dict(os.environ, JAVA_HOME=str(java))
    env["PATH"] = str(java / "bin") + os.pathsep + env["PATH"]
    run([java / "bin/javac.exe", "-encoding", "UTF-8", "-source", "8", "-target", "8",
         "-classpath", android, "-d", classes, source / "FutexInstrumentation.java"], env=env)
    run([java / "bin/java.exe", "-cp", build_tools / "lib/d8.jar", "com.android.tools.r8.D8",
         "--release", "--min-api", "26", "--lib", android, "--output", dex,
         *classes.rglob("*.class")], env=env)
    unsigned, aligned, signed = app / "unsigned.apk", app / "aligned.apk", app / "FutexPiAudit.apk"
    run([build_tools / "aapt2.exe", "link", "-o", unsigned, "--manifest",
         source / "AndroidManifest.xml", "-I", android, "--min-sdk-version", "26",
         "--target-sdk-version", "35", "--version-code", "1", "--version-name", "1.0"])
    with ZipFile(unsigned, "a") as archive:
        archive.write(dex / "classes.dex", "classes.dex")
        archive.write(native, "lib/arm64-v8a/libfutex_pi_probe.so")
    run([build_tools / "zipalign.exe", "-P", "16", "-f", "4", unsigned, aligned])
    signer = [java / "bin/java.exe", "-jar", build_tools / "lib/apksigner.jar"]
    run([*signer, "sign", "--ks", Path.home() / ".android/debug.keystore",
         "--ks-key-alias", "androiddebugkey", "--ks-pass", "pass:android",
         "--key-pass", "pass:android", "--out", signed, aligned])
    run([*signer, "verify", signed])
    permissions = run([build_tools / "aapt2.exe", "dump", "permissions", signed])
    write_capture(output / "apk-permissions.txt", permissions)
    if b"uses-permission" in permissions.stdout:
        raise RuntimeError("Test APK unexpectedly requests permissions")
    with ZipFile(signed) as archive:
        if archive.read("lib/arm64-v8a/libfutex_pi_probe.so") != native.read_bytes():
            raise RuntimeError("APK binary does not match standalone binary")
    hashes = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
              for path in [native, signed, ROOT / "tests/device/futex_pi_probe.c",
                           source / "AndroidManifest.xml", source / "FutexInstrumentation.java",
                           Path(__file__).resolve()]}
    (output / "sha256.json").write_text(json.dumps(hashes, indent=2), encoding="utf-8")
    return native, signed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--sdk", default=r"D:\Android\SDK")
    parser.add_argument("--ndk", default=os.environ.get("ANDROID_NDK_HOME"))
    parser.add_argument("--java-home", default=r"D:\Android\Android Studio\jbr")
    parser.add_argument("--output", default="build/futex-pi-device-test")
    args = parser.parse_args()
    output = (ROOT / args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    native, apk = build(args, output)
    print("Built identical native probe and zero-permission APK", flush=True)

    def adb(*command, **kwargs):
        return run(["adb", "-s", args.serial, *command], **kwargs)

    def shell(command, *, root=False, **kwargs):
        if root:
            command = "su -c " + shlex.quote(command)
        return adb("shell", command, **kwargs)

    remote = "/data/local/tmp/gpc-futex-pi-probe-20261112"
    installed = False
    if b"package:" in shell("pm path " + PACKAGE, check=False).stdout:
        raise RuntimeError("Test package already exists; refusing to replace it")
    try:
        adb("push", native, remote)
        shell("chmod 755 " + shlex.quote(remote))
        write_capture(output / "install.txt", adb("install", "-t", apk))
        installed = True
        write_capture(output / "environment.txt", shell(
            "id; uname -a; getprop ro.product.model; getprop ro.build.version.release; "
            "getprop ro.build.version.sdk; cat /proc/sys/kernel/pid_max; getenforce"))
        before = shell(remote + " --snapshot", root=True)
        write_capture(output / "before.jsonl", before)
        tasks = [row for row in records(before.stdout)
                 if row["type"] == "task" and row["stat"]["errno"] == 0
                 and row["stat"]["state"] not in ("Z", "X", "x")]
        kernel = [row for row in tasks if row["stat"]["pf_kthread"]]
        user = [row for row in tasks if not row["stat"]["pf_kthread"]]
        selected = sample(kernel, 32)
        selected += sample([row for row in user if row["tid"] == row["tgid"]], 16)
        selected += sample([row for row in user if row["tid"] != row["tgid"]], 16)
        # Include stable, easily recognizable examples in addition to spread sampling.
        selected += [row for row in tasks if row["tid"] in (1, 2, 3, 12)
                     or (row["tid"] == row["tgid"] and row["stat"]["comm"] in
                         ("system_server", "surfaceflinger", "zygote64", "com.gpucheck.app"))]
        selected = list({row["tid"]: row for row in selected}.values())
        selected.sort(key=lambda row: row["tid"])
        (output / "targets.json").write_text(json.dumps(selected, indent=2), encoding="utf-8")
        targets = [str(row["tid"]) for row in selected]
        command = remote + " --repeat 20 " + " ".join(targets)
        all_runs = {}
        for mode in ("root", "shell"):
            result = shell(command, root=mode == "root")
            write_capture(output / (mode + ".jsonl"), result)
            all_runs[mode] = records(result.stdout)
            print(f"Captured {mode}: {len(selected)} external targets", flush=True)
        result = shell("am instrument -w -r -e targets " + shlex.quote(",".join(targets))
                       + " " + COMPONENT)
        write_capture(output / "app-instrumentation.txt", result)
        if b"result=PASS" not in result.stdout:
            raise RuntimeError("App instrumentation did not pass: " + result.stdout.decode(errors="replace"))
        for filename, destination in (("results.jsonl", "app.jsonl"), ("errors.txt", "app-native-stderr.txt")):
            result = shell("cat " + shlex.quote(f"/data/user/0/{PACKAGE}/files/{filename}"), root=True)
            write_capture(output / destination, result)
        all_runs["app"] = records((output / "app.jsonl").read_bytes())
        after = shell(remote + " --snapshot", root=True)
        write_capture(output / "after.jsonl", after)
        after_by_tid = {row["tid"]: row for row in records(after.stdout) if row["type"] == "task"}
        stable, changed = {}, []
        for row in selected:
            post = after_by_tid.get(row["tid"], {}).get("stat", {})
            pre = row["stat"]
            if (post.get("errno") == 0 and post["starttime"] == pre["starttime"]
                    and post["pf_kthread"] == pre["pf_kthread"]
                    and post["state"] not in ("Z", "X", "x")):
                stable[row["tid"]] = row
            else:
                changed.append(row["tid"])
        summary = {"serial": args.serial, "stable_kernel_tids": sum(
            row["stat"]["pf_kthread"] for row in stable.values()),
            "stable_user_tids": sum(not row["stat"]["pf_kthread"] for row in stable.values()),
            "unstable_tids_excluded": changed, "modes": {}, "mismatches": []}
        expected_controls = {"zero_unlocked": (0, 0), "self": (-1, 35),
                             "live_same_process_thread": (-1, 11), "zombie": (-1, 3),
                             "nonexistent": (-1, 3), "exited_thread": (-1, 3)}
        for mode, rows in all_runs.items():
            meta = next(row for row in rows if row["type"] == "meta")
            end = [row for row in rows if row["type"] == "end"]
            if len(end) != 1 or end[0]["cleanup_failures"] != 0:
                raise RuntimeError(f"Incomplete native run: {mode}")
            if mode == "app" and not (meta["uid"] >= 10000 and "untrusted_app" in meta["selinux"]
                                      and int(meta["cap_eff"], 16) == 0):
                raise RuntimeError("App was not running in ordinary untrusted sandbox")
            counts, totals = Counter(), Counter()
            for row in rows:
                if row["type"] != "probe":
                    continue
                label = row["label"]
                if label == "external":
                    if row["tid"] not in stable:
                        continue
                    label = "kernel" if stable[row["tid"]]["stat"]["pf_kthread"] else "user"
                    expected = (-1, 1 if label == "kernel" else 11)
                else:
                    expected = expected_controls[label]
                counts[f"{label} private={row['private']} ret={row['ret']} errno={row['errno']}"] += 1
                totals[(row["label"], row["tid"], row["private"])] += 1
                if (row["ret"], row["errno"]) != expected:
                    summary["mismatches"].append({"mode": mode, **row})
            if any(count != 20 for count in totals.values()) or len(totals) != 2 * (len(stable) + 6):
                raise RuntimeError(f"Missing repetitions or cases in {mode}")
            summary["modes"][mode] = {"meta": meta, "counts": dict(sorted(counts.items()))}
        (output / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(json.dumps(summary, indent=2), flush=True)
        if summary["mismatches"]:
            raise RuntimeError("Unexpected results; inspect raw evidence")
    finally:
        cleanup = []
        if installed:
            result = adb("uninstall", PACKAGE, check=False)
            cleanup.append({"action": "uninstall test APK", "returncode": result.returncode,
                            "stdout": result.stdout.decode(errors="replace")})
        result = shell("rm -f " + shlex.quote(remote), check=False)
        cleanup.append({"action": "remove exact temporary binary", "returncode": result.returncode})
        remaining = shell("pm path " + PACKAGE + "; ls -l " + shlex.quote(remote), check=False)
        cleanup.append({"action": "verify absence", "returncode": remaining.returncode,
                        "stdout": remaining.stdout.decode(errors="replace"),
                        "stderr": remaining.stderr.decode(errors="replace")})
        (output / "cleanup.json").write_text(json.dumps(cleanup, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
