Cgroup Audit ordinary-App test harness

This standalone package is not part of the GPU Check application. It declares
no permissions and is not debuggable. Instrumentation runs the packaged native
auditor as a child of an ordinary Android application process; the native JSON
must be checked for the actual UID, groups and SELinux domain.

Build from the repository root after compiling the native auditor:
    .\scripts\cgroup-audit-app\build.ps1
Default input:
    build\cgroup-device-test\bin\cgroup_audit
Default output:
    build\cgroup-device-test\app-probe\CgroupAuditTest.apk

Install and run (replace SERIAL):
    adb -s SERIAL install -r -t build\cgroup-device-test\app-probe\CgroupAuditTest.apk
    adb -s SERIAL shell am instrument -w -r com.gpucheck.cgroupaudit/com.gpucheck.cgroupaudit.AuditInstrumentation

Optional instrumentation arguments:
    -e fixtures true
    -e targets_file /absolute/path/to/readable/targets-file
These map to the native auditor's --fixtures and --targets-file options.
Targets supplied by a root test controller are ground-truth validation inputs,
not evidence that an ordinary application can discover those targets itself.

The native executable is extracted from lib/arm64-v8a/libcgroup_audit.so.
Output and stderr are saved as:
    /data/user/0/com.gpucheck.cgroupaudit/files/audit.json
    /data/user/0/com.gpucheck.cgroupaudit/files/audit.err
The instrumentation response includes app_uid, app_pid, app_selinux,
native_exit, output_bytes, stderr_bytes and duration_ms. A PASS indicates that
the collector ran and produced output, not that cgroup coverage was complete.
The device-test controller may copy output with its existing root access.

Cleanup after collecting evidence:
    adb -s SERIAL uninstall com.gpucheck.cgroupaudit
