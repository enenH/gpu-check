package com.gpucheck.cgroupaudit;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.Context;
import android.os.Bundle;
import android.os.SystemClock;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/** Standalone, zero-permission device test; not part of the GPU Check product. */
public final class AuditInstrumentation extends Instrumentation {
    private Bundle arguments;

    @Override public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        this.arguments = arguments == null ? new Bundle() : new Bundle(arguments);
        start();
    }

    @Override public void onStart() {
        Bundle result = new Bundle();
        java.lang.Process collector = null;
        int resultCode = Activity.RESULT_CANCELED;
        long started = SystemClock.elapsedRealtime();
        try {
            Context context = getTargetContext();
            result.putInt("app_uid", android.os.Process.myUid());
            result.putInt("app_pid", android.os.Process.myPid());
            result.putString("app_selinux", new String(Files.readAllBytes(
                    new File("/proc/self/attr/current").toPath()), StandardCharsets.UTF_8).trim());
            if (android.os.Process.myUid() < 10000) {
                throw new IllegalStateException("Expected an ordinary application UID");
            }
            File executable = new File(context.getApplicationInfo().nativeLibraryDir,
                    "libcgroup_audit.so");
            File output = new File(context.getFilesDir(), "audit.json");
            File errors = new File(context.getFilesDir(), "audit.err");
            result.putString("output", output.getAbsolutePath());
            result.putString("stderr", errors.getAbsolutePath());
            List<String> command = new ArrayList<>();
            command.add(executable.getAbsolutePath());
            if ("true".equals(arguments.getString("fixtures"))) {
                command.add("--fixtures");
            }
            String targets = arguments.getString("targets_file");
            if (targets != null) {
                if (!new File(targets).isAbsolute()) {
                    throw new IllegalArgumentException("targets_file must be absolute");
                }
                command.add("--targets-file");
                command.add(targets);
            }
            collector = new ProcessBuilder(command)
                    .redirectOutput(output)
                    .redirectError(errors)
                    .start();
            if (!collector.waitFor(120, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Native audit timed out after 120 seconds");
            }
            int exitCode = collector.exitValue();
            result.putInt("native_exit", exitCode);
            result.putLong("output_bytes", output.length());
            result.putLong("stderr_bytes", errors.length());
            if (exitCode != 0 || output.length() == 0) {
                throw new IllegalStateException("Native audit failed, exit=" + exitCode);
            }
            result.putString("result", "PASS");
            resultCode = Activity.RESULT_OK;
        } catch (Throwable error) {
            result.putString("result", "FAIL");
            result.putString("error", android.util.Log.getStackTraceString(error));
        } finally {
            if (collector != null && collector.isAlive()) {
                collector.destroyForcibly();
            }
            result.putLong("duration_ms", SystemClock.elapsedRealtime() - started);
            finish(resultCode, result);
        }
    }
}
