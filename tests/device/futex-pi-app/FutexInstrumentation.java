package com.gpucheck.futexaudit;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.Context;
import android.os.Bundle;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/** Runs the identical standalone binary under the ordinary application sandbox. */
public final class FutexInstrumentation extends Instrumentation {
    private Bundle arguments;

    @Override public void onCreate(Bundle args) {
        super.onCreate(args);
        arguments = args == null ? new Bundle() : new Bundle(args);
        start();
    }

    @Override public void onStart() {
        Bundle result = new Bundle();
        Process child = null;
        int code = Activity.RESULT_CANCELED;
        try {
            Context context = getTargetContext();
            if (android.os.Process.myUid() < 10000) {
                throw new IllegalStateException("Expected ordinary application UID");
            }
            List<String> command = new ArrayList<>();
            command.add(new File(context.getApplicationInfo().nativeLibraryDir,
                    "libfutex_pi_probe.so").getAbsolutePath());
            command.add("--repeat");
            command.add("20");
            String targets = arguments.getString("targets", "");
            for (String tid : targets.split(",")) {
                if (!tid.matches("[1-9][0-9]*")) {
                    throw new IllegalArgumentException("Invalid TID");
                }
                command.add(tid);
            }
            File output = new File(context.getFilesDir(), "results.jsonl");
            File errors = new File(context.getFilesDir(), "errors.txt");
            child = new ProcessBuilder(command).redirectOutput(output).redirectError(errors).start();
            if (!child.waitFor(40, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Probe timed out");
            }
            result.putInt("native_exit", child.exitValue());
            result.putInt("app_uid", android.os.Process.myUid());
            result.putLong("output_bytes", output.length());
            if (child.exitValue() != 0 || output.length() == 0 || errors.length() != 0) {
                throw new IllegalStateException("Probe failed");
            }
            result.putString("result", "PASS");
            code = Activity.RESULT_OK;
        } catch (Throwable error) {
            result.putString("result", "FAIL");
            result.putString("error", android.util.Log.getStackTraceString(error));
        } finally {
            if (child != null && child.isAlive()) child.destroyForcibly();
            finish(code, result);
        }
    }
}
