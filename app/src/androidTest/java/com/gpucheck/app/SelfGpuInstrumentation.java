package com.gpucheck.app;

import android.app.Activity;
import android.app.Instrumentation;
import android.opengl.EGL14;
import android.opengl.EGLConfig;
import android.opengl.EGLContext;
import android.opengl.EGLDisplay;
import android.opengl.EGLSurface;
import android.opengl.GLES20;
import android.os.Bundle;
import android.os.SystemClock;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/** Device test: real App-owned EGL work, real owner queries, and a synthetic external-slot control. */
public final class SelfGpuInstrumentation extends Instrumentation {
    @Override public void onCreate(Bundle arguments) { super.onCreate(arguments); start(); }

    @Override public void onStart() {
        Bundle result = new Bundle();
        try {
            verify(result);
            result.putString("result", "PASS");
            finish(Activity.RESULT_OK, result);
        } catch (Throwable error) {
            result.putString("result", "FAIL");
            result.putString("error", android.util.Log.getStackTraceString(error));
            finish(Activity.RESULT_CANCELED, result);
        }
    }

    private void verify(Bundle result) throws Exception {
        EglWorkload work = new EglWorkload();
        java.lang.Process collector = null;
        int ownHighSamples = 0, completeSamples = 0, externalControlMatches = 0, reports = 0;
        int maxOwned = 0, maxQueryCount = 0;
        long maxQueryNs = 0;
        try {
            work.start();
            check(work.ready.await(5, TimeUnit.SECONDS), "EGL setup timed out");
            if (work.error != null) throw new AssertionError("EGL setup failed", work.error);
            File binary = new File(getTargetContext().getApplicationInfo().nativeLibraryDir, "libgpu_probe.so");
            collector = new ProcessBuilder(binary.getAbsolutePath(), "--samples", "10",
                    "--interval-ms", "2000", "--pid-limit", "1024").start();
            RiskEngine filteredEngine = new RiskEngine(20, 3, 2000);
            RiskEngine externalControl = new RiskEngine(20, 3, 2000);
            GpuHighFrequency unfiltered = new GpuHighFrequency();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(collector.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (!line.startsWith("{")) continue;
                    JSONObject raw = new JSONObject(line);
                    SelfGpuSlots.enrich(raw);
                    JSONObject global = raw.getJSONObject("globalGpu");
                    check(global.optBoolean("supported"), "KGSL memstore unavailable in target App");
                    JSONObject query = global.getJSONObject("selfGpuSlots");
                    check(query.optInt("pid") == android.os.Process.myPid(), "owner query ran outside App process");
                    check(query.optInt("uid") == android.os.Process.myUid() && android.os.Process.myUid() != 0,
                            "owner query did not run as the ordinary App UID");
                    JSONArray own = query.getJSONArray("slots");
                    maxOwned = Math.max(maxOwned, own.length());
                    maxQueryCount = Math.max(maxQueryCount, query.optInt("queryCount"));
                    maxQueryNs = Math.max(maxQueryNs,
                            query.optLong("queryFinishedMonotonicNs") - query.optLong("queryStartedMonotonicNs"));
                    if (query.optBoolean("complete")) completeSamples++;
                    JSONArray deltas = global.getJSONArray("slotDeltas");
                    boolean[] owned = new boolean[deltas.length()];
                    for (int i = 0; i < own.length(); i++) owned[own.getInt(i)] = true;
                    double[] rawOwn = new double[deltas.length()];
                    JSONArray ownOnly = new JSONArray();
                    for (int slot = 0; slot < deltas.length(); slot++) {
                        rawOwn[slot] = owned[slot] ? deltas.optDouble(slot, Double.NaN) : 0;
                        ownOnly.put(owned[slot] ? deltas.opt(slot) : 0);
                    }
                    int first = global.getInt("lifecycleSlotFirst"), end = global.getInt("lifecycleSlotEndExclusive");
                    GpuHighFrequency.Result rawResult = unfiltered.update(global.optLong("sampleMonotonicNs"),
                            global.optLong("intervalNs"), global.optBoolean("sampled"), rawOwn, first, end,
                            ints(global.optJSONArray("appearedSlots")), ints(global.optJSONArray("disappearedSlots")),
                            ints(global.optJSONArray("resetSlots")), ints(global.optJSONArray("slotDeltaWrappedSlots")));
                    if (rawResult.active) ownHighSamples++;

                    // Preserve measured App activity while removing unrelated device activity from this assertion.
                    global.put("slotDeltas", ownOnly);
                    JSONObject filtered = filteredEngine.process(new JSONObject(raw.toString()));
                    JSONObject hint = filtered.getJSONObject("globalGpu").getJSONObject("highFrequency");
                    check(!hint.optBoolean("active"), "App-owned GPU activity triggered the overlay hint: " + hint);
                    check(ownOnly.toString().equals(filtered.getJSONObject("globalGpu").getJSONArray("slotDeltas").toString()),
                            "filter modified raw GPU counters");

                    // Counter-only control: a non-owned ID must still be eligible after self filtering.
                    int externalSlot = end - 1;
                    while (externalSlot >= first && owned[externalSlot]) externalSlot--;
                    check(externalSlot >= first, "no non-owned slot available for control");
                    JSONObject control = new JSONObject(raw.toString());
                    JSONObject controlGpu = control.getJSONObject("globalGpu");
                    controlGpu.getJSONArray("slotDeltas").put(externalSlot, 60.0 * global.optLong("intervalNs") / 1_000_000_000.0);
                    controlGpu.put("appearedSlots", new JSONArray()).put("disappearedSlots", new JSONArray())
                            .put("resetSlots", new JSONArray()).put("slotDeltaWrappedSlots", new JSONArray());
                    JSONObject controlHint = externalControl.process(control).getJSONObject("globalGpu").getJSONObject("highFrequency");
                    if (controlHint.optBoolean("active")) {
                        JSONArray matching = controlHint.getJSONArray("slots");
                        check(matching.length() == 1 && matching.getJSONObject(0).getInt("slot") == externalSlot,
                                "external control incorrectly included a self slot");
                        externalControlMatches++;
                    }
                    reports++;
                }
            }
            check(collector.waitFor(5, TimeUnit.SECONDS) && collector.exitValue() == 0, "collector did not finish cleanly");
            check(reports == 10, "incomplete sample run");
            check(maxOwned > 0 && completeSamples >= 6, "self owner queries were not verified across the run");
            check(ownHighSamples > 0, "real EGL workload did not sustain the high-frequency threshold");
            check(externalControlMatches > 0, "self filtering suppressed the external-slot control");
            check(work.error == null, "EGL workload failed");
            result.putInt("appPid", android.os.Process.myPid());
            result.putInt("appUid", android.os.Process.myUid());
            result.putInt("reports", reports);
            result.putInt("maxOwnedSlots", maxOwned);
            result.putInt("completeOwnerQueries", completeSamples);
            result.putInt("maxQueryCount", maxQueryCount);
            result.putLong("maxQueryMs", maxQueryNs / 1_000_000L);
            result.putInt("realOwnHighFrequencySamples", ownHighSamples);
            result.putInt("syntheticExternalControlMatches", externalControlMatches);
        } finally {
            if (collector != null) collector.destroy();
            work.running = false;
            work.join(5000);
            check(!work.isAlive(), "EGL test worker did not stop");
        }
    }

    private static int[] ints(JSONArray values) {
        int[] result = new int[values == null ? 0 : values.length()];
        for (int i = 0; i < result.length; i++) result[i] = values.optInt(i, -1);
        return result;
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static final class EglWorkload extends Thread {
        final CountDownLatch ready = new CountDownLatch(1);
        volatile boolean running = true;
        volatile Throwable error;
        @Override public void run() {
            EGLDisplay display = EGL14.EGL_NO_DISPLAY;
            EGLContext context = EGL14.EGL_NO_CONTEXT;
            EGLSurface surface = EGL14.EGL_NO_SURFACE;
            try {
                display = EGL14.eglGetDisplay(EGL14.EGL_DEFAULT_DISPLAY);
                check(display != EGL14.EGL_NO_DISPLAY && EGL14.eglInitialize(display, new int[2], 0, new int[2], 0), "eglInitialize failed");
                int[] attributes = {EGL14.EGL_SURFACE_TYPE, EGL14.EGL_PBUFFER_BIT,
                        EGL14.EGL_RENDERABLE_TYPE, EGL14.EGL_OPENGL_ES2_BIT,
                        EGL14.EGL_RED_SIZE, 8, EGL14.EGL_GREEN_SIZE, 8, EGL14.EGL_BLUE_SIZE, 8, EGL14.EGL_ALPHA_SIZE, 8, EGL14.EGL_NONE};
                EGLConfig[] configs = new EGLConfig[1];
                int[] count = new int[1];
                check(EGL14.eglChooseConfig(display, attributes, 0, configs, 0, 1, count, 0) && count[0] > 0, "no EGL config");
                context = EGL14.eglCreateContext(display, configs[0], EGL14.EGL_NO_CONTEXT,
                        new int[]{EGL14.EGL_CONTEXT_CLIENT_VERSION, 2, EGL14.EGL_NONE}, 0);
                surface = EGL14.eglCreatePbufferSurface(display, configs[0],
                        new int[]{EGL14.EGL_WIDTH, 16, EGL14.EGL_HEIGHT, 16, EGL14.EGL_NONE}, 0);
                check(context != EGL14.EGL_NO_CONTEXT && surface != EGL14.EGL_NO_SURFACE
                        && EGL14.eglMakeCurrent(display, surface, surface, context), "EGL context setup failed");
                ByteBuffer pixel = ByteBuffer.allocateDirect(4);
                int frame = 0;
                while (running) {
                    GLES20.glClearColor((frame++ & 1) == 0 ? 0.25f : 0.75f, 0.5f, 0.25f, 1);
                    GLES20.glClear(GLES20.GL_COLOR_BUFFER_BIT);
                    GLES20.glReadPixels(0, 0, 1, 1, GLES20.GL_RGBA, GLES20.GL_UNSIGNED_BYTE, pixel);
                    GLES20.glFinish();
                    check(GLES20.glGetError() == GLES20.GL_NO_ERROR, "EGL workload GL error");
                    ready.countDown();
                    SystemClock.sleep(8);
                }
            } catch (Throwable failure) { error = failure; ready.countDown(); }
            finally {
                if (display != EGL14.EGL_NO_DISPLAY) {
                    EGL14.eglMakeCurrent(display, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_CONTEXT);
                    if (surface != EGL14.EGL_NO_SURFACE) EGL14.eglDestroySurface(display, surface);
                    if (context != EGL14.EGL_NO_CONTEXT) EGL14.eglDestroyContext(display, context);
                    EGL14.eglTerminate(display);
                }
                EGL14.eglReleaseThread();
            }
        }
    }
}
