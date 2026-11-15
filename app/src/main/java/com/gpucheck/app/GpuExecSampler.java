package com.gpucheck.app;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/** One cancellable native sampler per App process; a new session retires the old one. */
final class GpuExecSampler implements AutoCloseable {
    private static final boolean LOADED;
    static {
        boolean loaded;
        try { System.loadLibrary("gpu_exec"); loaded = true; }
        catch (LinkageError | SecurityException error) { loaded = false; }
        LOADED = loaded;
    }
    private final long session = LOADED ? nativeOpen() : 0;
    private volatile boolean closed;

    JSONObject measure(int[] slots, int samples, int windowMs, int slotCount) throws JSONException {
        if (closed || session == 0) return unavailable(closed ? "cancelled" : "native_unavailable");
        try {
            String raw = nativeMeasure(session, slots, samples, windowMs, slotCount);
            return raw == null ? unavailable("empty_result") : new JSONObject(raw);
        } catch (LinkageError | RuntimeException error) { return unavailable("native_failed"); }
    }
    JSONObject measureFrequency(int slotCount, int windowMs) throws JSONException {
        if (closed || session == 0) return frequencyUnavailable(closed ? "cancelled" : "native_unavailable");
        try {
            String raw = nativeMeasureFrequency(session, slotCount, windowMs);
            return raw == null ? frequencyUnavailable("empty_result") : new JSONObject(raw);
        } catch (LinkageError | RuntimeException error) { return frequencyUnavailable("native_failed"); }
    }
    @Override public void close() {
        closed = true;
        if (session != 0) nativeCancel(session);
    }
    static JSONObject unavailable(String reason) throws JSONException {
        return new JSONObject().put("method", "gpuexec_multi").put("status", "unavailable")
                .put("reason", reason).put("scope", "device_global_unattributed").put("slots", new JSONArray());
    }
    static JSONObject frequencyUnavailable(String reason) throws JSONException {
        return unavailable(reason).put("method", "gpu_slot_frequency").put("fullWindow", false);
    }
    private static native long nativeOpen();
    private static native void nativeCancel(long session);
    private static native String nativeMeasure(long session, int[] slots, int samples, int windowMs, int slotCount);
    private static native String nativeMeasureFrequency(long session, int slotCount, int windowMs);
}
