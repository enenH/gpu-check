package com.gpucheck.app;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/** Runs in the App, where HWUI/EGL's existing file descriptions are actually held. */
final class SelfGpuSlots {
    private static final boolean NATIVE_LOADED;
    static {
        boolean loaded;
        try { System.loadLibrary("gpu_self"); loaded = true; }
        catch (LinkageError | SecurityException error) { loaded = false; }
        NATIVE_LOADED = loaded;
    }

    private SelfGpuSlots() { }

    static void enrich(JSONObject report) throws JSONException {
        JSONObject global = report.optJSONObject("globalGpu");
        if (global == null) return;
        JSONArray deltas = global.optJSONArray("slotDeltas");
        int count = deltas == null ? 0 : deltas.length();
        int first = Math.max(1, global.optInt("lifecycleSlotFirst", 1));
        int end = Math.min(count - 7, global.optInt("lifecycleSlotEndExclusive", 1));
        JSONObject query = global.optBoolean("supported") && count <= 4096 && first < end
                ? inspect(first, end) : unavailable("gpu_slot_layout_unavailable");
        global.put("selfGpuSlots", query);
    }

    static JSONObject inspect(int first, int end) throws JSONException {
        if (!NATIVE_LOADED) return unavailable("native_owner_query_unavailable");
        try {
            String raw = nativeInspect(first, end);
            return raw == null ? unavailable("native_owner_query_empty") : new JSONObject(raw);
        } catch (LinkageError | RuntimeException | JSONException error) {
            return unavailable("native_owner_query_failed");
        }
    }

    private static JSONObject unavailable(String error) throws JSONException {
        return new JSONObject().put("complete", false).put("slots", new JSONArray()).put("error", error)
                .put("pid", android.os.Process.myPid()).put("uid", android.os.Process.myUid());
    }

    private static native String nativeInspect(int first, int end);
}
