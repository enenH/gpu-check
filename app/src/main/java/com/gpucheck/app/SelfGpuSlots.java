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

    static synchronized JSONObject inspect(int first, int end) throws JSONException {
        if (!NATIVE_LOADED) return unavailable("native_owner_query_unavailable");
        try {
            long started = android.os.SystemClock.uptimeMillis();
            int retriedRaces = 0;
            long firstQueryNs = 0;
            java.util.Set<Integer> confirmedSlots = new java.util.LinkedHashSet<>();
            JSONArray priorAttempts = new JSONArray();
            for (int attempt = 1; ; attempt++) {
                String raw = nativeInspect(first, end);
                JSONObject query = raw == null ? unavailable("native_owner_query_empty") : new JSONObject(raw);
                long queryStarted = query.optLong("queryStartedMonotonicNs");
                if (firstQueryNs == 0 && queryStarted > 0) firstQueryNs = queryStarted;
                JSONArray own = query.optJSONArray("slots");
                for (int i = 0; own != null && i < own.length(); i++) confirmedSlots.add(own.getInt(i));
                query.put("attempts", attempt).put("retriedScanRaceCount", retriedRaces);
                // A descriptor closed during enumeration is uncertainty, not a non-owner.
                // Retry that transient race with a new complete scan; never accept a partial one.
                if (query.optBoolean("complete") || attempt >= 3 || query.optInt("scanRaceCount") <= 0
                        || query.optBoolean("timedOut") || query.optInt("queryErrorCount") > 0
                        || android.os.SystemClock.uptimeMillis() - started >= 15) {
                    if (attempt > 1) query.put("slots", new JSONArray(confirmedSlots))
                            .put("queryStartedMonotonicNs", firstQueryNs).put("priorAttempts", priorAttempts);
                    return query;
                }
                priorAttempts.put(new JSONObject(query.toString()));
                retriedRaces += query.optInt("scanRaceCount");
            }
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
