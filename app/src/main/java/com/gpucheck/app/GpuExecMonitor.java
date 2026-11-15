package com.gpucheck.app;

import android.os.SystemClock;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Bounded, asynchronous short windows. No result participates in PID attribution or risk scoring. */
final class GpuExecMonitor implements AutoCloseable {
    static final int MAX_SLOTS = 16, SAMPLES = 30, WINDOW_MS = 500;
    static final long INTERVAL_MS = 5000, EXPIRY_MS = 15000;
    private final GpuExecSampler sampler = new GpuExecSampler();
    private final ExecutorService worker = Executors.newSingleThreadExecutor(r -> new Thread(r, "gpu-exec-coordinator"));
    private boolean closed, busy;
    private long lastStartedMs, resultAtMs, epoch;
    private int cursor;
    private int layoutCount;
    private String latest;
    private final Set<Integer> invalidatedLatest = new HashSet<>();
    private final Set<Integer> invalidatedDuringJob = new HashSet<>();
    private final GpuSlotFrequencyMonitor frequency;

    GpuExecMonitor() { this(null); }
    GpuExecMonitor(Runnable frequencyChanged) {
        frequency = new GpuSlotFrequencyMonitor(sampler, frequencyChanged);
    }
    JSONObject frequencySnapshot() throws JSONException { return frequency.snapshot(); }

    synchronized void enrich(JSONObject report) throws JSONException {
        if (closed) return;
        JSONObject global = report.optJSONObject("globalGpu");
        frequency.configure(global);
        if (global != null) global.put("slotFrequency", frequency.snapshot());
        JSONObject filter = global == null ? null : global.optJSONObject("highFrequency");
        if (global == null) return;
        long now = SystemClock.uptimeMillis();
        if (!global.optBoolean("supported") || filter == null || !filter.optBoolean("selfFilterComplete")) {
            latest = null; epoch++;
            global.put("execMulti", GpuExecSampler.unavailable(global.optBoolean("supported")
                    ? "waiting_self_filter" : "gpu_unavailable"));
            return;
        }
        JSONArray deltas = global.optJSONArray("slotDeltas");
        if (deltas == null) {
            latest = null; epoch++;
            global.put("execMulti", GpuExecSampler.unavailable("layout_unavailable")); return;
        }
        int count = deltas.length(), end = Math.min(256, Math.min(count - 7, global.optInt("lifecycleSlotEndExclusive", 1)));
        if (count != layoutCount) { latest = null; epoch++; layoutCount = count; invalidatedLatest.clear(); }
        Set<Integer> excluded = ids(filter.optJSONArray("selfSlotsExcluded"));
        Set<Integer> invalid = ids(global.optJSONArray("resetSlots"));
        invalid.addAll(ids(global.optJSONArray("slotDeltaWrappedSlots")));
        invalid.addAll(ids(global.optJSONArray("disappearedSlots")));
        invalidatedLatest.addAll(excluded); invalidatedLatest.addAll(invalid);
        if (busy) { invalidatedDuringJob.addAll(excluded); invalidatedDuringJob.addAll(invalid); }
        List<Integer> candidates = new ArrayList<>();
        int outsideRange = 0;
        for (int id = 1; id < count - 7; id++) {
            double delta = deltas.optDouble(id, Double.NaN);
            if (!Double.isFinite(delta) || delta <= 0 || excluded.contains(id) || invalid.contains(id)) continue;
            if (id < end) candidates.add(id); else outsideRange++;
        }
        if (!busy && !candidates.isEmpty() && (lastStartedMs == 0 || now - lastStartedMs >= INTERVAL_MS)) {
            List<Integer> ordered = new ArrayList<>();
            for (int id : candidates) if (id > cursor) ordered.add(id);
            for (int id : candidates) if (id <= cursor) ordered.add(id);
            int[] selected = new int[Math.min(MAX_SLOTS, ordered.size())];
            for (int i = 0; i < selected.length; i++) selected[i] = ordered.get(i);
            cursor = selected[selected.length - 1];
            invalidatedDuringJob.clear();
            busy = true; lastStartedMs = now;
            final long jobEpoch = epoch;
            final String selection = new JSONArray(selected).toString();
            final String before = filter.toString();
            worker.execute(() -> collect(selected, count, jobEpoch, selection, before));
        }
        JSONObject snapshot;
        if (latest != null && now - resultAtMs <= EXPIRY_MS) {
            snapshot = new JSONObject(latest);
            JSONArray rows = snapshot.optJSONArray("slots");
            for (int i = 0; rows != null && i < rows.length(); i++) {
                JSONObject row = rows.getJSONObject(i);
                int id = row.optInt("slot", -1);
                boolean suppressed = invalidatedLatest.contains(id) || id < 1 || id >= end;
                if (suppressed) row.put("eligible", false).put("suppressedReason", "current_self_or_discontinuous_slot");
            }
            snapshot.put("ageMs", now - resultAtMs);
        } else {
            snapshot = GpuExecSampler.unavailable(busy ? "sampling" : candidates.isEmpty()
                    ? "no_active_external_slots" : "waiting_next_window");
        }
        snapshot.put("sampling", busy).put("candidateCount", candidates.size())
                .put("selectionTruncated", candidates.size() > MAX_SLOTS).put("activeOutsideRange", outsideRange)
                .put("selfSlotsExcluded", new JSONArray(excluded)).put("maximumSlots", MAX_SLOTS)
                .put("intervalMs", INTERVAL_MS).put("windowMs", WINDOW_MS);
        global.put("execMulti", snapshot);
    }

    private void collect(int[] slots, int count, long jobEpoch, String selection, String before) {
        String result;
        try {
            JSONObject measured = sampler.measure(slots, SAMPLES, WINDOW_MS, count);
            synchronized (this) { if (closed) { busy = false; return; } }
            JSONObject after = SelfGpuSlots.inspect(1, count - 7);
            boolean verified = after.optBoolean("complete") && after.optInt("pid") == android.os.Process.myPid()
                    && after.optInt("uid") == android.os.Process.myUid();
            Set<Integer> own = ids(after.optJSONArray("slots"));
            JSONArray rows = measured.optJSONArray("slots");
            for (int i = 0; rows != null && i < rows.length(); i++) {
                JSONObject row = rows.getJSONObject(i);
                row.put("eligible", verified && row.optBoolean("valid") && !own.contains(row.optInt("slot", -1)));
            }
            measured.put("selection", new JSONArray(selection)).put("selfFilterBefore", new JSONObject(before))
                    .put("selfQueryAfter", after).put("selfFilterAfterComplete", verified);
            result = measured.toString();
        } catch (Exception error) {
            result = "{\"method\":\"gpuexec_multi\",\"scope\":\"device_global_unattributed\",\"status\":\"unavailable\",\"reason\":\"sampling_failed\",\"slots\":[]}";
        }
        synchronized (this) {
            busy = false;
            if (!closed && jobEpoch == epoch) {
                latest = result; resultAtMs = SystemClock.uptimeMillis();
                invalidatedLatest.clear(); invalidatedLatest.addAll(invalidatedDuringJob);
            }
        }
    }

    static Set<Integer> ids(JSONArray array) {
        Set<Integer> result = new HashSet<>();
        for (int i = 0; array != null && i < array.length(); i++) result.add(array.optInt(i, -1));
        return result;
    }
    @Override public synchronized void close() {
        closed = true; latest = null; epoch++;
        frequency.close();
        sampler.close(); worker.shutdownNow();
    }
}
