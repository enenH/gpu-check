package com.gpucheck.app;

import android.os.SystemClock;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Continuous full windows; owns no GPU context and shares its parent's cancellable session. */
final class GpuSlotFrequencyMonitor implements AutoCloseable {
    static final int WINDOW_MS = 500;
    static final long EXPIRY_MS = 1500;
    private final GpuExecSampler sampler;
    private final Runnable changed;
    private final GpuSlotFrequency policy = new GpuSlotFrequency();
    private final Thread worker;
    private boolean closed, enabled;
    private int slotCount, endExclusive;
    private long epoch, resultAtMs;
    private String latest;
    private String unavailableReason = "waiting_self_filter";
    private Set<Integer> currentExcluded = new HashSet<>(), previousOwn = new HashSet<>();
    private final Set<Integer> invalidatedDuringWindow = new HashSet<>();

    GpuSlotFrequencyMonitor(GpuExecSampler sampler, Runnable changed) {
        this.sampler = sampler; this.changed = changed;
        worker = new Thread(this::run, "gpu-frequency-worker");
        worker.start();
    }

    synchronized void configure(JSONObject global) {
        if (closed) return;
        JSONObject filter = global == null ? null : global.optJSONObject("highFrequency");
        JSONArray deltas = global == null ? null : global.optJSONArray("slotDeltas");
        int count = deltas == null ? 0 : deltas.length();
        int end = global == null ? 0 : global.optInt("lifecycleSlotEndExclusive", 0);
        boolean ready = global != null && global.optBoolean("supported") && count >= 9 && count <= 4096
                && end == count - 7 && filter != null && filter.optBoolean("selfFilterComplete");
        if (!ready) {
            enabled = false; epoch++; latest = null; policy.reset(); previousOwn.clear();
            unavailableReason = global != null && global.optBoolean("supported") ? "waiting_self_filter" : "gpu_unavailable";
            notifyAll(); return;
        }
        if (!enabled || slotCount != count || endExclusive != end) {
            epoch++; latest = null; policy.reset(); previousOwn.clear();
        }
        enabled = true; slotCount = count; endExclusive = end;
        currentExcluded = GpuExecMonitor.ids(filter.optJSONArray("selfSlotsExcluded"));
        Set<Integer> invalid = GpuExecMonitor.ids(global.optJSONArray("resetSlots"));
        invalid.addAll(GpuExecMonitor.ids(global.optJSONArray("slotDeltaWrappedSlots")));
        invalid.addAll(GpuExecMonitor.ids(global.optJSONArray("disappearedSlots")));
        invalid.addAll(currentExcluded);
        invalidatedDuringWindow.addAll(invalid); policy.invalidate(invalid);
        suppressLatest(invalid);
        notifyAll();
    }

    private void suppressLatest(Set<Integer> invalid) {
        if (latest == null || invalid.isEmpty()) return;
        try {
            JSONObject value = new JSONObject(latest);
            Set<Integer> own = GpuExecMonitor.ids(value.optJSONArray("selfSlotsExcluded"));
            own.addAll(currentExcluded);
            value.put("selfSlotsExcluded", new JSONArray(own));
            JSONArray rows = value.optJSONArray("slots");
            for (int i = 0; rows != null && i < rows.length(); i++) {
                JSONObject row = rows.getJSONObject(i);
                if (invalid.contains(row.optInt("slot", -1))) row.put("eligible", false).put("alert", false).put("stableForMs", 0);
            }
            aggregate(value); latest = value.toString();
        } catch (JSONException error) { latest = null; policy.reset(); }
    }

    synchronized JSONObject snapshot() throws JSONException {
        long age = SystemClock.uptimeMillis() - resultAtMs;
        if (closed || !enabled || latest == null || age < 0 || age > EXPIRY_MS) {
            return unavailable(closed ? "stopped" : !enabled ? unavailableReason : latest == null ? "sampling" : "stale");
        }
        return new JSONObject(latest).put("ageMs", age).put("sampledAtUptimeMs", resultAtMs);
    }

    private void run() {
        while (true) {
            int count, end;
            long jobEpoch;
            synchronized (this) {
                while (!closed && !enabled) {
                    try { wait(); } catch (InterruptedException ignored) { if (closed) return; }
                }
                if (closed) return;
                count = slotCount; end = endExclusive; jobEpoch = epoch;
                invalidatedDuringWindow.clear();
            }
            long began = SystemClock.uptimeMillis();
            try {
                JSONObject before = SelfGpuSlots.inspect(1, end);
                JSONObject measured = sampler.measureFrequency(count, WINDOW_MS);
                JSONObject after = SelfGpuSlots.inspect(1, end);
                long finishedAt = SystemClock.uptimeMillis();
                synchronized (this) {
                    if (closed) return;
                    if (!enabled || jobEpoch != epoch) continue;
                    long start = measured.optLong("startedMonotonicNs"), finish = measured.optLong("finishedMonotonicNs");
                    boolean verified = verified(before, end) && verified(after, end)
                            && before.optLong("queryFinishedMonotonicNs") <= start
                            && after.optLong("queryStartedMonotonicNs") >= finish;
                    if (!verified || !"complete".equals(measured.optString("status")) || !measured.optBoolean("fullWindow")) {
                        policy.reset(); previousOwn.clear();
                        latest = unavailable(verified ? measured.optString("reason", "sampling_failed") : "self_query_incomplete")
                                .put("selfQueryBefore", before).put("selfQueryAfter", after)
                                .put("samplingStatus", measured.optString("status"))
                                .put("samplingReason", measured.optString("reason")).toString();
                    } else {
                        Set<Integer> own = GpuExecMonitor.ids(before.optJSONArray("slots"));
                        own.addAll(GpuExecMonitor.ids(after.optJSONArray("slots")));
                        Set<Integer> excluded = new HashSet<>(own); excluded.addAll(previousOwn);
                        excluded.addAll(currentExcluded);
                        previousOwn = own;
                        JSONArray nativeRows = measured.optJSONArray("slots");
                        List<GpuSlotFrequency.Observation> observations = new ArrayList<>();
                        if (nativeRows == null || !measured.optBoolean("sparseSlots")
                                || measured.optInt("observedSlotCount") != end - 1
                                || measured.optInt("idleSlotCount", -1) + nativeRows.length() != end - 1) {
                            throw new JSONException("incomplete_frequency_layout");
                        }
                        int previousSlot = 0;
                        for (int i = 0; i < nativeRows.length(); i++) {
                            JSONObject row = nativeRows.getJSONObject(i);
                            int id = row.getInt("slot");
                            if (id <= previousSlot || id >= end) throw new JSONException("unexpected_frequency_slot");
                            previousSlot = id;
                            observations.add(new GpuSlotFrequency.Observation(id,
                                    row.optBoolean("valid") && !excluded.contains(id) && !invalidatedDuringWindow.contains(id), row.optDouble("observationsPerSecond", Double.NaN),
                                    row.getLong("submittedStart"), row.getLong("submittedEnd"),
                                    row.getLong("retiredStart"), row.getLong("retiredEnd")));
                        }
                        List<GpuSlotFrequency.Result> decisions = policy.update(start, finish, observations);
                        if (decisions.size() != observations.size()) {
                            latest = unavailable("discontinuous_window").toString();
                        } else {
                            JSONArray rows = new JSONArray();
                            for (int i = 0; i < decisions.size(); i++) {
                                GpuSlotFrequency.Result decision = decisions.get(i);
                                GpuSlotFrequency.Observation observation = decision.observation;
                                JSONObject row = nativeRows.getJSONObject(i);
                                // Native explicitly counts omitted quiet slots; absent rows clear their streaks.
                                rows.put(row.put("eligible", observation.eligible).put("stableForMs", decision.stableForMs).put("alert", decision.alert));
                            }
                            measured.put("slots", rows).put("selfSlotsExcluded", new JSONArray(excluded))
                                    .put("selfFilterComplete", true).put("observedSlotCount", end - 1)
                                    .put("thresholdFps", GpuSlotFrequency.THRESHOLD_FPS).put("sustainMs", 3000)
                                    .put("expiryMs", EXPIRY_MS).put("selfQueryBefore", before).put("selfQueryAfter", after);
                            aggregate(measured); latest = measured.toString();
                        }
                    }
                    resultAtMs = finishedAt;
                }
            } catch (Exception error) {
                synchronized (this) {
                    if (closed) return;
                    if (jobEpoch == epoch) {
                        policy.reset(); latest = null; unavailableReason = "sampling_failed";
                    }
                }
            }
            // Never call into the Service while holding this object's lock.
            if (changed != null) changed.run();
            long remaining = WINDOW_MS - (SystemClock.uptimeMillis() - began);
            if (remaining > 0) {
                synchronized (this) {
                    if (closed) return;
                    try { wait(remaining); } catch (InterruptedException ignored) { if (closed) return; }
                }
            }
        }
    }

    private static boolean verified(JSONObject query, int end) {
        return query.optBoolean("complete") && query.optInt("pid", -1) == android.os.Process.myPid()
                && query.optInt("uid", -1) == android.os.Process.myUid() && query.optInt("firstSlot") == 1
                && query.optInt("endExclusive") == end && query.optJSONArray("slots") != null;
    }
    private static JSONObject unavailable(String reason) throws JSONException {
        return new JSONObject().put("method", "gpu_slot_frequency").put("scope", "device_global_unattributed")
                .put("status", "unavailable").put("reason", reason).put("alert", false).put("peakFps", 0)
                .put("alertSlots", new JSONArray()).put("slots", new JSONArray()).put("ageMs", 0)
                .put("expiryMs", EXPIRY_MS).put("thresholdFps", GpuSlotFrequency.THRESHOLD_FPS).put("sustainMs", 3000);
    }
    private static void aggregate(JSONObject value) throws JSONException {
        JSONArray ids = new JSONArray(), rows = value.optJSONArray("slots"); double peak = 0;
        for (int i = 0; rows != null && i < rows.length(); i++) {
            JSONObject row = rows.getJSONObject(i);
            if (row.optBoolean("eligible") && row.optBoolean("alert")) {
                ids.put(row.getInt("slot")); peak = Math.max(peak, row.getDouble("observationsPerSecond"));
            }
        }
        value.put("alert", ids.length() > 0).put("alertSlots", ids).put("peakFps", peak);
    }
    @Override public synchronized void close() {
        closed = true; enabled = false; epoch++; latest = null; policy.reset(); notifyAll(); worker.interrupt();
    }
}
