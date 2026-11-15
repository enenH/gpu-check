package com.gpucheck.app;

import android.graphics.Color;
import android.os.SystemClock;
import android.view.View;
import android.widget.TextView;
import org.json.JSONArray;
import org.json.JSONObject;
import java.lang.reflect.Field;
import java.util.HashSet;
import java.util.Set;

/** Checks real published evidence and real Views; does not supply detector input. */
final class GpuFrequencyChecks {
    private static final long WATCHDOG_GRACE_MS = 350;

    static JSONObject models() throws Exception {
        try (GpuExecSampler sampler = new GpuExecSampler()) {
            GpuSlotFrequencyMonitor monitor = new GpuSlotFrequencyMonitor(sampler, null);
            // Keep its worker outside the lock throughout these explicitly synthetic snapshots.
            synchronized (monitor) {
                try {
                    seed(monitor);
                    require(monitor.snapshot().getBoolean("alert"), "Fresh coordinator result missing");
                    set(monitor, "resultAtMs", SystemClock.uptimeMillis() - GpuSlotFrequencyMonitor.EXPIRY_MS - 1);
                    require(!monitor.snapshot().getBoolean("alert"), "Coordinator retained an expired warning");
                    seed(monitor);
                    set(monitor, "resultAtMs", SystemClock.uptimeMillis() + 5000);
                    require(!monitor.snapshot().getBoolean("alert"), "Coordinator accepted a future observation");
                    seed(monitor);
                    monitor.configure(fixture(32).put("resetSlots", new JSONArray().put(5)));
                    require(!monitor.snapshot().getBoolean("alert"), "Counter reset retained warning");
                    monitor.configure(fixture(32));
                    require(!monitor.snapshot().getBoolean("alert"), "Reset warning revived without a new measurement");
                    seed(monitor);
                    JSONObject own = fixture(32);
                    own.getJSONObject("highFrequency").put("selfSlotsExcluded", new JSONArray().put(5));
                    monitor.configure(own);
                    require(!monitor.snapshot().getBoolean("alert"), "New self-owned slot retained warning");
                    seed(monitor);
                    JSONObject unsupported = fixture(32);
                    unsupported.getJSONObject("highFrequency").put("selfFilterComplete", false);
                    monitor.configure(unsupported);
                    require(!monitor.snapshot().getBoolean("alert"), "Incomplete self filter retained warning");
                    seed(monitor);
                    monitor.configure(fixture(33));
                    require(!monitor.snapshot().getBoolean("alert"), "Changed slot layout retained warning");
                    seed(monitor);
                    set(monitor, "latest", "{");
                    monitor.configure(fixture(32).put("resetSlots", new JSONArray().put(5)));
                    require(!monitor.snapshot().getBoolean("alert"), "Malformed coordinator data retained warning");
                    monitor.close();
                    monitor.configure(fixture(32));
                    require("stopped".equals(monitor.snapshot().getString("reason")), "Closed coordinator restarted");
                } finally { monitor.close(); }
            }
        }
        return new JSONObject().put("synthetic", true).put("checks", 10).put("result", "PASS");
    }

    private static JSONObject fixture(int count) throws Exception {
        JSONArray deltas = new JSONArray();
        for (int i = 0; i < count; i++) deltas.put(0);
        return new JSONObject().put("supported", true).put("slotDeltas", deltas).put("lifecycleSlotEndExclusive", count - 7)
                .put("highFrequency", new JSONObject().put("selfFilterComplete", true).put("selfSlotsExcluded", new JSONArray()));
    }
    private static void seed(GpuSlotFrequencyMonitor monitor) throws Exception {
        set(monitor, "enabled", true); set(monitor, "slotCount", 32); set(monitor, "endExclusive", 25);
        set(monitor, "resultAtMs", SystemClock.uptimeMillis());
        set(monitor, "latest", new JSONObject().put("status", "complete").put("alert", true).put("peakFps", 120)
                .put("slots", new JSONArray().put(new JSONObject().put("slot", 5).put("eligible", true)
                        .put("alert", true).put("stableForMs", 3000).put("observationsPerSecond", 120))).toString());
    }
    private static void set(Object target, String name, Object value) throws Exception {
        Field field = target.getClass().getDeclaredField(name); field.setAccessible(true); field.set(target, value);
    }

    static boolean real(JSONObject report) throws Exception {
        JSONObject global = report.getJSONObject("globalGpu");
        JSONObject frequency = global.getJSONObject("slotFrequency");
        require("device_global_unattributed".equals(frequency.getString("scope")), "GPU frequency scope missing");
        require(frequency.getDouble("thresholdFps") == 90 && frequency.getLong("sustainMs") == 3000,
                "GPU frequency threshold/duration differs from requested rule");
        boolean complete = "complete".equals(frequency.optString("status"));
        boolean alert = frequency.optBoolean("alert");
        if (!complete) {
            require(!alert, "Unavailable frequency result retained alert");
            return false;
        }
        long age = frequency.getLong("ageMs"), expiry = frequency.getLong("expiryMs");
        require(age >= 0 && expiry > 0, "Frequency freshness metadata invalid");
        require(frequency.getInt("pid") == android.os.Process.myPid() && frequency.getInt("uid") == android.os.Process.myUid(),
                "Frequency sampler did not retain the ordinary App process/UID");
        require(frequency.getBoolean("fullWindow") && frequency.getBoolean("selfFilterComplete"),
                "Frequency result lacks full-window and verified self-filter evidence");
        if (age > expiry) require(!alert, "Expired frequency result retained alert");
        JSONObject filter = global.optJSONObject("highFrequency");
        Set<Integer> self = ids(filter == null ? null : filter.optJSONArray("selfSlotsExcluded"));
        Set<Integer> excluded = ids(frequency.getJSONArray("selfSlotsExcluded"));
        JSONObject before = frequency.getJSONObject("selfQueryBefore"), after = frequency.getJSONObject("selfQueryAfter");
        require(before.optBoolean("complete") && after.optBoolean("complete"), "Incomplete frequency owner queries");
        Set<Integer> measuredSelf = ids(before.getJSONArray("slots"));
        measuredSelf.addAll(ids(after.getJSONArray("slots")));
        require(excluded.containsAll(measuredSelf) && excluded.containsAll(self), "Self exclusion omitted measured/current owned slots");
        self.addAll(excluded);
        Set<Integer> actualAlerts = new HashSet<>(), observed = new HashSet<>();
        JSONArray rows = frequency.getJSONArray("slots");
        int slotEnd = frequency.getInt("slotCount") - 7;
        require(slotEnd > 1, "Frequency slot layout invalid");
        double peak = 0;
        for (int i = 0; i < rows.length(); i++) {
            JSONObject row = rows.getJSONObject(i);
            int slot = row.getInt("slot");
            require(slot > 0 && slot < slotEnd && observed.add(slot), "Reserved/duplicate frequency slot");
            double rate = row.optDouble("observationsPerSecond", Double.NaN);
            require(Double.isFinite(rate) && rate >= 0, "Invalid observed frequency");
            long stable = row.getLong("stableForMs");
            require(stable >= 0, "Negative stable duration");
            boolean eligible = row.optBoolean("eligible");
            if (eligible) require(row.optBoolean("valid") && !self.contains(slot), "Own or invalid frequency slot is eligible");
            if (row.optBoolean("alert")) {
                require(eligible && rate > 90 && stable >= 3000, "Frequency warning fired without sustained external evidence");
                actualAlerts.add(slot);
                peak = Math.max(peak, rate);
            }
        }
        require(alert == !actualAlerts.isEmpty(), "Aggregate frequency warning differs from slot warnings");
        require(ids(frequency.getJSONArray("alertSlots")).equals(actualAlerts), "Frequency alert slot IDs differ from rows");
        if (alert) {
            require(filter != null && filter.optBoolean("selfFilterComplete"), "Warning without a complete current self filter");
            require(Math.abs(frequency.getDouble("peakFps") - peak) < 0.01, "Displayed peak frequency differs from warning slots");
        }
        return true;
    }

    static JSONObject ui(JSONObject shown, TextView warning, long receivedAtMs, boolean active) throws Exception {
        JSONObject global = shown == null ? null : shown.optJSONObject("globalGpu");
        JSONObject frequency = global == null ? null : global.optJSONObject("slotFrequency");
        long elapsedNow = SystemClock.elapsedRealtime(), uptimeNow = SystemClock.uptimeMillis();
        long age = Long.MAX_VALUE, expiry = 0;
        boolean valid = false;
        if (frequency != null) {
            long reportedAge = frequency.optLong("ageMs", -1);
            expiry = frequency.optLong("expiryMs", 1500);
            long sampled = frequency.optLong("sampledAtUptimeMs", -1);
            long sinceReceipt = elapsedNow - receivedAtMs;
            if (reportedAge >= 0 && sinceReceipt >= 0 && reportedAge <= Long.MAX_VALUE - sinceReceipt) {
                age = reportedAge + sinceReceipt;
                if (sampled >= 0) {
                    if (sampled > uptimeNow) age = Long.MAX_VALUE;
                    else age = Math.max(age, uptimeNow - sampled);
                }
            }
            double peak = frequency.optDouble("peakFps", Double.NaN);
            valid = active && "complete".equals(frequency.optString("status")) && frequency.optBoolean("alert")
                    && Double.isFinite(peak) && peak > 0 && expiry > 0;
        }
        boolean expected = valid && age <= expiry;
        boolean visible = warning.getVisibility() == View.VISIBLE;
        String text = warning.getText().toString();
        if (expected) require(visible, "Fresh GPU frequency warning is not visible");
        if (visible) {
            require(valid && age <= expiry + WATCHDOG_GRACE_MS, "GPU frequency warning retained after unavailable/stale/stopped state");
            require(warning.getCurrentTextColor() == Color.rgb(255, 119, 125), "GPU frequency warning is not red");
            require(text.contains("疑似后台悬浮窗") && text.contains("FPS") && text.contains("约"),
                    "GPU frequency warning is missing its estimate text");
            String rate = String.format(java.util.Locale.getDefault(), "%.1f", frequency.getDouble("peakFps"));
            require(text.contains(rate), "GPU frequency warning does not show the current peak FPS");
        } else require(text.isEmpty(), "Hidden GPU frequency warning retained old text");
        return new JSONObject().put("visible", visible).put("text", text).put("color", warning.getCurrentTextColor())
                .put("active", active).put("fresh", expected).put("effectiveAgeMs", age)
                .put("expiryMs", expiry).put("receivedAtElapsedMs", receivedAtMs)
                .put("capturedAtUptimeMs", uptimeNow).put("capturedAtEpochMs", System.currentTimeMillis())
                .put("result", frequency == null ? JSONObject.NULL : new JSONObject(frequency.toString()));
    }

    private static Set<Integer> ids(JSONArray array) {
        Set<Integer> result = new HashSet<>();
        for (int i = 0; array != null && i < array.length(); i++) result.add(array.optInt(i, -1));
        return result;
    }
    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
