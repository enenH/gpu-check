package com.gpucheck.app;

import org.json.JSONArray;
import org.json.JSONObject;
import java.util.Set;
import java.io.File;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

final class GpuExecChecks {
    static JSONObject models() throws Exception {
        try (GpuExecMonitor monitor = new GpuExecMonitor()) {
            JSONObject measured = new JSONObject().put("status", "complete").put("slotCount", 32)
                    .put("slots", new JSONArray().put(new JSONObject().put("slot", 5).put("eligible", true)));
            set(monitor, "latest", measured.toString()); set(monitor, "layoutCount", 32);
            set(monitor, "resultAtMs", android.os.SystemClock.uptimeMillis());
            JSONObject report = fixture();
            report.getJSONObject("globalGpu").put("resetSlots", new JSONArray().put(5));
            monitor.enrich(report);
            check(!row(report).getBoolean("eligible"), "reset result not suppressed");
            report = fixture(); monitor.enrich(report);
            check(!row(report).getBoolean("eligible"), "reset result revived on next snapshot");
            set(monitor, "latest", measured.toString());
            ((Set<?>) get(monitor, "invalidatedLatest")).clear();
            report = fixture(); report.getJSONObject("globalGpu").getJSONObject("highFrequency")
                    .put("selfSlotsExcluded", new JSONArray().put(5));
            monitor.enrich(report); check(!row(report).getBoolean("eligible"), "new self slot not suppressed");
            report = fixture(); monitor.enrich(report);
            check(!row(report).getBoolean("eligible"), "self result revived after ownership disappeared");
            set(monitor, "resultAtMs", android.os.SystemClock.uptimeMillis() - GpuExecMonitor.EXPIRY_MS - 1);
            report = fixture(); monitor.enrich(report);
            check(report.getJSONObject("globalGpu").getJSONObject("execMulti").getJSONArray("slots").length() == 0, "expired result retained");
            set(monitor, "latest", measured.toString()); set(monitor, "resultAtMs", android.os.SystemClock.uptimeMillis());
            report = fixture(); report.getJSONObject("globalGpu").getJSONObject("highFrequency").put("selfFilterComplete", false);
            monitor.enrich(report); check(get(monitor, "latest") == null, "failed self query retained old result");
            set(monitor, "latest", measured.toString()); set(monitor, "layoutCount", 31);
            report = fixture(); monitor.enrich(report); check(get(monitor, "latest") == null, "layout change retained old result");
            monitor.close(); report = fixture(); monitor.enrich(report);
            check(!report.getJSONObject("globalGpu").has("execMulti"), "closed monitor published result");
        }
        return new JSONObject().put("synthetic", true).put("checks", 8).put("result", "PASS");
    }
    private static JSONObject fixture() throws Exception {
        JSONArray deltas = new JSONArray(); for (int i = 0; i < 32; i++) deltas.put(0);
        return new JSONObject().put("globalGpu", new JSONObject().put("supported", true)
                .put("slotDeltas", deltas).put("lifecycleSlotEndExclusive", 25)
                .put("highFrequency", new JSONObject().put("selfFilterComplete", true).put("selfSlotsExcluded", new JSONArray())));
    }
    private static JSONObject row(JSONObject report) throws Exception {
        return report.getJSONObject("globalGpu").getJSONObject("execMulti").getJSONArray("slots").getJSONObject(0);
    }
    private static Object get(Object target, String name) throws Exception {
        Field field = target.getClass().getDeclaredField(name); field.setAccessible(true); return field.get(target);
    }
    private static void set(Object target, String name, Object value) throws Exception {
        Field field = target.getClass().getDeclaredField(name); field.setAccessible(true); field.set(target, value);
    }
    static void noWorkers() throws Exception {
        File[] tasks = new File("/proc/self/task").listFiles(); check(tasks != null, "cannot inspect own tasks");
        for (File task : tasks) {
            try {
                String name = new String(Files.readAllBytes(new File(task, "comm").toPath()), StandardCharsets.UTF_8).trim();
                check(!name.startsWith("gpu-exec-") && !name.startsWith("gpu-frequency-"),
                        "GPU sampling worker remained after stop: " + name);
            } catch (java.io.IOException ignored) { /* concurrent thread exit */ }
        }
    }
    static boolean real(JSONObject report) throws Exception {
        JSONObject global = report.getJSONObject("globalGpu");
        JSONObject exec = global.getJSONObject("execMulti");
        check("device_global_unattributed".equals(exec.optString("scope")), "GPU execution scope missing");
        if (!"complete".equals(exec.optString("status"))) return false;
        check(exec.getInt("uid") == android.os.Process.myUid() && exec.getInt("pid") == android.os.Process.myPid(),
                "GPU multi-slot sampler did not run in ordinary App");
        check(exec.getInt("workerCount") >= 1 && exec.getInt("workerCount") <= 16, "invalid worker count");
        check(exec.getInt("requestedSamples") == 30 && exec.getInt("windowMs") == 500, "wrong default sampling bounds");
        check(exec.getLong("ageMs") <= GpuExecMonitor.EXPIRY_MS, "stale result published");
        Set<Integer> before = GpuExecMonitor.ids(exec.getJSONObject("selfFilterBefore").getJSONArray("selfSlotsExcluded"));
        Set<Integer> after = GpuExecMonitor.ids(exec.getJSONObject("selfQueryAfter").optJSONArray("slots"));
        Set<Integer> current = GpuExecMonitor.ids(exec.getJSONArray("selfSlotsExcluded"));
        JSONArray selection = exec.getJSONArray("selection"), rows = exec.getJSONArray("slots");
        check(selection.length() <= 16 && selection.length() == rows.length(), "selection/result mismatch");
        for (int i = 0; i < selection.length(); i++) {
            int id = selection.getInt(i);
            check(id >= 1 && id < Math.min(256, exec.getInt("slotCount") - 7) && !before.contains(id), "self/reserved slot selected");
            JSONObject row = rows.getJSONObject(i);
            check(row.getInt("slot") == id, "slot order mismatch");
            GpuExecInstrumentation.validateStatistics(row);
            if (row.optBoolean("eligible")) check(row.optBoolean("valid") && exec.optBoolean("selfFilterAfterComplete")
                    && !after.contains(id) && !current.contains(id), "unverified or self slot displayed");
        }
        return true;
    }
    private static void check(boolean condition, String message) { if (!condition) throw new AssertionError(message); }
}
