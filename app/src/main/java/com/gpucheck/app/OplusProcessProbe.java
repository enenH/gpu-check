package com.gpucheck.app;

import android.content.Context;
import android.os.SystemClock;
import org.json.JSONArray;
import org.json.JSONObject;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;
import java.util.function.BooleanSupplier;

/** The recovered OplusActivityManager CPU-statistics route, under the caller's ordinary UID. */
final class OplusProcessProbe {
    static final String ROUTE = "oplus_cpu";
    static final int MAX_RECORD_CHARS = 4096;
    static final long SAMPLE_DELAY_MS = 700;
    private final Context context;
    private final Tracker suppliedTracker;
    private final long sampleDelayMs;

    interface Tracker {
        Object update(long lastUpdateTime) throws Exception;
        Object stats() throws Exception;
    }

    OplusProcessProbe(Context context) {
        this.context = context.getApplicationContext();
        suppliedTracker = null;
        sampleDelayMs = SAMPLE_DELAY_MS;
    }

    /** Only used by the separate test APK; no synthetic data is selected by production code. */
    OplusProcessProbe(Tracker tracker, long delayMs) {
        context = null;
        suppliedTracker = tracker;
        sampleDelayMs = Math.max(0, Math.min(SAMPLE_DELAY_MS, delayMs));
    }

    JSONObject collect(int[] candidates, BooleanSupplier cancelled) throws Exception {
        long started = SystemClock.elapsedRealtime();
        JSONObject report = OemProcessSupport.empty(ROUTE, "CHECKING", "")
                .put("method", "OplusActivityManager.updateCpuTracker/getCpuWorkingStats")
                .put("transport", "public_framework_reflection")
                .put("coverageScope", "returned_cpu_working_stats")
                .put("coverageLimited", true).put("uidProvided", false)
                .put("candidateCount", candidates == null ? 0 : candidates.length)
                .put("candidateFilterUsed", false).put("sampleDelayMs", sampleDelayMs)
                .put("updateCalls", 0).put("statsCalls", 0);
        try {
            checkCancelled(cancelled);
            Tracker tracker = suppliedTracker == null ? frameworkTracker() : suppliedTracker;
            checkCancelled(cancelled);
            // r.i in the original DEX uses the SAME initial uptime for both updates.
            long lastUpdateTime = SystemClock.uptimeMillis();
            report.put("lastUpdateTimeMs", lastUpdateTime);
            report.put("updateCalls", 1);
            Object first = tracker.update(lastUpdateTime);
            recordUpdate(report, "firstUpdateValue", first);
            long until = SystemClock.uptimeMillis() + sampleDelayMs;
            while (SystemClock.uptimeMillis() < until) {
                checkCancelled(cancelled);
                Thread.sleep(Math.min(25, Math.max(1, until - SystemClock.uptimeMillis())));
            }
            checkCancelled(cancelled);
            report.put("updateCalls", 2);
            Object second = tracker.update(lastUpdateTime);
            recordUpdate(report, "secondUpdateValue", second);
            checkCancelled(cancelled);
            report.put("statsCalls", 1);
            Object value = tracker.stats();
            checkCancelled(cancelled);
            if (!(value instanceof List<?>)) throw new IllegalArgumentException("CPU statistics reply is not a List");
            parseRecords((List<?>) value, report, cancelled);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            report.put("status", "CANCELLED").put("available", false).put("rows", new JSONArray());
        } catch (Exception | LinkageError error) {
            Throwable cause = OemProcessSupport.rootCause(error);
            report.put("status", OemProcessSupport.status(cause)).put("available", false)
                    .put("detail", cause.toString()).put("rows", new JSONArray());
        }
        return report.put("observedAtMs", SystemClock.elapsedRealtime())
                .put("durationMs", SystemClock.elapsedRealtime() - started);
    }

    private Tracker frameworkTracker() throws Exception {
        Class<?> type = OemProcessSupport.loadClass(context, "android.app.OplusActivityManager",
                "/system/framework/oplus-framework.jar");
        Method instanceMethod = type.getMethod("getInstance");
        Method update = type.getMethod("updateCpuTracker", long.class);
        Method stats = type.getMethod("getCpuWorkingStats");
        if (!Modifier.isStatic(instanceMethod.getModifiers()) || !List.class.isAssignableFrom(stats.getReturnType()))
            throw new UnsupportedOperationException("Unsupported Oplus CPU API signature");
        Object instance = instanceMethod.invoke(null);
        if (instance == null || !type.isInstance(instance))
            throw new UnsupportedOperationException("OplusActivityManager instance unavailable");
        // Do not access hidden private singleton fields or guess firmware-specific Binder codes.
        return new Tracker() {
            @Override public Object update(long lastUpdateTime) throws Exception { return update.invoke(instance, lastUpdateTime); }
            @Override public Object stats() throws Exception { return stats.invoke(instance); }
        };
    }

    private static void recordUpdate(JSONObject report, String key, Object value) throws Exception {
        // The wrapper returns a float on the verified firmware; it is not per-PID CPU usage.
        if (value instanceof Number && Double.isFinite(((Number) value).doubleValue())) report.put(key, value);
        else if (value != null) throw new IllegalArgumentException("Unsupported updateCpuTracker return value");
    }

    static void parseRecords(List<?> records, JSONObject report, BooleanSupplier cancelled) throws Exception {
        LinkedHashMap<Integer, JSONObject> rows = new LinkedHashMap<>();
        Set<Integer> conflicting = new HashSet<>();
        int rejected = 0, duplicate = 0, processed = 0;
        int returned = records.size();
        int limit = Math.min(returned, OemProcessSupport.MAX_ROWS);
        long chars = 0;
        boolean byteBudgetHit = false;
        for (int i = 0; i < limit; i++) {
            checkCancelled(cancelled);
            Object value = records.get(i);
            processed++;
            if (!(value instanceof String)) { rejected++; continue; }
            String raw = (String) value;
            chars += raw.length();
            if (chars > OemProcessSupport.MAX_REPLY_BYTES / 2) { byteBudgetHit = true; break; }
            JSONObject row = parseRecord(raw);
            if (row == null) { rejected++; continue; }
            int pid = row.getInt("pid");
            if (conflicting.contains(pid)) { rejected++; continue; }
            JSONObject previous = rows.get(pid);
            if (previous != null) {
                duplicate++;
                if (!previous.getString("name").equals(row.getString("name"))) {
                    rows.remove(pid);
                    conflicting.add(pid);
                }
                continue;
            }
            rows.put(pid, row);
        }
        boolean partial = returned > limit || byteBudgetHit || rejected > 0 || !conflicting.isEmpty();
        String status = returned == 0 ? "EMPTY" : rows.isEmpty() ? "INCOMPATIBLE" : partial ? "PARTIAL" : "OK";
        report.put("rows", new JSONArray(rows.values())).put("status", status)
                .put("available", returned == 0 || !rows.isEmpty()).put("returnedCount", returned)
                .put("parsedCount", rows.size()).put("processedCount", processed)
                .put("rejectedCount", rejected).put("duplicateCount", duplicate)
                .put("conflictingPidCount", conflicting.size())
                .put("truncated", returned > limit || byteBudgetHit)
                .put("rowLimit", OemProcessSupport.MAX_ROWS).put("byteBudgetHit", byteBudgetHit)
                .put("replyFormat", "name=pid=opaque_statistics")
                .put("detail", returned == 0 ? "Framework returned no CPU working records; this does not prove complete process coverage"
                        : rows.isEmpty() ? "No valid name=PID= statistics records" : "");
    }

    /** r.z in the recovered DEX finds the first ASCII '=positivePID=' delimiter. */
    static JSONObject parseRecord(String raw) throws Exception {
        if (raw == null || raw.isEmpty() || raw.length() > MAX_RECORD_CHARS) return null;
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (Character.isISOControl(c) && c != '\t') return null;
        }
        for (int equals = 0; equals < raw.length() - 2; equals++) {
            if (raw.charAt(equals) != '=') continue;
            int end = equals + 1;
            long pid = 0;
            while (end < raw.length() && raw.charAt(end) >= '0' && raw.charAt(end) <= '9') {
                pid = pid * 10 + raw.charAt(end) - '0';
                if (pid > Integer.MAX_VALUE) return null;
                end++;
            }
            if (end == equals + 1 || end >= raw.length() || raw.charAt(end) != '=' || pid <= 0) continue;
            String name = raw.substring(0, equals).trim();
            if (name.isEmpty() || name.length() > 1024) return null;
            // Retain the opaque values as evidence; neither UID nor percent is inferred from them.
            return OemProcessSupport.row((int) pid, -1, name, -1, ROUTE)
                    .put("stats", new JSONObject().put("raw", raw))
                    .put("uidSource", "not_provided_by_cpu_working_stats");
        }
        return null;
    }

    private static void checkCancelled(BooleanSupplier cancelled) throws InterruptedException {
        if (Thread.currentThread().isInterrupted() || cancelled.getAsBoolean()) throw new InterruptedException("Cancelled CPU query");
    }
}
