package com.gpucheck.app;

import android.content.Context;
import android.os.SystemClock;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import java.util.LinkedHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/** Independent, bounded workers: an unavailable/hung OEM route cannot stall CPU or another route. */
final class OverlayMonitor implements AutoCloseable {
    private static final String[] ROUTES = {"oplus", "nubia", "zui"};
    private static final ExecutorService[] WORKERS = new ExecutorService[3];
    private static final AtomicBoolean[] BUSY = new AtomicBoolean[3];
    static {
        for (int i = 0; i < 3; i++) {
            final String name = ROUTES[i];
            WORKERS[i] = Executors.newSingleThreadExecutor(task -> {
                Thread thread = new Thread(task, "overlay-" + name); thread.setDaemon(true); return thread;
            });
            BUSY[i] = new AtomicBoolean();
        }
    }
    private final LayerProbe oplus, nubia;
    private final ZuiLayerProbe zui;
    private final String[] snapshots = new String[3];
    private final long[] nextAt = new long[3], startedAt = new long[3];
    private final boolean[] inFlight = new boolean[3];
    private volatile boolean closed;

    OverlayMonitor(Context context) {
        oplus = new LayerProbe(context.getPackageName()); nubia = new LayerProbe(context.getPackageName());
        zui = new ZuiLayerProbe(context);
    }

    synchronized JSONObject snapshot() throws JSONException {
        JSONArray routes = new JSONArray();
        LinkedHashMap<String, JSONObject> suspects = new LinkedHashMap<>();
        long now = SystemClock.elapsedRealtime();
        int available = 0;
        for (int i = 0; i < ROUTES.length; i++) {
            if (startedAt[i] == 0) startedAt[i] = now;
            if (!closed && !inFlight[i] && now >= nextAt[i] && BUSY[i].compareAndSet(false, true)) {
                inFlight[i] = true; startedAt[i] = now;
                final int index = i;
                WORKERS[i].execute(() -> collect(index));
            }
            JSONObject route = snapshots[i] == null ? LayerProbe.empty(ROUTES[i], closed ? "CANCELLED" : "CHECKING", "")
                    : new JSONObject(snapshots[i]);
            long maxAge = i == 2 ? 95000 : 15000;
            boolean waitingForPreviousSession = snapshots[i] == null && BUSY[i].get();
            boolean timedOut = (inFlight[i] || waitingForPreviousSession) && now - startedAt[i] > (i == 2 ? 40000 : 5000);
            boolean stale = route.optBoolean("available") && now - route.optLong("observedAtMs", 0) > maxAge;
            if (closed || timedOut || stale) route.put("previousStatus", route.optString("status"))
                    .put("status", closed ? "CANCELLED" : timedOut ? "TIMEOUT" : "STALE").put("available", false);
            route.put("inFlight", inFlight[i]).put("brandGateUsed", false);
            if (route.optBoolean("available")) {
                available++;
                JSONArray rows = route.optJSONArray("rows");
                for (int j = 0; rows != null && j < rows.length(); j++) {
                    JSONObject row = rows.getJSONObject(j);
                    if (row.optBoolean("suspicious")) suspects.putIfAbsent(row.optString("normalizedName"), row);
                }
            }
            routes.put(route);
        }
        return new JSONObject().put("schema", 1).put("routes", routes).put("availableRoutes", available)
                .put("suspected", !suspects.isEmpty()).put("suspiciousCount", suspects.size())
                .put("suspects", new JSONArray(suspects.values())).put("coverageLimited", true)
                .put("classification", "name_heuristic").put("brandGateUsed", false);
    }

    private void collect(int index) {
        JSONObject report;
        try {
            report = index == 0 ? oplus.oplus(() -> closed) : index == 1 ? nubia.nubia(() -> closed) : zui.collect(() -> closed);
        } catch (Exception | LinkageError error) {
            try { report = LayerProbe.empty(ROUTES[index], "FAILED", error.toString()).put("observedAtMs", SystemClock.elapsedRealtime()); }
            catch (JSONException impossible) { throw new IllegalStateException(impossible); }
        } finally { BUSY[index].set(false); }
        synchronized (this) {
            inFlight[index] = false;
            if (closed) return;
            snapshots[index] = report.toString();
            long delay = report.has("retryAfterMs") ? report.optLong("retryAfterMs", 60000)
                    : index == 2 ? 60000 : report.optBoolean("available") ? 2000 : 30000;
            nextAt[index] = SystemClock.elapsedRealtime() + delay;
        }
    }

    @Override public synchronized void close() {
        closed = true;
        java.util.Arrays.fill(snapshots, null);
    }
}
