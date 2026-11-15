package com.gpucheck.app;

import android.content.Context;
import android.os.SystemClock;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;

/** Five bounded workers: slow or unsupported OEM services never block the native sampling loop. */
final class OemProcessMonitor implements AutoCloseable {
    static final String[] ROUTE_NAMES = {"miui_cpu", "miui_memory", "oplus_cpu", "mindsync", "vivo_rms"};
    static final int CANDIDATE_BATCH = 256;
    static final long CALL_TIMEOUT_MS = 5000;
    private static final int HANDLE_BUDGET = 256;
    private static final ExecutorService[] WORKERS = new ExecutorService[ROUTE_NAMES.length];
    private static final AtomicBoolean[] BUSY = new AtomicBoolean[ROUTE_NAMES.length];
    static {
        for (int i = 0; i < ROUTE_NAMES.length; i++) {
            final String name = ROUTE_NAMES[i];
            WORKERS[i] = Executors.newSingleThreadExecutor(task -> {
                Thread thread = new Thread(task, "oem-process-" + name); thread.setDaemon(true); return thread;
            });
            BUSY[i] = new AtomicBoolean();
        }
    }
    interface Route { JSONObject collect(int[] candidates, BooleanSupplier cancelled) throws Exception; }
    interface Clock { long now(); }
    private final Route[] routes;
    private final Clock clock;
    private final Result[] results = new Result[ROUTE_NAMES.length];
    private final long[] nextAt = new long[ROUTE_NAMES.length], startedAt = new long[ROUTE_NAMES.length];
    private final int[] candidateCursor = new int[ROUTE_NAMES.length];
    private final boolean[] inFlight = new boolean[ROUTE_NAMES.length], attempted = new boolean[ROUTE_NAMES.length];
    private final Map<Integer, Long> suppressedUntil = new HashMap<>();
    private Map<Integer, String> currentIdentities = new HashMap<>();
    private Set<Integer> previousNativePids = new HashSet<>();
    private int[] candidatePids = new int[0];
    private volatile boolean closed;

    OemProcessMonitor(Context context) {
        this(defaultRoutes(context), SystemClock::elapsedRealtime);
    }

    /** Test seam only changes route transport and time; production shares the same worker limits. */
    OemProcessMonitor(Route[] routes, Clock clock) {
        if (routes == null || routes.length != ROUTE_NAMES.length || clock == null)
            throw new IllegalArgumentException("Exactly five OEM routes and a clock are required");
        this.routes = routes.clone(); this.clock = clock;
        for (Route route : this.routes) if (route == null) throw new IllegalArgumentException("Missing OEM route");
    }

    private static Route[] defaultRoutes(Context context) {
        MiuiProcessProbe miui = new MiuiProcessProbe(context);
        OplusProcessProbe oplus = new OplusProcessProbe(context);
        RedVivoProcessProbe redVivo = new RedVivoProcessProbe(context);
        return new Route[]{miui::cpu, miui::memory, oplus::collect, redVivo::mindsync, redVivo::vivo};
    }

    synchronized JSONObject snapshot() throws JSONException {
        long now = clock.now();
        JSONArray reports = new JSONArray();
        int available = 0;
        for (int i = 0; i < ROUTE_NAMES.length; i++) {
            if (!attempted[i]) { attempted[i] = true; startedAt[i] = now; }
            if (!closed && !inFlight[i] && now >= nextAt[i] && BUSY[i].compareAndSet(false, true)) {
                inFlight[i] = true; startedAt[i] = now;
                final int index = i;
                final int candidateCount = candidatePids.length;
                final int[] batch = nextBatch(i);
                final Map<Integer, String> identities = new HashMap<>(currentIdentities);
                final long started = now;
                WORKERS[i].execute(() -> collect(index, batch, candidateCount, identities, started));
            }
            Result cached = results[i];
            JSONObject report = cached == null ? OemProcessSupport.empty(ROUTE_NAMES[i], closed ? "CANCELLED" : "CHECKING", "")
                    : new JSONObject(cached.json);
            boolean waiting = cached == null && !inFlight[i] && BUSY[i].get();
            boolean timedOut = (inFlight[i] || waiting) && now - startedAt[i] > CALL_TIMEOUT_MS;
            long observed = report.optLong("observedAtMs", -1);
            boolean stale = cached != null && Boolean.TRUE.equals(report.opt("available"))
                    && (observed <= 0 || observed > now || now - observed > OemProcessMerger.MAX_AGE_MS);
            if (closed || timedOut || stale) {
                report.put("previousStatus", report.optString("status"))
                        .put("status", closed ? "CANCELLED" : timedOut ? "TIMEOUT" : "STALE")
                        .put("available", false).put("rows", new JSONArray());
                if (cached != null && (closed || stale)) cached.releaseHandles();
            } else if (cached != null) {
                JSONArray rows = report.optJSONArray("rows");
                for (int j = 0; rows != null && j < rows.length(); j++) {
                    JSONObject row = rows.optJSONObject(j);
                    if (row == null) continue;
                    Integer fd = cached.handles.get(row.optInt("pid", -1));
                    row.put("pidfdAlive", fd != null && OemProcessSupport.pidfdAlive(fd));
                }
            }
            report.put("inFlight", inFlight[i]).put("waitingForPreviousSession", waiting)
                    .put("brandGateUsed", false).put("timeoutMs", CALL_TIMEOUT_MS)
                    .put("maxAgeMs", OemProcessMerger.MAX_AGE_MS).put("workerLimit", 1);
            if (Boolean.TRUE.equals(report.opt("available"))) available++;
            reports.put(report);
        }
        return new JSONObject().put("schema", 1).put("routes", reports).put("availableRoutes", available)
                .put("coverageLimited", true).put("brandGateUsed", false).put("workerLimit", ROUTE_NAMES.length)
                .put("candidateBatchLimit", CANDIDATE_BATCH).put("effectiveUidPromoted", false);
    }

    synchronized void enrich(JSONObject raw) throws JSONException {
        if (closed) {
            OemProcessMerger.merge(raw, new JSONArray(), new HashSet<>(), clock.now());
            return;
        }
        long now = clock.now();
        if (!raw.has("nativeReturnedCandidates")) {
            JSONArray nativeRows = raw.optJSONArray("processes");
            int nativeCount = 0;
            for (int i = 0; nativeRows != null && i < nativeRows.length(); i++) {
                JSONObject row = nativeRows.optJSONObject(i);
                if (row != null && !row.optBoolean("oemOnly")) nativeCount++;
            }
            raw.put("nativeReturnedCandidates", nativeCount);
        }
        Map<Integer, String> identities = new HashMap<>();
        Set<Integer> nativePids = new LinkedHashSet<>();
        Set<Integer> duplicateIdentities = new HashSet<>();
        Set<Integer> excludedCandidates = new HashSet<>();
        JSONArray nativeExcluded = raw.optJSONArray("cpuExcludedPidTids");
        for (int i = 0; nativeExcluded != null && i < nativeExcluded.length(); i++)
            excludedCandidates.add(nativeExcluded.optInt(i, -1));
        for (String key : new String[]{"processes", "cpuSamples"}) {
            JSONArray rows = raw.optJSONArray(key);
            for (int i = 0; rows != null && i < rows.length(); i++) {
                JSONObject row = rows.optJSONObject(i);
                if (row == null || row.optBoolean("oemOnly")) continue;
                int pid = row.optInt("pid", -1);
                if (pid <= 0) continue;
                nativePids.add(pid);
                if (KernelThreadPolicy.KERNEL.equals(KernelThreadPolicy.classify(row, raw))
                        || MonitoredProcessFilter.isSelf(pid, row.optInt("uid", -1), raw.optInt("collectorPid", -1),
                        android.os.Process.myPid(), android.os.Process.myUid())) excludedCandidates.add(pid);
                String identity = row.optString("identityToken", "");
                if (!Boolean.TRUE.equals(row.opt("identityVerified")) || identity.isEmpty()) continue;
                String old = identities.put(pid, identity);
                if (old != null && !old.equals(identity)) duplicateIdentities.add(pid);
            }
        }
        for (int pid : duplicateIdentities) identities.remove(pid);
        for (int pid : previousNativePids) if (!nativePids.contains(pid)) suppressedUntil.put(pid, now + OemProcessMerger.MAX_AGE_MS);
        JSONArray events = raw.optJSONArray("processEvents");
        for (int i = 0; events != null && i < events.length(); i++) {
            JSONObject event = events.optJSONObject(i);
            if (event != null && "EXITED".equals(event.optString("type")))
                suppressedUntil.put(event.optInt("pid", -1), now + OemProcessMerger.MAX_AGE_MS);
        }
        suppressedUntil.entrySet().removeIf(entry -> entry.getValue() < now);
        previousNativePids = nativePids;
        currentIdentities = identities;
        LinkedHashSet<Integer> candidates = new LinkedHashSet<>(nativePids);
        candidates.removeAll(excludedCandidates);
        for (Result result : results) {
            if (result == null) continue;
            JSONObject report = new JSONObject(result.json);
            long observed = report.optLong("observedAtMs", -1);
            if (!report.optBoolean("available") || observed <= 0 || observed > now || now - observed > OemProcessMerger.MAX_AGE_MS) continue;
            JSONArray rows = report.optJSONArray("rows");
            for (int i = 0; rows != null && i < rows.length(); i++) {
                JSONObject row = rows.optJSONObject(i);
                if (row != null && row.optInt("pid", -1) > 0 && !suppressedUntil.containsKey(row.optInt("pid"))
                        && !excludedCandidates.contains(row.optInt("pid")))
                    candidates.add(row.optInt("pid"));
            }
        }
        candidatePids = new int[candidates.size()];
        int cursor = 0; for (int pid : candidates) candidatePids[cursor++] = pid;
        Arrays.sort(candidatePids);
        JSONObject snapshot = snapshot();
        OemProcessMerger.merge(raw, snapshot.getJSONArray("routes"), suppressedUntil.keySet(), now);
        JSONObject aggregate = raw.getJSONObject("oemProcesses");
        aggregate.put("workerLimit", ROUTE_NAMES.length).put("candidateCount", candidatePids.length)
                .put("candidateBatchLimit", CANDIDATE_BATCH).put("suppressedPidCount", suppressedUntil.size());
    }

    private int[] nextBatch(int route) {
        int size = Math.min(CANDIDATE_BATCH, candidatePids.length);
        int[] result = new int[size];
        if (size == 0) return result;
        int start = Math.floorMod(candidateCursor[route], candidatePids.length);
        for (int i = 0; i < size; i++) result[i] = candidatePids[(start + i) % candidatePids.length];
        candidateCursor[route] = (start + size) % candidatePids.length;
        return result;
    }

    private void collect(int index, int[] candidates, int candidateCount, Map<Integer, String> identities, long started) {
        try { collectResult(index, candidates, candidateCount, identities, started); }
        finally {
            synchronized (this) { inFlight[index] = false; }
            BUSY[index].set(false);
        }
    }

    private void collectResult(int index, int[] candidates, int candidateCount, Map<Integer, String> identities, long started) {
        Map<Integer, Integer> handles = new HashMap<>();
        JSONObject report;
        try {
            report = routes[index].collect(candidates, () -> closed || clock.now() - started > CALL_TIMEOUT_MS);
            if (report == null) throw new IllegalArgumentException("OEM route returned no report");
            long completed = clock.now();
            if (closed || completed < started || completed - started > CALL_TIMEOUT_MS) {
                report = OemProcessSupport.empty(ROUTE_NAMES[index], closed ? "CANCELLED" : "TIMEOUT", "Route deadline exceeded");
            }
            report.put("route", ROUTE_NAMES[index]).put("observedAtMs", completed)
                    .put("startedAtMs", started).put("durationMs", Math.max(0, completed - started))
                    .put("candidateCount", candidateCount).put("candidateBatchCount", candidates.length)
                    .put("candidateCoverageLimited", candidates.length < candidateCount).put("brandGateUsed", false);
            JSONArray rows = report.optJSONArray("rows"), bounded = new JSONArray();
            int omissions = 0;
            if (Boolean.TRUE.equals(report.opt("available"))) {
                for (int i = 0; rows != null && i < Math.min(rows.length(), OemProcessSupport.MAX_ROWS); i++) {
                    JSONObject row = rows.optJSONObject(i);
                    if (row == null || row.optInt("pid", -1) <= 0) continue;
                    int pid = row.optInt("pid");
                    JSONObject copy = new JSONObject(row.toString());
                    String binding = identities.getOrDefault(pid, "");
                    copy.put("bindingIdentityToken", binding).put("pidfdAlive", false).put("observedAtMs", completed);
                    if (binding.isEmpty() && !closed && !handles.containsKey(pid)) {
                        if (handles.size() < HANDLE_BUDGET) {
                            int fd = OemProcessSupport.openPidfd(pid);
                            if (fd >= 0) handles.put(pid, fd);
                        } else omissions++;
                    }
                    bounded.put(copy);
                }
            }
            report.put("rows", bounded).put("unverifiedHandleLimit", HANDLE_BUDGET)
                    .put("unverifiedHandleOmissions", omissions).put("rowsTruncated", rows != null && rows.length() > OemProcessSupport.MAX_ROWS);
        } catch (Exception | LinkageError error) {
            try { report = OemProcessSupport.empty(ROUTE_NAMES[index], OemProcessSupport.status(error), error.toString())
                    .put("observedAtMs", clock.now()).put("startedAtMs", started); }
            catch (JSONException impossible) { throw new IllegalStateException(impossible); }
        }
        synchronized (this) {
            if (closed || !Boolean.TRUE.equals(report.opt("available"))) {
                for (int fd : handles.values()) OemProcessSupport.closePidfd(fd);
                handles.clear();
            }
            if (closed) return;
            if ((index == 1 || index == 4) && Boolean.TRUE.equals(report.opt("available")) && results[index] != null)
                retainUnqueriedRows(report, results[index], candidates, handles, clock.now());
            if (results[index] != null) results[index].releaseHandles();
            results[index] = new Result(report.toString(), handles);
            nextAt[index] = clock.now() + ("NO_CANDIDATES".equals(report.optString("status")) ? 1000
                    : Boolean.TRUE.equals(report.opt("available")) ? 2000 : 30000);
        }
    }

    /** Targeted services rotate PID batches. A skipped PID retains only its original timestamp and binding. */
    private static void retainUnqueriedRows(JSONObject report, Result previous, int[] requested,
                                           Map<Integer, Integer> handles, long now) {
        try {
            JSONObject old = new JSONObject(previous.json);
            if (!Boolean.TRUE.equals(old.opt("available"))) return;
            Set<Integer> queried = new HashSet<>();
            JSONArray explicit = report.optJSONArray("queriedPids");
            if (explicit != null) {
                for (int i = 0; i < explicit.length(); i++) queried.add(explicit.optInt(i, -1));
            } else for (int pid : requested) queried.add(pid);
            JSONArray rows = report.getJSONArray("rows");
            for (int i = 0; i < rows.length(); i++) queried.add(rows.getJSONObject(i).optInt("pid", -1));
            JSONArray oldRows = old.optJSONArray("rows");
            int retained = 0;
            for (int i = 0; oldRows != null && i < oldRows.length() && rows.length() < OemProcessSupport.MAX_ROWS; i++) {
                JSONObject row = oldRows.optJSONObject(i);
                if (row == null) continue;
                int pid = row.optInt("pid", -1);
                long observed = row.optLong("observedAtMs", old.optLong("observedAtMs", -1));
                if (pid <= 0 || queried.contains(pid) || observed <= 0 || observed > now || now - observed > OemProcessMerger.MAX_AGE_MS) continue;
                Integer fd = previous.handles.get(pid);
                if (row.optString("bindingIdentityToken").isEmpty()) {
                    if (fd == null || !OemProcessSupport.pidfdAlive(fd) || handles.size() >= HANDLE_BUDGET) continue;
                    handles.put(pid, fd); previous.handles.remove(pid);
                }
                rows.put(new JSONObject(row.toString()).put("observedAtMs", observed)); retained++;
            }
            report.put("retainedUnqueriedRows", retained).put("rowTimestampsRetained", true)
                    .put("rowCount", rows.length());
        } catch (JSONException malformedOldResult) {
            // Invalid prior diagnostics must not prevent publication of the new successful route.
        }
    }

    @Override public synchronized void close() {
        closed = true;
        for (int i = 0; i < results.length; i++) {
            if (results[i] != null) results[i].releaseHandles();
            results[i] = null;
        }
        candidatePids = new int[0]; currentIdentities.clear(); previousNativePids.clear(); suppressedUntil.clear();
    }

    private static final class Result {
        final String json;
        final Map<Integer, Integer> handles;
        Result(String json, Map<Integer, Integer> handles) { this.json = json; this.handles = handles; }
        void releaseHandles() {
            for (int fd : handles.values()) OemProcessSupport.closePidfd(fd);
            handles.clear();
        }
    }
}
