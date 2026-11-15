package com.gpucheck.app;

import android.app.Instrumentation;
import android.os.SystemClock;
import android.view.View;

import org.json.JSONArray;
import org.json.JSONObject;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/** Synthetic controls only. No fixture PID or UID is passed to the real detector. */
final class OemProcessChecks {
    private static final int PID = 900071, OTHER_PID = 900072, APP_UID = 19999;
    private static final String TOKEN = "held_pidfd:900071:7";
    private static final String[] ROUTES = {"miui_cpu", "miui_memory", "oplus_cpu", "mindsync", "vivo_rms"};
    private static int checks;
    private OemProcessChecks() { }

    static JSONObject run() throws Exception {
        checks = 0;
        mergeControls();
        additionalMergeControls();
        JSONObject scheduling = schedulingControls();
        JSONObject targetedCache = targetedCacheControls();
        return new JSONObject().put("result", "PASS").put("synthetic", true).put("checks", checks)
                .put("scheduling", scheduling).put("targetedCache", targetedCache);
    }

    private static void mergeControls() throws Exception {
        JSONObject input = frame(nativeRow(-1));
        OemProcessMerger.merge(input, routes(observation(PID, 10123, TOKEN)), Collections.emptySet(), 10000);
        JSONObject found = find(input, PID);
        require(found.getInt("uid") == -1 && found.getInt("reportedUid") == 10123, "OEM UID remains distinct from effective UID");
        require(found.getBoolean("identityVerified") && found.getString("identityToken").equals(TOKEN), "Native identity retained");
        require(found.getDouble("cpuPercent") == 17.5 && found.getLong("cpuWindowEndNs") == 9000000, "OEM does not replace CPU sample");
        require(found.getString("name").equals("synthetic-process") && found.getInt("reportedPpid") == 100, "Bound name/parent enrichment");
        require(found.getBoolean("oemIdentityBound") && !input.getJSONObject("oemProcesses").getBoolean("effectiveUidPromoted"), "Explicit attribution semantics");

        OemProcessMerger.merge(input, new JSONArray(), Collections.emptySet(), 10001);
        found = find(input, PID);
        require(!found.has("reportedUid") && !found.has("oemEvidence") && found.getString("name").equals("PID " + PID),
                "Absent current evidence clears UID and restores original name");

        for (String malformed : new String[]{"stale", "future", "missingTime", "unavailable", "stringAvailable", "wrongIdentity", "missingBinding", "negativeUid"}) {
            input = frame(nativeRow(-1));
            JSONObject observation = observation(PID, 10123, TOKEN);
            JSONObject route = route("miui_cpu", observation);
            switch (malformed) {
                case "stale": route.put("observedAtMs", 1000); break;
                case "future": route.put("observedAtMs", 30000); break;
                case "missingTime": route.remove("observedAtMs"); break;
                case "unavailable": route.put("available", false); break;
                case "stringAvailable": route.put("available", "true"); break;
                case "wrongIdentity": observation.put("bindingIdentityToken", "held_pidfd:900071:replacement"); break;
                case "missingBinding": observation.remove("bindingIdentityToken"); break;
                case "negativeUid": observation.put("uid", -2); break;
                default: throw new AssertionError(malformed);
            }
            OemProcessMerger.merge(input, new JSONArray().put(route), Collections.emptySet(), 20000);
            require(!find(input, PID).has("reportedUid"), "Reject invalid current OEM evidence: " + malformed);
        }
        for (Object verification : new Object[]{false, "true"}) {
            input = frame(nativeRow(-1).put("identityVerified", verification));
            OemProcessMerger.merge(input, routes(observation(PID, 0, TOKEN)), Collections.emptySet(), 10000);
            require(!find(input, PID).has("reportedUid"), "Unverified native row cannot bind OEM metadata");
        }

        input = frame(nativeRow(1000));
        OemProcessMerger.merge(input, routes(observation(PID, 0, TOKEN)), Collections.emptySet(), 10000);
        found = find(input, PID);
        require(found.getInt("uid") == 1000 && found.getInt("reportedUid") == 0 && found.getBoolean("reportedUidConflict"),
                "Native effective UID wins and conflicting OEM UID is exposed");

        input = frame(nativeRow(-1));
        JSONArray conflicts = new JSONArray().put(route("miui_cpu", observation(PID, 10123, TOKEN)))
                .put(route("vivo_rms", observation(PID, 10456, TOKEN).put("ppid", 200)));
        OemProcessMerger.merge(input, conflicts, Collections.emptySet(), 10000);
        found = find(input, PID);
        require(found.getInt("reportedUid") == -1 && found.getBoolean("reportedUidConflict")
                && found.getJSONArray("reportedUidValues").length() == 2, "Conflicting OEM UIDs remain unknown");
        require(found.getInt("reportedPpid") == -1 && found.getBoolean("reportedPpidConflict"), "Conflicting parents remain unknown");

        input = frame(nativeRow(-1), nativeRow(-1));
        OemProcessMerger.merge(input, routes(observation(PID, 10123, TOKEN)), Collections.emptySet(), 10000);
        for (int i = 0; i < input.getJSONArray("processes").length(); i++)
            require(!input.getJSONArray("processes").getJSONObject(i).has("reportedUid"), "Duplicate native identities are never enriched");

        input = frame();
        OemProcessMerger.merge(input, routes(observation(PID, 0, "")), Collections.emptySet(), 10000);
        found = find(input, PID);
        require(found != null && found.getBoolean("oemOnly") && !found.getBoolean("identityVerified")
                && found.getString("identityToken").isEmpty() && found.getInt("uid") == -1, "OEM-only row stays unverified");
        require(found.getDouble("cpuPercent") == -1 && !found.getBoolean("cpuKnown"), "OEM-only CPU is unknown, never zero-filled");
        JSONObject processed = new RiskEngine(20, 3, 2000).process(input);
        require(processed.getInt("rootProcessCount") == 0 && processed.getInt("highRiskCount") == 0,
                "OEM-reported UID 0 cannot create root/high-risk classification");
        OemProcessMerger.merge(input, new JSONArray(), Collections.emptySet(), 10001);
        require(input.getJSONArray("processes").length() == 0, "OEM-only rows disappear with evidence");

        for (String rejection : new String[]{"dead", "stringAlive", "boundWithoutNative", "suppressed", "selfUid", "selfPid", "collectorPid", "excludedTid"}) {
            input = frame();
            JSONObject row = observation(PID, 10123, "");
            Set<Integer> suppressed = new HashSet<>();
            switch (rejection) {
                case "dead": row.put("pidfdAlive", false); break;
                case "stringAlive": row.put("pidfdAlive", "true"); break;
                case "boundWithoutNative": row.put("bindingIdentityToken", TOKEN); break;
                case "suppressed": suppressed.add(PID); break;
                case "selfUid": row.put("uid", APP_UID); break;
                case "selfPid": row.put("pid", input.getInt("appPid")); break;
                case "collectorPid": row.put("pid", input.getInt("collectorPid")); break;
                case "excludedTid": input.put("cpuExcludedPidTids", new JSONArray().put(PID)); break;
                default: throw new AssertionError(rejection);
            }
            OemProcessMerger.merge(input, routes(row), suppressed, 10000);
            require(input.getJSONArray("processes").length() == 0, "Reject OEM-only candidate: " + rejection);
        }

        input = frame(nativeRow(-1).put("name", "native-name"));
        OemProcessMerger.merge(input, routes(observation(PID, 10123, TOKEN)), Collections.emptySet(), 10000);
        require(find(input, PID).getString("name").equals("native-name"), "Readable native name has priority");
        OemProcessMerger.merge(input, routes(observation(PID, 10123, TOKEN)), Collections.emptySet(), 25001);
        require(!find(input, PID).has("reportedUid"), "TTL removes cached metadata even from reused JSONObject");

        input = frame(nativeRow(-1).put("identityToken", "new-identity"));
        OemProcessMerger.merge(input, routes(observation(PID, 10123, TOKEN)), Collections.emptySet(), 10000);
        require(!find(input, PID).has("reportedUid"), "PID reuse cannot inherit prior OEM name or UID");
        input = frame();
        OemProcessMerger.merge(input, routes(observation(OTHER_PID, -1, "")), Collections.emptySet(), 10000);
        require(find(input, OTHER_PID).getInt("reportedUid") == -1, "Service without UID retains explicit unknown");
    }

    private static void additionalMergeControls() throws Exception {
        JSONObject input = frame().put("cpuSamples", new JSONArray().put(nativeRow(-1)));
        OemProcessMerger.merge(input, routes(observation(PID, 10123, TOKEN)), Collections.emptySet(), 10000);
        require(input.getJSONArray("processes").length() == 0
                && input.getJSONArray("cpuSamples").getJSONObject(0).getInt("reportedUid") == 10123,
                "CPU-only metadata stays in the sample until RiskEngine independently admits it");
        JSONObject processed = new RiskEngine(20, 3, 2000).process(input);
        JSONObject found = find(processed, PID);
        require(found != null && !found.optBoolean("oemOnly") && found.getBoolean("identityVerified")
                && found.getString("identityToken").equals(TOKEN), "CPU-only identity survives OEM enrichment and RiskEngine admission");
        require(found.getDouble("cpuPercent") == 17.5 && found.getInt("uid") == -1 && found.getInt("reportedUid") == 10123,
                "CPU-only current CPU/effective UID are retained with reported UID separate");
        require(found.getString("name").equals("synthetic-process"), "Admitted CPU-only row carries bound OEM name");
        require(processed.getJSONArray("cpuSamples").length() == 1, "CPU-only metadata merge retains real CPU sample");

        for (String invalid : new String[]{"unverified", "stringVerified", "noToken", "negativeCpu", "duplicate"}) {
            JSONObject cpu = nativeRow(-1);
            switch (invalid) {
                case "unverified": cpu.put("identityVerified", false); break;
                case "stringVerified": cpu.put("identityVerified", "true"); break;
                case "noToken": cpu.put("identityToken", ""); break;
                case "negativeCpu": cpu.put("cpuPercent", -1); break;
                case "duplicate": break;
                default: throw new AssertionError(invalid);
            }
            JSONArray cpuRows = new JSONArray().put(cpu);
            if (invalid.equals("duplicate")) cpuRows.put(new JSONObject(cpu.toString()));
            input = frame().put("cpuSamples", cpuRows);
            OemProcessMerger.merge(input, routes(observation(PID, 0, TOKEN)), Collections.emptySet(), 10000);
            processed = new RiskEngine(20, 3, 2000).process(input);
            require(processed.getJSONArray("processes").length() == 0 && processed.getInt("rootProcessCount") == 0,
                    "OEM enrichment cannot bypass CPU-only admission: " + invalid);
        }

        input = frame(nativeRow(-1));
        JSONArray mixed = new JSONArray()
                .put(route("miui_cpu", observation(PID, 10123, TOKEN).put("source", "uid_source")))
                .put(route("oplus_cpu", observation(PID, -1, TOKEN).put("source", "name_source")))
                .put(route("miui_memory", observation(PID, -1, TOKEN).put("name", "").put("source", "parent_source")));
        OemProcessMerger.merge(input, mixed, Collections.emptySet(), 10000);
        found = find(input, PID);
        require(found.getString("reportedUidSource").equals("uid_source"), "UID provenance excludes name-only and parent-only routes");
        require(found.getJSONArray("oemSources").length() == 3, "Full OEM provenance still retains all contributing routes");
        input = frame(nativeRow(-1));
        OemProcessMerger.merge(input, routes(observation(PID, -1, TOKEN)), Collections.emptySet(), 10000);
        require(find(input, PID).getString("reportedUidSource").isEmpty(), "Unknown OEM UID has no fabricated source");

        JSONArray names = new JSONArray().put(route("miui_cpu", observation(PID, -1, TOKEN).put("name", "first-name")))
                .put(route("oplus_cpu", observation(PID, -1, TOKEN).put("name", "different-name")));
        input = frame(nativeRow(-1));
        OemProcessMerger.merge(input, names, Collections.emptySet(), 10000);
        found = find(input, PID);
        require(found.getBoolean("reportedNameConflict") && found.getJSONArray("reportedNames").length() == 2
                && found.getString("reportedName").isEmpty() && found.getString("name").equals("PID " + PID),
                "Conflicting OEM names do not choose one arbitrarily for a PID placeholder");
        input = frame(nativeRow(-1).put("name", "native-authoritative-name"));
        OemProcessMerger.merge(input, names, Collections.emptySet(), 10000);
        require(find(input, PID).getString("name").equals("native-authoritative-name"), "Name conflicts preserve readable native name");

        input = frame(nativeRow(-1));
        OemProcessMerger.merge(input, routes(observation(PID, APP_UID, TOKEN)), Collections.emptySet(), 10000);
        require(find(input, PID).getBoolean("oemSelfProcess"), "Consistent identity-bound app UID marks own process");
        processed = new RiskEngine(20, 3, 2000).process(input);
        require(processed.getJSONArray("processes").length() == 0 && processed.getInt("monitoredProcessCount") == 0,
                "Identity-bound OEM same-UID process is filtered from monitored results");
        input = frame(nativeRow(1000));
        OemProcessMerger.merge(input, routes(observation(PID, APP_UID, TOKEN)), Collections.emptySet(), 10000);
        require(!find(input, PID).optBoolean("oemSelfProcess") && find(input, PID).getBoolean("reportedUidConflict"),
                "OEM app UID cannot replace known native nonself UID");
        processed = new RiskEngine(20, 3, 2000).process(input);
        require(find(processed, PID) != null && find(processed, PID).getInt("uid") == 1000,
                "Known native nonself process remains monitored despite conflicting OEM app UID");
        input = frame(nativeRow(-1));
        JSONArray selfConflict = new JSONArray().put(route("miui_cpu", observation(PID, APP_UID, TOKEN)))
                .put(route("vivo_rms", observation(PID, 10123, TOKEN)));
        OemProcessMerger.merge(input, selfConflict, Collections.emptySet(), 10000);
        require(!find(input, PID).optBoolean("oemSelfProcess"), "Disagreeing OEM UIDs cannot suppress a possible external process");

        for (String invalidTime : new String[]{"expiredRow", "rowAfterRoute", "zeroRow"}) {
            input = frame(nativeRow(-1));
            long timestamp = invalidTime.equals("expiredRow") ? 1000 : invalidTime.equals("rowAfterRoute") ? 20001 : 0;
            JSONObject freshRoute = route("miui_memory", observation(PID, 10123, TOKEN).put("observedAtMs", timestamp))
                    .put("observedAtMs", 20000);
            OemProcessMerger.merge(input, new JSONArray().put(freshRoute), Collections.emptySet(), 20000);
            require(!find(input, PID).has("reportedUid"), "Fresh route cannot renew invalid original row timestamp: " + invalidTime);
        }
        input = frame(nativeRow(-1));
        JSONObject freshRoute = route("miui_memory", observation(PID, 10123, TOKEN).put("observedAtMs", 5000))
                .put("observedAtMs", 20000);
        OemProcessMerger.merge(input, new JSONArray().put(freshRoute), Collections.emptySet(), 20000);
        require(find(input, PID).getLong("oemObservedAtMs") == 5000, "Valid retained row keeps exact original age at TTL boundary");
        OemProcessMerger.merge(input, new JSONArray().put(freshRoute), Collections.emptySet(), 20001);
        require(!find(input, PID).has("reportedUid"), "Retained row expires immediately after original TTL boundary");
    }

    private static JSONObject targetedCacheControls() throws Exception {
        AtomicLong time = new AtomicLong(10000);
        AtomicInteger mode = new AtomicInteger();
        OemProcessMonitor.Route[] transports = new OemProcessMonitor.Route[5];
        for (int i = 0; i < transports.length; i++) {
            final int index = i;
            transports[i] = (candidates, cancelled) -> {
                JSONArray rows = new JSONArray();
                if (mode.get() == 0 && (index == 0 || index == 1 || index == 4))
                    rows.put(observation(PID, 10123, TOKEN));
                return new JSONObject().put("route", ROUTES[index]).put("available", true).put("status", "AVAILABLE")
                        .put("rows", rows).put("observedAtMs", time.get())
                        .put("queriedPids", new JSONArray().put(mode.get() == 1 ? OTHER_PID : PID));
            };
        }
        OemProcessMonitor monitor = new OemProcessMonitor(transports, time::get);
        try {
            collectCacheRound(monitor, time.get());
            for (String target : new String[]{"miui_memory", "vivo_rms"})
                require(routeRow(monitor.snapshot(), target, PID).getLong("observedAtMs") == 10000,
                        "Initial targeted observation timestamp: " + target);
            mode.set(1);
            time.set(12001);
            collectCacheRound(monitor, time.get());
            JSONObject second = monitor.snapshot();
            require(routeRow(second, "miui_cpu", PID) == null, "Enumeration route does not retain an absent process");
            for (String target : new String[]{"miui_memory", "vivo_rms"}) {
                JSONObject row = routeRow(second, target, PID);
                require(row != null && row.getLong("observedAtMs") == 10000
                        && row.getString("bindingIdentityToken").equals(TOKEN), "Unqueried targeted PID retains original timestamp and identity: " + target);
            }
            time.set(14002);
            collectCacheRound(monitor, time.get());
            for (String target : new String[]{"miui_memory", "vivo_rms"})
                require(routeRow(monitor.snapshot(), target, PID).getLong("observedAtMs") == 10000,
                        "Repeated other-PID refresh cannot renew row lifetime: " + target);
            time.set(26001);
            collectCacheRound(monitor, time.get());
            for (String target : new String[]{"miui_memory", "vivo_rms"})
                require(routeRow(monitor.snapshot(), target, PID) == null, "Targeted cache drops PID after original 15-second TTL: " + target);
            mode.set(0);
            time.set(28002);
            collectCacheRound(monitor, time.get());
            for (String target : new String[]{"miui_memory", "vivo_rms"})
                require(routeRow(monitor.snapshot(), target, PID).getLong("observedAtMs") == 28002,
                        "Actual requery provides a new observation timestamp: " + target);
            mode.set(2);
            time.set(30003);
            collectCacheRound(monitor, time.get());
            for (String target : new String[]{"miui_memory", "vivo_rms"})
                require(routeRow(monitor.snapshot(), target, PID) == null, "Current queried PID with empty return clears cached row: " + target);
            return new JSONObject().put("synthetic", true).put("routes", new JSONArray().put("miui_memory").put("vivo_rms"))
                    .put("originalRowTtlPreserved", true).put("queriedEmptyClears", true).put("result", "PASS");
        } finally { monitor.close(); SystemClock.sleep(30); }
    }

    private static void collectCacheRound(OemProcessMonitor monitor, long expectedAt) throws Exception {
        JSONObject other = nativeRow(-1).put("pid", OTHER_PID).put("identityToken", "held_pidfd:900072:7");
        monitor.enrich(frame(nativeRow(-1), other));
        long deadline = SystemClock.elapsedRealtime() + 2500;
        while (SystemClock.elapsedRealtime() < deadline) {
            JSONArray routes = monitor.snapshot().getJSONArray("routes");
            int finished = 0;
            for (int i = 0; i < routes.length(); i++) {
                JSONObject route = routes.getJSONObject(i);
                if (route.optBoolean("available") && !route.optBoolean("inFlight")
                        && route.optLong("observedAtMs", -1) == expectedAt) finished++;
            }
            if (finished == 5) return;
            SystemClock.sleep(10);
        }
        throw new AssertionError("Targeted cache round did not finish at fake time " + expectedAt + ": " + monitor.snapshot());
    }

    private static JSONObject routeRow(JSONObject snapshot, String target, int pid) throws Exception {
        JSONArray routes = snapshot.getJSONArray("routes");
        for (int i = 0; i < routes.length(); i++) {
            JSONObject route = routes.getJSONObject(i);
            if (!target.equals(route.optString("route"))) continue;
            JSONArray rows = route.getJSONArray("rows");
            for (int j = 0; j < rows.length(); j++) if (rows.getJSONObject(j).optInt("pid", -1) == pid) return rows.getJSONObject(j);
        }
        return null;
    }

    private static JSONObject schedulingControls() throws Exception {
        AtomicLong time = new AtomicLong(10000);
        CountDownLatch started = new CountDownLatch(5), release = new CountDownLatch(1), blockedFinished = new CountDownLatch(1);
        AtomicInteger blockedCalls = new AtomicInteger(), nextSessionBlockedCalls = new AtomicInteger();
        OemProcessMonitor.Route[] routes = new OemProcessMonitor.Route[5];
        OemProcessMonitor.Route[] next = new OemProcessMonitor.Route[5];
        for (int i = 0; i < 5; i++) {
            final int index = i;
            routes[i] = (candidates, cancelled) -> {
                started.countDown();
                if (index == 0) {
                    blockedCalls.incrementAndGet();
                    try { release.await(5, TimeUnit.SECONDS); }
                    finally { blockedFinished.countDown(); }
                }
                return new JSONObject().put("route", ROUTES[index]).put("status", "AVAILABLE").put("available", true)
                        .put("rows", new JSONArray()).put("observedAtMs", time.get());
            };
            next[i] = (candidates, cancelled) -> {
                if (index == 0) nextSessionBlockedCalls.incrementAndGet();
                return new JSONObject().put("route", ROUTES[index]).put("status", "AVAILABLE").put("available", true)
                        .put("rows", new JSONArray()).put("observedAtMs", time.get());
            };
        }
        OemProcessMonitor first = new OemProcessMonitor(routes, time::get);
        OemProcessMonitor second = null;
        try {
            long before = SystemClock.elapsedRealtime();
            first.snapshot();
            require(SystemClock.elapsedRealtime() - before < 500, "Snapshot does not await Binder workers");
            require(started.await(3, TimeUnit.SECONDS), "Five route workers are started independently");
            JSONObject snapshot = awaitAvailable(first, 4, 2000);
            require(available(snapshot) == 4, "A blocked route does not starve the other four routes");
            for (int i = 0; i < 20; i++) first.snapshot();
            require(blockedCalls.get() == 1, "Repeated snapshots do not queue more blocked work");
            time.set(17001);
            require(routeStatus(first.snapshot(), "miui_cpu").equals("TIMEOUT"), "Blocked route reports timeout");
            first.close();
            require(available(first.snapshot()) == 0, "Closing clears completed route evidence");
            second = new OemProcessMonitor(next, time::get);
            second.snapshot();
            SystemClock.sleep(70);
            require(nextSessionBlockedCalls.get() == 0, "New session cannot create a second hung worker for same route");
            release.countDown();
            require(blockedFinished.await(2, TimeUnit.SECONDS), "Synthetic blocked route releases for subsequent tests");
            awaitAvailable(second, 5, 2500);
            require(nextSessionBlockedCalls.get() == 1, "New session can collect after old worker finishes");
            require(available(first.snapshot()) == 0, "Late old callback cannot republish closed session evidence");
            return new JSONObject().put("synthetic", true).put("routes", 5).put("independentWorkers", true)
                    .put("blockedRouteDidNotStallPeers", true).put("oldSessionDidNotPublish", true);
        } finally {
            release.countDown(); first.close(); if (second != null) second.close();
            blockedFinished.await(2, TimeUnit.SECONDS);
            SystemClock.sleep(30);
        }
    }

    static JSONObject ui(Instrumentation instrumentation, MainActivity activity) throws Exception {
        AtomicReference<Throwable> failure = new AtomicReference<>();
        AtomicInteger verified = new AtomicInteger();
        instrumentation.runOnMainSync(() -> {
            JSONObject previous = null;
            try {
                Field current = MainActivity.class.getDeclaredField("currentReport"); current.setAccessible(true);
                previous = (JSONObject) current.get(activity);
                Method render = MainActivity.class.getDeclaredMethod("renderProcesses"); render.setAccessible(true);
                Field list = MainActivity.class.getDeclaredField("processList"); list.setAccessible(true);
                JSONObject[] cases = {nativeRow(1000), nativeRow(-1).put("reportedUid", 10123),
                        nativeRow(-1).put("reportedUid", 10123).put("reportedUidConflict", true), nativeRow(-1),
                        nativeRow(1000).put("reportedUid", 0).put("reportedUidConflict", true)};
                String[] labels = {"UID 1000", "UID 10123（厂商）", "UID 未知（来源冲突）", "UID 未知", "UID 1000"};
                for (int i = 0; i < cases.length; i++) {
                    require(MainActivity.processUidLabel(cases[i]).equals(labels[i]), "Independent UID label expectation " + i);
                    current.set(activity, frame(cases[i])); render.invoke(activity);
                    String text = OemProcessInstrumentation.texts((View) list.get(activity));
                    require(text.contains(labels[i]), "Reused process card displays native/reported/conflict/unknown UID " + i);
                    if (i >= 2) require(!text.contains("UID 10123（厂商）"), "Reused card clears previous reported UID");
                    verified.incrementAndGet();
                }
                current.set(activity, previous); render.invoke(activity);
            } catch (Throwable error) { failure.set(error); }
        });
        if (failure.get() != null) throw new AssertionError("Synthetic UID UI checks", failure.get());
        return new JSONObject().put("synthetic", true).put("cases", verified.get()).put("result", "PASS");
    }

    private static JSONObject awaitAvailable(OemProcessMonitor monitor, int count, long timeout) throws Exception {
        long deadline = SystemClock.elapsedRealtime() + timeout;
        JSONObject last = null;
        while (SystemClock.elapsedRealtime() < deadline) {
            last = monitor.snapshot(); if (available(last) >= count) return last;
            SystemClock.sleep(10);
        }
        throw new AssertionError("Timed out awaiting " + count + " synthetic routes: " + last);
    }

    private static int available(JSONObject snapshot) throws Exception {
        int count = 0; JSONArray routes = snapshot.getJSONArray("routes");
        for (int i = 0; i < routes.length(); i++) if (routes.getJSONObject(i).optBoolean("available")) count++;
        return count;
    }

    private static String routeStatus(JSONObject snapshot, String name) throws Exception {
        JSONArray routes = snapshot.getJSONArray("routes");
        for (int i = 0; i < routes.length(); i++) if (name.equals(routes.getJSONObject(i).optString("route"))) return routes.getJSONObject(i).optString("status");
        return "missing";
    }

    private static JSONObject nativeRow(int uid) throws Exception {
        return new JSONObject().put("pid", PID).put("uid", uid).put("name", "PID " + PID)
                .put("identityVerified", true).put("identityToken", TOKEN).put("cpuPercent", 17.5)
                .put("cpuWindowStartNs", 1000000).put("cpuWindowEndNs", 9000000);
    }

    private static JSONObject observation(int pid, int uid, String binding) throws Exception {
        return new JSONObject().put("pid", pid).put("uid", uid).put("name", "synthetic-process").put("ppid", 100)
                .put("source", "synthetic-route").put("bindingIdentityToken", binding).put("pidfdAlive", true);
    }

    private static JSONObject route(String name, JSONObject row) throws Exception {
        return new JSONObject().put("route", name).put("available", true).put("status", "AVAILABLE")
                .put("observedAtMs", 10000).put("rows", new JSONArray().put(row));
    }

    private static JSONArray routes(JSONObject row) throws Exception { return new JSONArray().put(route("miui_cpu", row)); }

    private static JSONObject frame(JSONObject... rows) throws Exception {
        JSONArray input = new JSONArray(); for (JSONObject row : rows) input.put(row);
        return new JSONObject().put("schema", 1).put("sampleIndex", 10).put("elapsedMs", 20000)
                .put("collectorUid", APP_UID).put("collectorPid", 900099).put("appPid", 900098)
                .put("processes", input).put("cpuSamples", new JSONArray());
    }

    private static JSONObject find(JSONObject frame, int pid) throws Exception {
        JSONArray rows = frame.getJSONArray("processes");
        for (int i = 0; i < rows.length(); i++) if (rows.getJSONObject(i).optInt("pid", -1) == pid) return rows.getJSONObject(i);
        return null;
    }

    private static void require(boolean condition, String message) { if (!condition) throw new AssertionError(message); checks++; }
}
