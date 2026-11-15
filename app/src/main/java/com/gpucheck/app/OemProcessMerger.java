package com.gpucheck.app;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Merges current service observations without promoting reported UID to effective-UID evidence. */
final class OemProcessMerger {
    static final long MAX_AGE_MS = 15000;
    private static final String[] DERIVED = {"reportedUid", "reportedUidSource", "reportedUidConflict",
            "reportedUidValues", "reportedName", "reportedNameConflict", "reportedNames", "oemSelfProcess",
            "reportedPpid", "reportedPpidConflict", "ppidSource",
            "oemSources", "oemEvidence", "oemIdentityBound", "oemObservedAtMs", "oemOriginalName"};
    private OemProcessMerger() { }

    static void merge(JSONObject raw, JSONArray routes, Set<Integer> suppressedPids, long nowMs) throws JSONException {
        JSONArray input = raw.optJSONArray("processes");
        if (input == null) input = new JSONArray();
        JSONArray output = new JSONArray();
        Map<Integer, JSONObject> current = new LinkedHashMap<>();
        Set<Integer> duplicates = new HashSet<>();
        Set<Integer> excluded = new HashSet<>();
        JSONArray excludedValues = raw.optJSONArray("cpuExcludedPids");
        if (excludedValues == null) excludedValues = raw.optJSONArray("cpuExcludedPidTids");
        for (int i = 0; excludedValues != null && i < excludedValues.length(); i++) excluded.add(excludedValues.optInt(i, -1));
        int collectorPid = raw.optInt("collectorPid", -1), appPid = raw.optInt("appPid", android.os.Process.myPid());
        int appUid = raw.optInt("collectorUid", android.os.Process.myUid());
        for (int i = 0; i < input.length(); i++) {
            JSONObject process = input.optJSONObject(i);
            if (process == null || process.optBoolean("oemOnly")) continue;
            if (process.has("oemOriginalName")) process.put("name", process.optString("oemOriginalName"));
            for (String key : DERIVED) process.remove(key);
            int pid = process.optInt("pid", -1);
            if (current.put(pid, process) != null) duplicates.add(pid);
            output.put(process);
        }
        // CPU-only observations keep RiskEngine's independent admission/exit/freshness checks.
        // Enrich the sample in place, but never synthesize a process that bypasses those checks.
        JSONArray cpu = raw.optJSONArray("cpuSamples");
        Map<Integer, Integer> cpuCounts = new HashMap<>();
        for (int i = 0; cpu != null && i < cpu.length(); i++) {
            JSONObject row = cpu.optJSONObject(i);
            if (row != null) cpuCounts.merge(row.optInt("pid", -1), 1, Integer::sum);
        }
        for (int i = 0; cpu != null && i < cpu.length(); i++) {
            JSONObject row = cpu.optJSONObject(i);
            if (row == null) continue;
            if (row.has("oemOriginalName")) row.put("name", row.optString("oemOriginalName"));
            for (String key : DERIVED) row.remove(key);
            int pid = row.optInt("pid", -1);
            if (pid <= 0 || current.containsKey(pid)) continue;
            if (cpuCounts.getOrDefault(pid, 0) != 1) { duplicates.add(pid); continue; }
            current.put(pid, row);
        }
        Map<Integer, List<Observation>> observations = new LinkedHashMap<>();
        int available = 0, rejected = 0;
        for (int r = 0; routes != null && r < routes.length(); r++) {
            JSONObject route = routes.optJSONObject(r);
            if (route == null || !Boolean.TRUE.equals(route.opt("available"))) continue;
            long observed = route.optLong("observedAtMs", -1);
            if (observed <= 0 || observed > nowMs || nowMs - observed > MAX_AGE_MS) continue;
            available++;
            JSONArray rows = route.optJSONArray("rows");
            for (int i = 0; rows != null && i < Math.min(rows.length(), OemProcessSupport.MAX_ROWS); i++) {
                JSONObject row = rows.optJSONObject(i);
                if (row == null) continue;
                long rowObserved = row.optLong("observedAtMs", observed);
                if (rowObserved <= 0 || rowObserved > observed || rowObserved > nowMs
                        || nowMs - rowObserved > MAX_AGE_MS) { rejected++; continue; }
                int pid = row.optInt("pid", -1), uid = row.optInt("uid", -1);
                if (pid <= 0 || uid < -1 || duplicates.contains(pid) || excluded.contains(pid)
                        || pid == collectorPid || pid == appPid) { rejected++; continue; }
                JSONObject nativeRow = current.get(pid);
                String binding = row.optString("bindingIdentityToken", "");
                if (nativeRow != null) {
                    String identity = nativeRow.optString("identityToken", "");
                    if (!Boolean.TRUE.equals(nativeRow.opt("identityVerified")) || identity.isEmpty()
                            || !identity.equals(binding)) { rejected++; continue; }
                    if (nativeRow.optInt("uid", -1) == appUid && appUid >= 0) { rejected++; continue; }
                } else {
                    if (!binding.isEmpty() || !Boolean.TRUE.equals(row.opt("pidfdAlive"))
                            || (suppressedPids != null && suppressedPids.contains(pid)) || (uid == appUid && appUid >= 0)) {
                        rejected++; continue;
                    }
                }
                observations.computeIfAbsent(pid, ignored -> new ArrayList<>())
                        .add(new Observation(row, route.optString("route"), rowObserved));
            }
        }
        int added = 0, enriched = 0, uidKnown = 0, conflicts = 0;
        for (Map.Entry<Integer, List<Observation>> entry : observations.entrySet()) {
            int pid = entry.getKey();
            JSONObject process = current.get(pid);
            boolean bound = process != null;
            if (process == null) {
                process = new JSONObject().put("pid", pid).put("uid", -1).put("uidSource", "unknown")
                        .put("name", "PID " + pid).put("cpuPercent", -1).put("cpuKnown", false)
                        .put("identityVerified", false).put("identityToken", "")
                        .put("identitySource", "oem_service_candidate_unverified").put("oemOnly", true)
                        .put("metadataAccessible", false).put("gpuEvidenceReadable", false)
                        .put("errors", new JSONArray().put("OEM service candidate; process identity and effective UID are not verified"));
                output.put(process); added++;
            } else enriched++;
            LinkedHashSet<Integer> uids = new LinkedHashSet<>(), parents = new LinkedHashSet<>();
            LinkedHashSet<String> sources = new LinkedHashSet<>(), uidSources = new LinkedHashSet<>(), names = new LinkedHashSet<>();
            JSONArray evidence = new JSONArray();
            long newest = 0;
            for (Observation item : entry.getValue()) {
                JSONObject row = item.row;
                int uid = row.optInt("uid", -1), parent = row.optInt("ppid", -1);
                if (uid >= 0) uids.add(uid);
                if (parent >= 0 && parent != pid) parents.add(parent);
                String name = row.optString("name", "");
                if (!name.trim().isEmpty() && name.length() <= 4096 && name.indexOf('\0') < 0) names.add(name);
                String source = row.optString("source", item.route);
                if (source.isEmpty()) source = item.route;
                sources.add(source);
                if (uid >= 0) uidSources.add(source);
                JSONObject copy = new JSONObject(row.toString()).put("route", item.route).put("observedAtMs", item.observed);
                copy.remove("bindingIdentityToken"); copy.remove("pidfdAlive");
                evidence.put(copy); newest = Math.max(newest, item.observed);
            }
            int reported = uids.size() == 1 ? uids.iterator().next() : -1;
            int nativeUid = process.optInt("uid", -1);
            boolean conflict = uids.size() > 1 || (nativeUid >= 0 && !uids.isEmpty()
                    && (uids.size() != 1 || !uids.contains(nativeUid)));
            if (reported >= 0) uidKnown++;
            if (conflict) conflicts++;
            process.put("reportedUid", reported).put("reportedUidSource", String.join(",", uidSources))
                    .put("reportedUidValues", new JSONArray(uids)).put("reportedUidConflict", conflict)
                    .put("oemSources", new JSONArray(sources)).put("oemEvidence", evidence)
                    .put("oemIdentityBound", bound).put("oemObservedAtMs", newest)
                    .put("reportedPpid", parents.size() == 1 ? parents.iterator().next() : -1)
                    .put("reportedPpidConflict", parents.size() > 1).put("ppidSource", "oem_service_reported");
            String name = names.size() == 1 ? names.iterator().next() : "";
            process.put("reportedName", name).put("reportedNames", new JSONArray(names)).put("reportedNameConflict", names.size() > 1)
                    .put("oemSelfProcess", bound && nativeUid < 0 && reported == appUid && appUid >= 0 && !conflict);
            String original = process.optString("name", "");
            if (!name.isEmpty() && (original.isEmpty() || original.equals("PID " + pid))) {
                process.put("oemOriginalName", original).put("name", name);
            }
        }
        raw.put("processes", output).put("oemProcesses", new JSONObject().put("schema", 1)
                .put("routes", routes == null ? new JSONArray() : routes).put("availableRoutes", available)
                .put("coverageLimited", true).put("brandGateUsed", false).put("enrichedProcessCount", enriched)
                .put("addedCandidateCount", added).put("reportedUidCount", uidKnown).put("uidConflictCount", conflicts)
                .put("rejectedObservationCount", rejected).put("effectiveUidPromoted", false)
                .put("uidSemantics", "uid is native effective-UID evidence; reportedUid is an OEM service observation"));
    }

    private static final class Observation {
        final JSONObject row;
        final String route;
        final long observed;
        Observation(JSONObject row, String route, long observed) { this.row = row; this.route = route; this.observed = observed; }
    }
}
