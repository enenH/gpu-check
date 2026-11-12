package com.gpucheck.app;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class RiskEngine {
    private static final int LIFECYCLE_LIMIT = 1024;
    private final RiskPolicy policy;
    private final AvcRiskPolicy avcPolicy;
    private final CgroupWatchPolicy cgroupPolicy;
    private final CpuGpuLifecycle lifecycle = new CpuGpuLifecycle();
    private final GpuHighFrequency highFrequency = new GpuHighFrequency();
    private final SelfGpuFilter selfGpuFilter = new SelfGpuFilter();
    private final double threshold;
    private final int windows;
    private final int intervalMs;
    private final long sessionStartedAt = System.currentTimeMillis();
    private long previousElapsed = -1;
    private final Map<Integer, String> cgroupLifecycleWatches = new HashMap<>();

    RiskEngine(double threshold, int windows, int intervalMs) {
        this.threshold = threshold;
        this.windows = windows;
        this.intervalMs = intervalMs;
        this.policy = new RiskPolicy(threshold, windows);
        this.avcPolicy = new AvcRiskPolicy(threshold, windows);
        this.cgroupPolicy = new CgroupWatchPolicy(intervalMs);
    }

    JSONObject process(JSONObject report) throws JSONException {
        long elapsed = report.optLong("elapsedMs", -1);
        if (previousElapsed >= 0 && (elapsed <= previousElapsed || elapsed - previousElapsed > intervalMs * 4L)) {
            policy.beginSnapshot();
            policy.endSnapshot();
            avcPolicy.beginSnapshot(false, false);
            avcPolicy.endSnapshot();
            if (elapsed >= 0 && elapsed < previousElapsed) lifecycle.reset();
            else lifecycle.resetObservations();
            highFrequency.reset();
            selfGpuFilter.reset();
        }
        previousElapsed = elapsed;
        policy.beginSnapshot();
        JSONObject global = report.optJSONObject("globalGpu");
        avcPolicy.beginSnapshot(global != null && global.optBoolean("sampled"), global != null && global.optBoolean("active"));
        long sampleIndex = report.optLong("sampleIndex", -1);
        JSONObject cgroupScan = report.optJSONObject("cgroupScan");
        boolean cgroupPathMethodAvailable = cgroupScan != null
                && CgroupWatchPolicy.METHOD.equals(cgroupScan.optString("method"))
                && Boolean.TRUE.equals(cgroupScan.opt("available"))
                && Boolean.TRUE.equals(cgroupScan.opt("calibrationValid"))
                && cgroupScan.optLong("sampleIndex", -1) == sampleIndex;
        cgroupPolicy.beginSnapshot(sampleIndex, elapsed, cgroupPathMethodAvailable);
        JSONArray input = mergeCurrentCpuRows(report);
        JSONArray environmentChecks = report.optJSONArray("environmentChecks");
        if (environmentChecks == null) environmentChecks = new JSONArray();
        JSONArray excludedKernelThreads = new JSONArray();
        int kernelDomainMismatches = 0;
        JSONArray nativeEvents = report.optJSONArray("processEvents");
        List<JSONObject> sorted = new ArrayList<>();
        int high = 0;
        int watching = 0;
        int rootDenied = 0;
        int rootCount = 0, cgroupAnomalies = 0, cgroupWatching = 0;
        Map<String, JSONObject> currentRows = new HashMap<>();
        Map<Integer, String> currentRoots = new HashMap<>();
        Map<Integer, String> currentCgroupWatches = new HashMap<>();
        Map<Integer, Integer> occurrences = new HashMap<>();
        for (int i = 0; input != null && i < input.length(); i++) {
            int pid = input.getJSONObject(i).optInt("pid", -1);
            occurrences.put(pid, occurrences.getOrDefault(pid, 0) + 1);
        }
        for (int i = 0; input != null && i < input.length(); i++) {
            JSONObject p = input.getJSONObject(i);
            int pid = p.optInt("pid", -1);
            boolean isSelf = isSelf(p, report);
            if (!MonitoredProcessFilter.acceptsCpu(pid, isSelf) || occurrences.get(pid) != 1) continue;
            String threadType = KernelThreadPolicy.classify(p, report);
            boolean kernelDomainMismatch = KernelThreadPolicy.kernelDomainMismatch(p, threadType);
            p.put("threadType", threadType).put("kernelDomainMismatch", kernelDomainMismatch);
            if (KernelThreadPolicy.KERNEL.equals(threadType)) {
                excludedKernelThreads.put(new JSONObject().put("pid", pid)
                        .put("identityToken", p.optString("identityToken"))
                        .put("threadTypeCheck", p.optJSONObject("threadTypeCheck")));
                lifecycle.revoke(pid, p.optString("identityToken"));
                continue;
            }
            if (kernelDomainMismatch) {
                kernelDomainMismatches++;
                environmentChecks.put(new JSONObject().put("type", "avc_kernel_userspace")
                        .put("status", "ANOMALY").put("pid", pid)
                        .put("identityToken", p.optString("identityToken"))
                        .put("avcTargetContext", p.optString("avcTargetContext"))
                        .put("avcEvidenceAgeMs", p.optLong("avcEvidenceAgeMs"))
                        .put("avcEvidence", p.opt("avcEvidence"))
                        .put("threadTypeCheck", p.optJSONObject("threadTypeCheck"))
                        .put("reason", "AVC 目标域为 kernel，但同一存活身份的 futex 检查确认是用户态线程。"));
            }
            int observedUid = p.optInt("uid", -1);
            String processIdentity = p.optString("identityToken", "");
            CgroupWatchPolicy.Decision cgroup = cgroupPolicy.evaluate(pid, processIdentity,
                    occurrences.get(pid) == 1 && Boolean.TRUE.equals(p.opt("identityVerified"))
                            ? cgroupCheck(p.optJSONObject("cgroupCheck")) : null, isSelf);
            boolean rootCandidate = !isSelf && isRoot(p);
            p.put("cgroupAnomaly", cgroup.anomaly).put("cgroupWatch", cgroupWatchJson(cgroup))
                    .put("rootCandidate", rootCandidate).put("monitoredCandidate", true);
            currentRows.put(processKey(p), p);
            if (rootCandidate) currentRoots.put(pid, processIdentity);
            if (cgroup.validMissing) {
                cgroupWatching++;
                if (!rootCandidate && cgroup.consecutive == 1
                        && (processIdentity.equals(cgroupLifecycleWatches.get(pid))
                            || lifecycle.confirmedOnset(pid, processIdentity) != null)) {
                    // A skipped/duplicate/late round restarts anomaly confirmation even
                    // when the next raw MISSING carries the same process identity.
                    lifecycle.revoke(pid, processIdentity);
                }
                // Preserve a birth event while confirmation is pending. It is bound to the
                // lifecycle detector only after admission, without weakening its CPU/GPU rule.
                currentCgroupWatches.put(pid, processIdentity);
            }
            if (cgroup.anomaly) cgroupAnomalies++;
            boolean explicitOtherDomain = observedUid < 0 && p.optBoolean("identityVerified")
                    && !p.optBoolean("avcRootDomainHint") && !p.optString("avcTargetContext").isEmpty()
                    && p.optString("identityToken").equals(p.optString("avcIdentityToken"));
            boolean watchedExit = processIdentity.equals(cgroupLifecycleWatches.get(pid))
                    && trustedExit(nativeEvents, pid, processIdentity, global);
            if ((observedUid > 0 || explicitOtherDomain) && !cgroup.validMissing && !watchedExit) {
                lifecycle.revoke(pid, processIdentity);
            }
            p.remove("riskBasis");
            p.remove("riskConfidence");
            String risk = "MONITORING", reason = sortableCpu(p) < 0
                    ? "正在建立 CPU 基线或当前 CPU 时钟不可读取。" : "正在持续采样该进程的 CPU 使用率。";
            int consecutive = 0;
            if (rootCandidate) {
                rootCount++;
                if (observedUid < 0 || !p.optBoolean("gpuEvidenceReadable")) rootDenied++;
                RiskPolicy.Decision d = policy.evaluate(pid, p.optLong("startTimeTicks"),
                        observedUid, p.optDouble("cpuPercent", -1), p.optString("background", "unknown"),
                        p.optBoolean("gpuDeviceOpen"), p.optBoolean("gpuActive"),
                        p.optBoolean("gpuEvidenceReadable", p.optBoolean("gpuScanComplete", false)));
                String identity = processIdentity;
                if (identity.isEmpty() && p.optLong("startTimeTicks") > 0) identity = "stat:" + p.optLong("startTimeTicks");
                if (p.has("identityVerified") && !p.optBoolean("identityVerified")) identity = "";
                AvcRiskPolicy.Decision avc = avcPolicy.evaluate(pid, identity,
                        p.optDouble("cpuPercent", -1), p.optBoolean("avcRootDomainHint"), false);
                risk = d.risk; reason = d.reason; consecutive = d.consecutiveHigh;
                if (!"HIGH".equals(risk) && p.optBoolean("avcRootDomainHint")) {
                    risk = avc.risk; reason = avc.reason; consecutive = avc.consecutiveHigh;
                }
                if ("HIGH".equals(avc.risk)) {
                    risk = "HIGH"; reason = avc.reason; consecutive = avc.consecutiveHigh;
                    p.put("riskBasis", "avc_root_domain_cpu_global_memstore")
                            .put("riskConfidence", "heuristic").put("gpuAttribution", "global_unattributed")
                            .put("rootIdentityEvidence", "avc_target_selinux_domain");
                } else if ("HIGH".equals(d.risk)) {
                    p.put("riskBasis", "verified_uid_background_gpu_device_cpu").put("riskConfidence", "direct_metadata");
                }
            }
            if (cgroup.anomaly && !"HIGH".equals(risk)) {
                risk = "WATCH"; reason = cgroup.reason;
                p.put("riskBasis", "proc_cgroup_path_mismatch").put("riskConfidence", "named_path_mismatch");
            }
            p.put("risk", risk).put("consecutiveHigh", consecutive).put("reason", reason);
            sorted.add(p);
            if ("HIGH".equals(risk)) high++;
            else if (rootCandidate && ("WATCH".equals(risk) || "UNKNOWN".equals(risk))) watching++;
        }
        policy.endSnapshot();
        avcPolicy.endSnapshot();
        cgroupPolicy.endSnapshot();
        sorted.sort(Comparator.comparingDouble(RiskEngine::sortableCpu).reversed()
                .thenComparingInt(p -> p.optInt("pid", Integer.MAX_VALUE)));
        int eligibleCandidates = sorted.size();
        Set<String> retainedIdentities = new HashSet<>();
        high = watching = rootDenied = rootCount = cgroupAnomalies = 0;
        for (JSONObject p : sorted) {
            retainedIdentities.add(processKey(p));
            if (p.optBoolean("cgroupAnomaly")) cgroupAnomalies++;
            if (!p.optBoolean("rootCandidate")) continue;
            rootCount++;
            if (p.optInt("uid", -1) < 0 || !p.optBoolean("gpuEvidenceReadable")) rootDenied++;
            String risk = p.optString("risk");
            if ("HIGH".equals(risk)) high++;
            else if ("WATCH".equals(risk) || "UNKNOWN".equals(risk)) watching++;
        }
        for (Map.Entry<Integer, String> previous : cgroupLifecycleWatches.entrySet()) {
            int pid = previous.getKey(); String identity = previous.getValue();
            if (!identity.equals(currentCgroupWatches.get(pid)) && !identity.equals(currentRoots.get(pid))
                    && !trustedExit(nativeEvents, pid, identity, global)) {
                lifecycle.revoke(pid, identity);
            }
        }
        cgroupLifecycleWatches.clear();
        cgroupLifecycleWatches.putAll(currentCgroupWatches);
        JSONArray cpuSamples = report.optJSONArray("cpuSamples");
        if (cpuSamples == null) cpuSamples = new JSONArray(sorted);
        JSONArray monitoredCpuSamples = new JSONArray();
        Set<String> sampledIdentities = new HashSet<>();
        for (int i = 0; i < cpuSamples.length(); i++) {
            JSONObject p = cpuSamples.getJSONObject(i);
            if (!retainedIdentities.contains(processKey(p))) continue;
            JSONObject current = currentRows.get(processKey(p));
            if (current != null && current.optInt("uid", -1) >= 0) p.put("uid", current.optInt("uid"));
            if (isSelf(p, report)) continue;
            boolean anomaly = current != null && current.optBoolean("cgroupAnomaly");
            boolean rootCandidate = current != null && current.optBoolean("rootCandidate");
            if (sortableCpu(p) < 0) continue;
            p.put("cgroupAnomaly", anomaly).put("rootCandidate", rootCandidate).put("monitoredCandidate", true);
            if (current != null) p.put("cgroupWatch", current.optJSONObject("cgroupWatch"));
            if (sampledIdentities.add(processKey(p))) monitoredCpuSamples.put(p);
        }
        for (JSONObject p : sorted) {
            if (sortableCpu(p) >= 0 && sampledIdentities.add(processKey(p))) {
                monitoredCpuSamples.put(new JSONObject().put("pid", p.optInt("pid"))
                        .put("uid", p.optInt("uid", -1)).put("identityToken", p.optString("identityToken"))
                        .put("identityVerified", p.optBoolean("identityVerified"))
                        .put("cpuPercent", p.optDouble("cpuPercent", -1))
                        .put("rootCandidate", p.optBoolean("rootCandidate"))
                        .put("cgroupAnomaly", p.optBoolean("cgroupAnomaly")).put("monitoredCandidate", true));
            }
        }
        double[] slotDeltas = null;
        if (global != null && global.optBoolean("supported")) {
            JSONArray deltas = global.optJSONArray("slotDeltas");
            if (deltas != null && deltas.length() <= 4096) {
                slotDeltas = new double[deltas.length()];
                for (int i = 0; i < deltas.length(); i++) {
                    slotDeltas[i] = global.optBoolean("sampled") && !deltas.isNull(i)
                            ? deltas.optDouble(i, Double.NaN) : Double.NaN;
                }
                JSONArray wrapped = global.optJSONArray("slotDeltaWrappedSlots");
                for (int i = 0; wrapped != null && i < wrapped.length(); i++) {
                    int slot = wrapped.optInt(i, -1);
                    if (slot >= 0 && slot < slotDeltas.length) slotDeltas[slot] = Double.NaN;
                }
            }
        }
        // CPU monitoring covers external processes. GPU lifecycle correlation keeps its original scope
        // and separate bounded state, so ordinary CPU rows cannot create GPU/root evidence.
        List<CpuGpuLifecycle.RootSample> monitoredLifecycleSamples = new ArrayList<>();
        int lifecycleEligibleCount = 0;
        for (JSONObject p : sorted) {
            if (!p.optBoolean("identityVerified") || !MonitoredProcessFilter.accepts(isSelf(p, report),
                    p.optBoolean("rootCandidate"), p.optBoolean("cgroupAnomaly"))) continue;
            lifecycleEligibleCount++;
            if (monitoredLifecycleSamples.size() < LIFECYCLE_LIMIT) monitoredLifecycleSamples.add(new CpuGpuLifecycle.RootSample(
                    p.optInt("pid"), p.optString("identityToken", ""), p.optDouble("cpuPercent", -1)));
        }
        List<CpuGpuLifecycle.ProcessEvent> processEvents = new ArrayList<>();
        for (int i = 0; nativeEvents != null && i < Math.min(nativeEvents.length(), 512); i++) {
            JSONObject event = nativeEvents.optJSONObject(i);
            if (event == null) continue;
            processEvents.add(new CpuGpuLifecycle.ProcessEvent(event.optString("type"), event.optInt("pid"),
                    event.optString("identityToken"), event.optLong("observedMonotonicNs"), event.optString("evidence")));
        }
        boolean lifecycleCoverageLimited = report.optBoolean("processEventsTruncated")
                || report.optBoolean("candidatesTruncated")
                || (nativeEvents != null && nativeEvents.length() > 512) || lifecycleEligibleCount > LIFECYCLE_LIMIT;
        // Retain known matches, but still consume trustworthy exits to retire their identities.
        if (lifecycleCoverageLimited) lifecycle.resetObservations();
        CpuGpuLifecycle.GpuSample gpuSample = new CpuGpuLifecycle.GpuSample(
                global == null ? 0 : global.optLong("sampleMonotonicNs"),
                global == null ? 0 : global.optLong("intervalNs"),
                global != null && global.optBoolean("sampled") && !lifecycleCoverageLimited,
                slotDeltas == null ? new double[0] : slotDeltas,
                intArray(global == null ? null : global.optJSONArray("appearedSlots")),
                intArray(global == null ? null : global.optJSONArray("disappearedSlots")),
                combinedSlots(global == null ? null : global.optJSONArray("resetSlots"),
                        global == null ? null : global.optJSONArray("slotDeltaWrappedSlots")),
                global == null ? 1 : global.optInt("lifecycleSlotFirst", 1),
                global == null ? 1 : global.optInt("lifecycleSlotEndExclusive", 1));
        SelfGpuFilter.Result selfFilter = selfGpuFilter.update(gpuSample.sampleMonotonicNs, gpuSample.intervalNs,
                slotDeltas == null ? 0 : slotDeltas.length, gpuSample.firstSlot, gpuSample.endExclusive,
                android.os.Process.myPid(), android.os.Process.myUid(), selfGpuQuery(global));
        GpuHighFrequency.Result frequency = highFrequency.update(gpuSample.sampleMonotonicNs, gpuSample.intervalNs,
                global != null && global.optBoolean("sampled") && selfFilter.ready, slotDeltas,
                gpuSample.firstSlot, gpuSample.endExclusive,
                gpuSample.appearedSlots, gpuSample.disappearedSlots, gpuSample.resetSlots, selfFilter.excludedSlots);
        if (global != null) global.put("highFrequency", highFrequencyJson(frequency, selfFilter));
        CpuGpuLifecycle.Update lifecycleUpdate = lifecycle.update(gpuSample, monitoredLifecycleSamples, processEvents);
        JSONArray recentLifecycleSignals = new JSONArray();
        for (CpuGpuLifecycle.Result result : lifecycleUpdate.recentExits) recentLifecycleSignals.put(lifecycleJson(result));
        report.put("recentLifecycleSignals", recentLifecycleSignals).put("lifecycleCoverageLimited", lifecycleCoverageLimited);
        report.remove("processEvents");
        for (JSONObject p : sorted) {
            CpuGpuLifecycle.Result eventResult = p.optBoolean("identityVerified")
                    ? lifecycle.confirmedOnset(p.optInt("pid"), p.optString("identityToken")) : null;
            if (eventResult == null) eventResult = lifecycleUpdate.liveResults.get(p.optInt("pid"));
            if (eventResult != null && eventResult.identityToken.equals(p.optString("identityToken"))) {
                p.put("cpuGpuLifecycle", lifecycleJson(eventResult).put("candidateScope",
                        p.optBoolean("rootCandidate") ? "root_identity" : "cgroup_named_path_mismatch"));
            }
        }
        JSONArray processes = new JSONArray();
        for (JSONObject p : sorted) processes.put(p);
        JSONArray errors = report.optJSONArray("errors");
        report.remove("avcRecentEvents");
        String status = errors != null && errors.length() > 0 ? "用户态采集中 · 部分证据受限" : "普通应用权限 · 正在采集";
        report.put("processes", processes).put("highRiskCount", high).put("suspectCount", 0)
                .put("kernelThreadExcludedCount", excludedKernelThreads.length())
                .put("excludedKernelThreads", excludedKernelThreads)
                .put("kernelDomainMismatchCount", kernelDomainMismatches)
                .put("environmentChecks", environmentChecks)
                .put("environmentAnomaly", report.optBoolean("environmentAnomaly") || kernelDomainMismatches > 0)
                .put("rootProcessCount", rootCount).put("rootWatchCount", watching)
                .put("monitoredProcessCount", sorted.size()).put("cgroupAnomalyCount", cgroupAnomalies)
                .put("cgroupWatchCount", cgroupWatching)
                .put("rootDeniedProcesses", rootDenied).put("probeScope", "all_discovered_external_processes")
                .put("cpuSamples", monitoredCpuSamples).put("cpuSampleCount", monitoredCpuSamples.length())
                .put("returnedCandidates", sorted.size())
                .put("candidateLimit", 0)
                .put("candidatesTruncated", report.optBoolean("candidatesTruncated"))
                .put("matchedCandidates", eligibleCandidates)
                .put("monitoredCandidatesTruncated", false)
                .put("monitoredEligibleCount", eligibleCandidates).put("monitoredCapacityOmissions", 0)
                .put("lifecycleEligibleCount", lifecycleEligibleCount).put("lifecycleLimit", LIFECYCLE_LIMIT)
                .put("lifecycleCapacityOmissions", Math.max(0, lifecycleEligibleCount - LIFECYCLE_LIMIT))
                .put("threshold", threshold).put("windows", windows).put("intervalMs", intervalMs)
                .put("sessionStartedAt", sessionStartedAt).put("status", status)
                .put("rule", "普通权限组合规则：目标 PID 的 AVC 拒绝日志指向 root 执行域、CPU ≥ " + threshold
                        + "% 连续 " + windows + " 次、全局 memstore 连续 " + windows + " 次推进，报告高风险（启发式）。"
                        + "监听所有可发现的外部用户态进程 CPU，包括普通和零负载进程；排除本应用、采集器、同 UID 进程及其线程，以及经校准 futex 检查确认的内核线程，页面仅显示 CPU 排序前 10 个。"
                        + "AVC 目标域为 kernel 而 futex 确认是用户态线程时显示环境异常；检查未知不触发该异常，也不据此排除。"
                        + "有效 UID 0、匹配 root 目标域和连续 3 次 cgroup 命名路径未匹配的证据单独用于风险与 GPU 生命周期观察。"
                        + "命名路径差异不表示进程没有内核 cgroup，不证明 root 身份或 GPU 归属。")
                .put("gpuEvidenceNote", "全局 GPU 活动单独报告，不分配给高 CPU 进程；普通应用不能读取的身份或设备归属保持未知。")
                .put("cpuUnit", "one_core_percent");
        return report;
    }

    private static boolean isRoot(JSONObject p) {
        return RootProcessFilter.accepts(p.optInt("uid", -1), p.optBoolean("identityVerified"),
                p.optString("identityToken", ""), p.optBoolean("avcRootDomainHint"),
                p.optString("avcTargetContext", ""), p.optString("avcIdentityToken", ""));
    }

    private static boolean isSelf(JSONObject p, JSONObject report) {
        return MonitoredProcessFilter.isSelf(p.optInt("pid", -1), p.optInt("uid", -1),
                report.optInt("collectorPid", -1), android.os.Process.myPid(), android.os.Process.myUid());
    }

    private static String processKey(JSONObject p) {
        return p.optInt("pid", -1) + ":" + p.optString("identityToken", "");
    }

    /** Merge only evidence delivered in this snapshot; never resurrect cached metadata or CPU. */
    private JSONArray mergeCurrentCpuRows(JSONObject report) throws JSONException {
        JSONArray input = report.optJSONArray("processes"), cpu = report.optJSONArray("cpuSamples");
        report.put("nativeMatchedCandidates", report.optInt("matchedCandidates", input == null ? 0 : input.length()))
                .put("nativeReturnedCandidates", input == null ? 0 : input.length())
                .put("nativeCandidatesTruncated", report.optBoolean("candidatesTruncated"));
        JSONArray merged = new JSONArray();
        Set<Integer> presentPids = new HashSet<>();
        for (int i = 0; input != null && i < input.length(); i++) {
            JSONObject row = input.getJSONObject(i);
            merged.put(row);
            presentPids.add(row.optInt("pid", -1));
        }
        Map<Integer, Integer> cpuOccurrences = new HashMap<>();
        for (int i = 0; cpu != null && i < cpu.length(); i++) {
            JSONObject row = cpu.optJSONObject(i);
            if (row != null) {
                int pid = row.optInt("pid", -1);
                cpuOccurrences.put(pid, cpuOccurrences.getOrDefault(pid, 0) + 1);
            }
        }
        int added = 0, addedRoots = 0;
        for (int i = 0; cpu != null && i < cpu.length(); i++) {
            JSONObject row = cpu.optJSONObject(i);
            if (row == null) continue;
            int pid = row.optInt("pid", -1), uid = row.optInt("uid", -1);
            String identity = row.optString("identityToken", "");
            double measuredCpu = row.optDouble("cpuPercent", -1);
            if (pid <= 0 || presentPids.contains(pid) || cpuOccurrences.get(pid) != 1
                    || !Boolean.TRUE.equals(row.opt("identityVerified")) || identity.trim().isEmpty()
                    || !Double.isFinite(measuredCpu) || measuredCpu < 0 || isSelf(row, report)) continue;
            long age = row.optLong("avcEvidenceAgeMs", -1);
            boolean freshAvc = age >= 0 && age <= AvcEvidence.MAX_AGE_MS
                    && identity.equals(row.optString("avcIdentityToken"))
                    && !row.optString("avcTargetContext").isEmpty();
            if (trustedExit(report.optJSONArray("processEvents"), pid, identity, report.optJSONObject("globalGpu"))) continue;
            JSONObject observation = new JSONObject().put("pid", pid).put("uid", uid)
                    .put("name", "PID " + pid).put("identityToken", identity).put("identityVerified", true)
                    .put("identitySource", row.optString("identitySource", "current_cpu_sample"))
                    .put("uidSource", uid < 0 ? "unknown" : row.optString("uidSource", "current_cpu_sample"))
                    .put("cpuPercent", measuredCpu).put("cpuSource", "dynamic_process_sched_clock")
                    .put("observationSource", "current_cpu_sample").put("background", "unknown")
                    .put("metadataAccessible", false).put("metadataProbeAttempted", false)
                    .put("metadataProbeState", "cpu_sample_only").put("gpuDeviceOpen", false)
                    .put("gpuActive", false).put("gpuScanComplete", false).put("gpuEvidenceReadable", false)
                    .put("cgroupCheck", new JSONObject().put("state", "UNKNOWN").put("procPresent", false)
                            .put("stableIdentity", false).put("nonZombie", false).put("pathFound", false)
                            .put("pathCalibrationValid", false).put("pathCoverageComplete", false)
                            .put("uidCoverageComplete", false).put("identityToken", identity)
                            .put("sampleIndex", report.optLong("sampleIndex", -1))
                            .put("reason", "cpu_sample_without_proc_cgroup_observation"));
            if (freshAvc) {
                java.util.Iterator<String> names = row.keys();
                while (names.hasNext()) {
                    String name = names.next();
                    if (name.startsWith("avc")) observation.put(name, row.opt(name));
                }
            }
            if (row.has("threadTypeCheck")) observation.put("threadTypeCheck", row.optJSONObject("threadTypeCheck"));
            merged.put(observation); presentPids.add(pid); added++;
            if (!isSelf(observation, report) && isRoot(observation)) addedRoots++;
        }
        report.put("cpuOnlyProcesses", added).put("cpuOnlyRootCandidates", addedRoots);
        return merged;
    }

    private static CgroupWatchPolicy.Check cgroupCheck(JSONObject check) {
        if (check == null) return null;
        for (String field : new String[]{"procPresent", "stableIdentity", "nonZombie", "pathCalibrationValid",
                "pathCoverageComplete", "uidCoverageComplete", "pathFound"}) {
            if (!(check.opt(field) instanceof Boolean)) return null;
        }
        JSONObject proc = check.optJSONObject("procEvidence");
        boolean heldIdentityLive = proc != null && Boolean.TRUE.equals(proc.opt("pidfdLiveBefore"))
                && Boolean.TRUE.equals(proc.opt("pidfdLiveAfter"));
        CgroupWatchPolicy.Paths paths = new CgroupWatchPolicy.Paths(
                Boolean.TRUE.equals(check.opt("pathCalibrationValid")), Boolean.TRUE.equals(check.opt("pathCoverageComplete")),
                Boolean.TRUE.equals(check.opt("uidCoverageComplete")), Boolean.TRUE.equals(check.opt("pathFound")),
                check.optInt("testedUidCount", -1), check.optInt("testedPathCount", -1), check.optInt("missingPathCount", -1),
                check.optLong("uidCatalogGeneration", -1), check.optString("coverageScope"));
        return new CgroupWatchPolicy.Check(check.optString("state"), Boolean.TRUE.equals(check.opt("procPresent")),
                Boolean.TRUE.equals(check.opt("stableIdentity")) && heldIdentityLive,
                Boolean.TRUE.equals(check.opt("nonZombie")), paths,
                check.optString("identityToken"), check.optLong("sampleIndex", -1), check.optString("reason"));
    }

    private boolean trustedExit(JSONArray events, int pid, String identity, JSONObject global) {
        long now = global == null ? 0 : global.optLong("sampleMonotonicNs");
        long interval = global == null ? 0 : global.optLong("intervalNs");
        if (now <= 0 || interval <= 0 || identity.isEmpty()) return false;
        CpuGpuLifecycle.Result onset = lifecycle.confirmedOnset(pid, identity);
        for (int i = 0; events != null && i < Math.min(events.length(), 512); i++) {
            JSONObject event = events.optJSONObject(i);
            if (event == null || event.optInt("pid", -1) != pid
                    || !identity.equals(event.optString("identityToken"))
                    || !"EXITED".equals(event.optString("type"))) continue;
            String evidence = event.optString("evidence");
            long time = event.optLong("observedMonotonicNs");
            if (time <= 0 || time > now + interval || now - time > 30_000_000_000L
                    || (onset != null && time <= onset.observedMonotonicNs)) continue;
            if ("pidfd_readable".equals(evidence) || "pidfd_hup".equals(evidence)
                    || "pidfd_poll_readable".equals(evidence) || "pidfd_poll_hup".equals(evidence)) return true;
        }
        return false;
    }

    private static JSONObject cgroupWatchJson(CgroupWatchPolicy.Decision decision) throws JSONException {
        return new JSONObject().put("status", decision.status).put("consecutive", decision.consecutive)
                .put("scope", "named_uid_pid_paths")
                .put("required", CgroupWatchPolicy.REQUIRED).put("first", decision.first).put("last", decision.last)
                .put("firstSampleIndex", decision.firstSampleIndex).put("lastSampleIndex", decision.lastSampleIndex)
                .put("reason", decision.reason);
    }

    private static int[] intArray(JSONArray values) {
        if (values == null) return new int[0];
        int[] result = new int[Math.min(values.length(), 4096)];
        for (int i = 0; i < result.length; i++) result[i] = values.optInt(i, -1);
        return result;
    }

    private static JSONObject lifecycleJson(CpuGpuLifecycle.Result result) throws JSONException {
        JSONArray slots = new JSONArray();
        if (result.slots != null) for (int slot : result.slots) slots.put(slot);
        return new JSONObject().put("state", result.state).put("kind", result.kind)
                .put("pid", result.pid).put("identityToken", result.identityToken).put("slots", slots)
                .put("observedMonotonicNs", result.observedMonotonicNs)
                .put("reason", result.reason.replace("root 范围", "监听范围"))
                .put("candidateScope", "root_identity_or_cgroup_named_path_mismatch").put("ownershipConfirmed", false);
    }

    private static SelfGpuFilter.Query selfGpuQuery(JSONObject global) {
        JSONObject query = global == null ? null : global.optJSONObject("selfGpuSlots");
        if (query == null) return null;
        JSONArray values = query.optJSONArray("slots");
        int[] slots = null;
        if (values != null && values.length() <= 4096) {
            slots = new int[values.length()];
            for (int i = 0; i < slots.length; i++) {
                Object value = values.opt(i);
                if (!(value instanceof Number)) return null;
                Number number = (Number) value;
                long id = number.longValue();
                if (id < Integer.MIN_VALUE || id > Integer.MAX_VALUE || number.doubleValue() != id) return null;
                slots[i] = (int) id;
            }
        }
        return new SelfGpuFilter.Query(Boolean.TRUE.equals(query.opt("complete")), slots,
                query.optInt("firstSlot", -1), query.optInt("endExclusive", -1),
                query.optLong("queryStartedMonotonicNs", 0), query.optLong("queryFinishedMonotonicNs", 0),
                query.optInt("pid", -1), query.optInt("uid", -1), query.optInt("gpuFdCount", -1));
    }

    private static JSONObject highFrequencyJson(GpuHighFrequency.Result result, SelfGpuFilter.Result selfFilter)
            throws JSONException {
        JSONArray slots = new JSONArray();
        for (GpuHighFrequency.Slot slot : result.slots) {
            slots.put(new JSONObject().put("slot", slot.id).put("ratePerSecond", slot.ratePerSecond)
                    .put("sustainedMs", slot.sustainedMs).put("sampleCount", slot.sampleCount));
        }
        JSONArray excludedSlots = new JSONArray(), currentSelfSlots = new JSONArray();
        for (int slot : selfFilter.excludedSlots) excludedSlots.put(slot);
        for (int slot : selfFilter.currentSlots) currentSelfSlots.put(slot);
        return new JSONObject().put("active", result.active).put("slots", slots)
                .put("selfFilterComplete", selfFilter.ready).put("selfFilterReason", selfFilter.reason)
                .put("selfSlotsExcluded", excludedSlots).put("currentSelfSlots", currentSelfSlots)
                .put("thresholdPerSecond", GpuHighFrequency.MIN_RATE_PER_SECOND)
                .put("requiredDurationMs", GpuHighFrequency.MIN_DURATION_MS)
                .put("minimumSamples", GpuHighFrequency.MIN_SAMPLES)
                .put("counter", "retired_increments_per_second").put("scope", "device_global_unattributed");
    }

    private static int[] combinedSlots(JSONArray first, JSONArray second) {
        int[] a = intArray(first), b = intArray(second);
        int[] result = new int[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    private static double sortableCpu(JSONObject process) {
        double cpu = process.optDouble("cpuPercent", -1);
        return Double.isFinite(cpu) && cpu >= 0 ? cpu : Double.NEGATIVE_INFINITY;
    }
}
