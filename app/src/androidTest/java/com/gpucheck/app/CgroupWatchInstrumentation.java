package com.gpucheck.app;

import android.app.Activity;
import android.app.Instrumentation;
import android.os.Bundle;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.concurrent.TimeUnit;

/** Real ordinary-App sampling and explicitly synthetic RiskEngine integration controls. */
public final class CgroupWatchInstrumentation extends Instrumentation {
    private static final int ANOMALY_PID = 900001;
    private static final int ROOT_PID = 900002;
    private final JSONArray controls = new JSONArray();

    @Override public void onCreate(Bundle arguments) { super.onCreate(arguments); start(); }

    @Override public void onStart() {
        Bundle result = new Bundle();
        try {
            check(android.os.Process.myUid() >= 10000, "Tests must run in an ordinary application UID");
            verifyEngine();
            verifyAllProcessCpu();
            verifySelfCpuExclusion();
            verifyCollector(result);
            File evidence = new File(getTargetContext().getFilesDir(), "cgroup-feature-controls.json");
            Files.write(evidence.toPath(), new JSONObject().put("synthetic", true)
                    .put("controls", controls).toString(2).getBytes(StandardCharsets.UTF_8));
            result.putInt("syntheticControls", controls.length());
            result.putInt("appUid", android.os.Process.myUid());
            result.putString("result", "PASS");
            finish(Activity.RESULT_OK, result);
        } catch (Throwable error) {
            result.putString("result", "FAIL");
            result.putString("error", android.util.Log.getStackTraceString(error));
            finish(Activity.RESULT_CANCELED, result);
        }
    }

    private void verifyEngine() throws Exception {
        RiskEngine engine = new RiskEngine(20, 3, 2000);
        JSONObject output = null;
        for (int sample = 0; sample < 3; sample++) {
            output = engine.process(frame(sample, row(ANOMALY_PID, -1, "held:a", 0, "MISSING", sample)));
            check(output.getInt("cgroupAnomalyCount") == (sample == 2 ? 1 : 0), "three-sample confirmation");
        }
        JSONObject observed = onlyProcess(output);
        check(observed.getBoolean("cgroupAnomaly"), "zero-CPU anomaly missing");
        check(observed.getBoolean("monitoredCandidate"), "anomaly excluded from existing monitor");
        check(output.getInt("rootProcessCount") == 0 && output.getInt("highRiskCount") == 0,
                "cgroup mismatch fabricated root/high-risk identity");
        check("WATCH".equals(observed.getString("risk")), "anomaly must use existing WATCH state");
        check("proc_cgroup_path_mismatch".equals(observed.getString("riskBasis")), "missing anomaly evidence basis");
        check(hasCpu(output, ANOMALY_PID, 0), "measured zero CPU was dropped");
        controls.put(new JSONObject().put("case", "zero_cpu_unknown_uid_admitted").put("report", output));

        output = engine.process(frame(3, row(ANOMALY_PID, -1, "held:a", 0, "PRESENT", 3)));
        check(output.getInt("monitoredProcessCount") == 1 && output.getInt("cgroupAnomalyCount") == 0,
                "path recovery must clear the anomaly without stopping CPU monitoring");
        controls.put(new JSONObject().put("case", "named_path_restored").put("report", output));

        engine = new RiskEngine(20, 3, 2000);
        for (int sample = 0; sample < 3; sample++) {
            output = engine.process(frame(sample, row(ANOMALY_PID, 20001, "held:nonroot", 0.01, "MISSING", sample)));
        }
        check(output.getInt("monitoredProcessCount") == 1 && output.getInt("rootProcessCount") == 0,
                "known nonroot mismatch should be monitored without becoming root");
        controls.put(new JSONObject().put("case", "low_cpu_known_nonroot_admitted").put("report", output));
        JSONObject restricted = frame(3, row(ANOMALY_PID, 20001, "held:nonroot", 0, "MISSING", 3));
        restricted.getJSONObject("cgroupScan").put("complete", false).put("calibrationValid", false)
                .put("errno", 13).put("status", "unavailable");
        output = engine.process(restricted);
        check(output.getInt("monitoredProcessCount") == 1 && output.getInt("cgroupAnomalyCount") == 0,
                "EACCES must clear the anomaly without stopping CPU monitoring");
        controls.put(new JSONObject().put("case", "permission_denial_resets").put("report", output));
        verifyPathEvidence();

        engine = new RiskEngine(20, 3, 2000);
        for (int sample = 0; sample < 3; sample++) {
            JSONObject conflict = row(ANOMALY_PID, -1, "held:conflict", 0, "MISSING", sample)
                    .put("identityVerified", false);
            output = engine.process(frame(sample, conflict));
        }
        check(output.getInt("cgroupAnomalyCount") == 0, "contradictory identity evidence was accepted");
        controls.put(new JSONObject().put("case", "unverified_row_identity_rejected").put("report", output));

        engine = new RiskEngine(20, 3, 2000);
        engine.process(frame(0, row(ANOMALY_PID, -1, "held:old", 0, "MISSING", 0)));
        engine.process(frame(1, row(ANOMALY_PID, -1, "held:old", 0, "MISSING", 1)));
        output = engine.process(frame(2, row(ANOMALY_PID, -1, "held:new", 0, "MISSING", 2)));
        check(output.getInt("cgroupAnomalyCount") == 0, "PID reuse inherited previous anomaly evidence");
        controls.put(new JSONObject().put("case", "pid_reuse_resets").put("report", output));
        output = engine.process(frame(4, row(ANOMALY_PID, -1, "held:new", 0, "MISSING", 4)));
        check(output.getInt("cgroupAnomalyCount") == 0, "skipped sample counted as consecutive");
        controls.put(new JSONObject().put("case", "skipped_sample_resets").put("report", output));

        engine = new RiskEngine(20, 3, 2000);
        for (int sample = 0; sample < 3; sample++) {
            JSONObject self = row(ANOMALY_PID, android.os.Process.myUid(), "held:self", 99, "MISSING", sample);
            output = engine.process(frame(sample, self));
        }
        check(output.getInt("monitoredProcessCount") == 0 && output.getInt("cpuSampleCount") == 0
                        && output.getInt("rootProcessCount") == 0 && output.getInt("cgroupAnomalyCount") == 0,
                "same-UID process was retained in CPU monitoring");
        controls.put(new JSONObject().put("case", "own_uid_cpu_excluded").put("report", output));

        // A confirmed root HIGH row must not override the user's CPU ordering.
        engine = new RiskEngine(20, 3, 2000);
        for (int sample = 0; sample < 3; sample++) {
            JSONObject root = row(ROOT_PID, 0, "held:root", 30, "PRESENT", sample)
                    .put("background", "background").put("gpuDeviceOpen", true)
                    .put("gpuActive", true).put("gpuEvidenceReadable", true);
            output = engine.process(frame(sample,
                    row(ANOMALY_PID, -1, "held:busy", 70, "MISSING", sample), root));
        }
        JSONArray ordered = output.getJSONArray("processes");
        check(ordered.length() == 2 && ordered.getJSONObject(0).getInt("pid") == ANOMALY_PID,
                "mixed root/anomaly list was not sorted by CPU");
        check(output.getInt("rootProcessCount") == 1 && output.getInt("monitoredProcessCount") == 2,
                "root and anomaly counts were conflated");
        controls.put(new JSONObject().put("case", "shared_cpu_order").put("report", output));
        output = engine.process(frame(3, row(ANOMALY_PID, -1, "held:busy", -1, "MISSING", 3),
                row(ROOT_PID, 0, "held:root", 0, "PRESENT", 3)));
        check(output.getJSONArray("processes").getJSONObject(1).getInt("pid") == ANOMALY_PID,
                "unknown CPU was not sorted last");
        controls.put(new JSONObject().put("case", "unknown_cpu_last").put("report", output));

        output = engine.process(frame(4));
        check(output.getInt("cgroupAnomalyCount") == 0 && output.getInt("monitoredProcessCount") == 0,
                "missing/retired process remained in monitor");
        controls.put(new JSONObject().put("case", "missing_process_removed").put("report", output));
        verifyCpuOnlyRoots();
        verifyMixedCapacity();
    }

    private void verifyCpuOnlyRoots() throws Exception {
        RiskEngine engine = new RiskEngine(20, 3, 2000);
        JSONObject busy = row(ROOT_PID, 0, "held:idle", 60, "PRESENT", 0)
                .put("name", "previous name must not be reused").put("background", "background")
                .put("gpuDeviceOpen", true).put("gpuActive", true).put("gpuEvidenceReadable", true);
        engine.process(frame(0, busy));
        JSONObject idle = rootCpu(ROOT_PID, "held:idle", 0, 2000)
                .put("name", "not CPU evidence").put("background", "background")
                .put("gpuDeviceOpen", true).put("gpuActive", true).put("gpuEvidenceReadable", true);
        JSONObject output = engine.process(cpuOnlyFrame(1, idle));
        JSONObject observed = onlyProcess(output);
        check(hasCpu(output, ROOT_PID, 0) && observed.getDouble("cpuPercent") == 0,
                "live idle root disappeared from the shared queue");
        check(output.getInt("cpuOnlyRootCandidates") == 1 && output.getInt("rootProcessCount") == 1,
                "CPU-only root admission count is wrong");
        check(observed.getInt("uid") == -1 && observed.getString("name").equals("PID " + ROOT_PID)
                        && "unknown".equals(observed.getString("background"))
                        && !observed.getBoolean("gpuDeviceOpen") && !observed.getBoolean("gpuActive")
                        && !observed.getBoolean("gpuEvidenceReadable") && output.getInt("highRiskCount") == 0,
                "CPU-only admission borrowed UID/name/GPU metadata");
        controls.put(new JSONObject().put("case", "real_idle_regression_cpu_only_root").put("report", output));

        output = engine.process(cpuOnlyFrame(2, rootCpu(ROOT_PID, "held:idle", 0.001, 4000)));
        check(onlyProcess(output).getDouble("cpuPercent") == 0.001, "low CPU root was dropped");
        output = engine.process(cpuOnlyFrame(3));
        check(output.getInt("monitoredProcessCount") == 0, "missing current CPU was replaced with cached zero");
        controls.put(new JSONObject().put("case", "cpu_only_root_missing_sample_removed").put("report", output));

        output = engine.process(cpuOnlyFrame(4, rootCpu(ROOT_PID, "held:idle", 0, 30001)));
        check(output.getInt("monitoredProcessCount") == 1 && output.getInt("rootProcessCount") == 0,
                "expired AVC must clear root identity without dropping CPU");
        output = engine.process(cpuOnlyFrame(5, rootCpu(ROOT_PID, "held:idle", 0, 0).put("avcRootDomainHint", false)));
        check(output.getInt("monitoredProcessCount") == 1 && output.getInt("rootProcessCount") == 0,
                "missing root evidence was replaced by cached identity");
        controls.put(new JSONObject().put("case", "cpu_only_avc_expiry_not_extended").put("report", output));

        for (JSONObject invalid : new JSONObject[]{
                rootCpu(ROOT_PID, "held:idle", 0, 0).put("identityVerified", false),
                rootCpu(ROOT_PID, "held:idle", -1, 0)}) {
            check(new RiskEngine(20, 3, 2000).process(cpuOnlyFrame(0, invalid)).getInt("monitoredProcessCount") == 0,
                    "invalid CPU-only row admitted");
        }
        for (JSONObject ordinary : new JSONObject[]{
                rootCpu(ROOT_PID, "held:idle", 0, 0).put("avcIdentityToken", "held:different"),
                rootCpu(ROOT_PID, "held:idle", 0, 0).put("uid", 20001)}) {
            JSONObject cpuReport = new RiskEngine(20, 3, 2000).process(cpuOnlyFrame(0, ordinary));
            check(cpuReport.getInt("monitoredProcessCount") == 1 && cpuReport.getInt("rootProcessCount") == 0,
                    "ordinary CPU sample was excluded or promoted to root");
        }
        controls.put(new JSONObject().put("case", "cpu_only_invalid_evidence_rejected").put("passed", true));

        JSONObject explicitNonroot = frame(0, row(ROOT_PID, 20001, "held:idle", 0, "PRESENT", 0));
        explicitNonroot.put("cpuSamples", new JSONArray().put(rootCpu(ROOT_PID, "held:idle", 0, 0)));
        output = new RiskEngine(20, 3, 2000).process(explicitNonroot);
        check(output.getInt("monitoredProcessCount") == 1 && output.getInt("cpuSampleCount") == 1
                        && output.getInt("rootProcessCount") == 0,
                "CPU-only root overrode current nonroot process metadata");
        JSONObject replaced = frame(0, row(ROOT_PID, 20001, "held:new", 0, "PRESENT", 0));
        replaced.put("cpuSamples", new JSONArray().put(rootCpu(ROOT_PID, "held:old", 0, 0)));
        output = new RiskEngine(20, 3, 2000).process(replaced);
        check(output.getInt("monitoredProcessCount") == 1 && output.getInt("cpuSampleCount") == 1
                        && "held:new".equals(onlyProcess(output).getString("identityToken")),
                "CPU-only row overrode a replacement PID identity");
        controls.put(new JSONObject().put("case", "cpu_only_current_process_identity_wins").put("report", output));

        JSONObject duplicate = cpuOnlyFrame(0, rootCpu(ROOT_PID, "held:a", 0, 0), rootCpu(ROOT_PID, "held:b", 0, 0));
        check(new RiskEngine(20, 3, 2000).process(duplicate).getInt("monitoredProcessCount") == 0,
                "conflicting CPU-only identities admitted");
        JSONObject exited = cpuOnlyFrame(0, rootCpu(ROOT_PID, "held:exit", 0, 0));
        exited.put("processEvents", new JSONArray().put(new JSONObject().put("type", "EXITED")
                .put("pid", ROOT_PID).put("identityToken", "held:exit").put("observedMonotonicNs", 2_000_000_000L)
                .put("evidence", "pidfd_readable")));
        check(new RiskEngine(20, 3, 2000).process(exited).getInt("monitoredProcessCount") == 0,
                "verified exit was overridden by a CPU-only row");
        controls.put(new JSONObject().put("case", "cpu_only_duplicate_and_exit_rejected").put("passed", true));

        JSONObject currentUid = rootCpu(ROOT_PID, "held:numeric", 60, 30001).put("uid", 0)
                .put("gpuDeviceOpen", true).put("gpuActive", true).put("gpuEvidenceReadable", true);
        output = new RiskEngine(20, 3, 2000).process(cpuOnlyFrame(0, currentUid));
        check(output.getInt("rootProcessCount") == 1 && output.getInt("highRiskCount") == 0
                        && !onlyProcess(output).optBoolean("avcRootDomainHint"),
                "expired AVC or copied GPU evidence promoted current numeric UID root");

        JSONArray many = new JSONArray();
        for (int i = 0; i < 1200; i++) many.put(rootCpu(1000000 + i, "held:capacity:" + i, i, 0));
        JSONObject full = frame(0).put("cpuSamples", many).put("matchedCandidates", 0).put("candidatesTruncated", false);
        output = new RiskEngine(20, 3, 2000).process(full);
        JSONArray retained = output.getJSONArray("processes");
        check(retained.length() == 1200 && output.getInt("returnedCandidates") == 1200
                        && output.getInt("monitoredProcessCount") == 1200 && output.getInt("rootProcessCount") == 1200
                        && output.getInt("cpuSampleCount") == 1200 && output.getInt("matchedCandidates") == 1200
                        && output.getInt("monitoredEligibleCount") == 1200 && output.getInt("monitoredCapacityOmissions") == 0
                        && !output.getBoolean("candidatesTruncated") && output.getBoolean("lifecycleCoverageLimited")
                        && output.getInt("lifecycleCapacityOmissions") == 176,
                "CPU queue was truncated or lifecycle capacity was not reported separately");
        for (int i = 0; i < retained.length(); i++) {
            check(retained.getJSONObject(i).getInt("pid") == 1001199 - i
                            && retained.getJSONObject(i).getDouble("cpuPercent") == 1199 - i,
                    "merged capacity selection was not CPU-descending at index " + i);
        }
        controls.put(new JSONObject().put("case", "cpu_only_merge_cpu_order_and_capacity").put("report", output));
        output = new RiskEngine(20, 3, 2000).process(cpuOnlyFrame(0,
                rootCpu(ROOT_PID + 1, "held:tie1", 0, 0), rootCpu(ROOT_PID, "held:tie0", 0, 0)));
        check(output.getJSONArray("processes").getJSONObject(0).getInt("pid") == ROOT_PID,
                "same-CPU merge did not use ascending PID order");
    }

    private void verifyMixedCapacity() throws Exception {
        RiskEngine engine = new RiskEngine(20, 3, 2000);
        JSONObject output = null;
        final int count = 700, idlePid = 1200000 + count - 1;
        for (int sample = 0; sample < 3; sample++) {
            JSONObject[] rows = new JSONObject[count + 1];
            for (int i = 0; i < count; i++) {
                rows[i] = row(1200000 + i, -1, "held:mixed:" + i, i == count - 1 ? 0 : i % 30,
                        "MISSING", sample);
            }
            rows[count] = row(ROOT_PID, 0, "held:mixed-root", 200, "PRESENT", sample);
            output = engine.process(frame(sample, rows));
        }
        JSONArray retained = output.getJSONArray("processes");
        check(retained.length() == count + 1 && output.getInt("monitoredEligibleCount") == count + 1
                        && output.getInt("cgroupAnomalyCount") == count && output.getInt("rootProcessCount") == 1
                        && output.getInt("monitoredCapacityOmissions") == 0
                        && !output.getBoolean("candidatesTruncated") && !output.getBoolean("lifecycleCoverageLimited"),
                "more than 128 valid mixed candidates caused artificial truncation or coverage loss");
        check(retained.getJSONObject(0).getInt("pid") == ROOT_PID && hasCpu(output, idlePid, 0),
                "mixed candidate set dropped the busy root or idle anomaly");
        double previousCpu = Double.POSITIVE_INFINITY;
        int previousPid = -1;
        boolean idleSeen = false;
        for (int i = 0; i < retained.length(); i++) {
            JSONObject process = retained.getJSONObject(i);
            double cpu = process.getDouble("cpuPercent");
            int pid = process.getInt("pid");
            check(cpu < previousCpu || (cpu == previousCpu && pid > previousPid),
                    "mixed candidate order was not CPU-descending with PID tie-breaking");
            check(process.has("cpuGpuLifecycle"), "lifecycle dropped a retained identity inside the supported capacity");
            if (pid == idlePid) idleSeen = process.getDouble("cpuPercent") == 0;
            previousCpu = cpu; previousPid = pid;
        }
        check(idleSeen, "zero-CPU anomaly was removed by the previous 128-row limit");
        controls.put(new JSONObject().put("case", "mixed_paths_and_root_capacity_without_coverage_loss").put("report", output));

        JSONObject nativeTruncated = frame(0, row(ROOT_PID, 0, "held:native-limit", 50, "PRESENT", 0))
                .put("candidatesTruncated", true);
        output = new RiskEngine(20, 3, 2000).process(nativeTruncated);
        check(output.getBoolean("lifecycleCoverageLimited") && output.getBoolean("nativeCandidatesTruncated")
                        && output.getInt("monitoredCapacityOmissions") == 0,
                "native candidate truncation was lost when Java had no additional omissions");
        controls.put(new JSONObject().put("case", "native_candidate_truncation_limits_lifecycle").put("report", output));
    }

    private void verifyAllProcessCpu() throws Exception {
        JSONObject[] ordinary = new JSONObject[1200];
        for (int i = 0; i < ordinary.length; i++) {
            ordinary[i] = row(2000000 + i, 20001, "held:ordinary:" + i, i / 1000.0, "PRESENT", 0);
        }
        RiskEngine engine = new RiskEngine(20, 3, 2000);
        JSONObject output = engine.process(frame(0, ordinary));
        check(output.getInt("monitoredProcessCount") == 1200 && output.getInt("cpuSampleCount") == 1200,
                "normal/low/zero CPU processes were filtered or capped");
        check(output.getInt("rootProcessCount") == 0 && output.getInt("cgroupAnomalyCount") == 0
                        && output.getInt("highRiskCount") == 0 && !output.getBoolean("lifecycleCoverageLimited")
                        && output.getInt("lifecycleEligibleCount") == 0,
                "ordinary CPU monitoring polluted risk/lifecycle scope");
        check("MONITORING".equals(output.getJSONArray("processes").getJSONObject(0).getString("risk")),
                "ordinary CPU sample mislabeled as a risk candidate");
        List<JSONObject> leaders = MainActivity.cpuLeaders(output.getJSONArray("processes"), -1);
        check(leaders.size() == 10 && leaders.get(0).getInt("pid") == 2001199
                        && leaders.get(9).getInt("pid") == 2001190, "UI did not choose the global top ten");
        // A previously idle process outside the displayed ten must immediately enter after a burst.
        ordinary[0].put("cpuPercent", 150);
        output = engine.process(frame(1, ordinary));
        leaders = MainActivity.cpuLeaders(output.getJSONArray("processes"), -1);
        check(output.getInt("monitoredProcessCount") == 1200 && leaders.size() == 10
                        && leaders.get(0).getInt("pid") == 2000000 && leaders.get(9).getInt("pid") == 2001191,
                "an undisplayed process stopped sampling or failed to enter top ten");
        JSONArray few = new JSONArray().put(row(8, -1, "unknown", -1, "UNKNOWN", 0))
                .put(row(7, 20001, "idle", 0, "PRESENT", 0))
                .put(row(6, 20001, "low-b", 0.01, "PRESENT", 0))
                .put(row(5, 20001, "low-a", 0.01, "PRESENT", 0));
        leaders = MainActivity.cpuLeaders(few, -1);
        check(leaders.size() == 4 && leaders.get(0).getInt("pid") == 5 && leaders.get(1).getInt("pid") == 6
                        && leaders.get(2).getInt("pid") == 7 && leaders.get(3).getInt("pid") == 8,
                "low/zero/unknown CPU sorting or PID tie break is wrong");
        check(few.length() == 4 && MainActivity.cpuLeaders(new JSONArray(), -1).isEmpty(), "leader selection changed the report");
        controls.put(new JSONObject().put("case", "all_process_cpu_and_top_ten").put("passed", true));
    }

    private void verifySelfCpuExclusion() throws Exception {
        int collector = 910001, ownUid = android.os.Process.myUid();
        JSONObject[] self = new JSONObject[]{
                row(android.os.Process.myPid(), -1, "held:app", 1000, "PRESENT", 0),
                row(collector, -1, "held:collector", 900, "PRESENT", 0),
                row(910002, ownUid, "held:shared-uid", 800, "PRESENT", 0),
                row(910003, ownUid, "held:thread", 700, "PRESENT", 0)};
        JSONObject report = new RiskEngine(20, 3, 2000).process(frame(0, self).put("collectorPid", collector));
        check(report.getInt("monitoredProcessCount") == 0 && report.getInt("cpuSampleCount") == 0,
                "App/collector/shared-UID/thread leaked into CPU output");
        report = new RiskEngine(20, 3, 2000).process(cpuOnlyFrame(0, self).put("collectorPid", collector));
        check(report.getInt("monitoredProcessCount") == 0 && report.getInt("cpuSampleCount") == 0,
                "CPU-only merge resurrected self");
        JSONArray rows = new JSONArray();
        for (JSONObject own : self) rows.put(own);
        for (int i = 0; i < 12; i++) rows.put(row(920000 + i, -1, "held:external:" + i, i, "PRESENT", 0));
        List<JSONObject> leaders = MainActivity.cpuLeaders(rows, collector);
        check(leaders.size() == 10 && leaders.get(0).getInt("pid") == 920011
                        && leaders.get(9).getInt("pid") == 920002 && rows.length() == 16,
                "UI capped before excluding self or failed to fill the external top ten");
        controls.put(new JSONObject().put("case", "self_cpu_excluded_at_all_layers").put("passed", true));
    }

    private void verifyPathEvidence() throws Exception {
        for (String invalid : new String[]{"pathCalibrationValid", "pathCoverageComplete", "uidCoverageComplete",
                "pidfdLiveBefore", "pidfdLiveAfter", "pathFound", "missingPathCount", "uidCatalogGeneration",
                "coverageScope", "method"}) {
            RiskEngine engine = new RiskEngine(20, 3, 2000);
            JSONObject output = null;
            for (int sample = 0; sample < 3; sample++) {
                JSONObject item = row(ANOMALY_PID, -1, "held:path", 0, "MISSING", sample);
                JSONObject frame = frame(sample, item);
                JSONObject evidence = item.getJSONObject("cgroupCheck");
                if (invalid.startsWith("pidfd")) evidence.getJSONObject("procEvidence").put(invalid, false);
                else if ("pathFound".equals(invalid)) evidence.put(invalid, true);
                else if ("missingPathCount".equals(invalid)) evidence.put(invalid, 1);
                else if ("uidCatalogGeneration".equals(invalid)) evidence.put(invalid, -1);
                else if ("coverageScope".equals(invalid)) evidence.put(invalid, "all_kernel_memberships");
                else if ("method".equals(invalid)) frame.getJSONObject("cgroupScan").put(invalid, "membership_scan");
                else evidence.put(invalid, false);
                output = engine.process(frame);
                check(output.getInt("cgroupAnomalyCount") == 0, "invalid path evidence accepted: " + invalid);
            }
            controls.put(new JSONObject().put("case", "invalid_path_" + invalid).put("report", output));
        }

        RiskEngine engine = new RiskEngine(20, 3, 2000);
        JSONObject output = null;
        for (int sample = 0; sample < 3; sample++) {
            JSONObject item = row(ANOMALY_PID, -1, "held:catalog", 0, "MISSING", sample);
            item.getJSONObject("cgroupCheck").put("uidCatalogGeneration", sample < 2 ? 7 : 8);
            output = engine.process(frame(sample, item));
        }
        check(output.getInt("cgroupAnomalyCount") == 0, "new catalog inherited old confirmation");
        controls.put(new JSONObject().put("case", "catalog_change_resets").put("report", output));

        // A budget-limited batch may contain one completely checked PID. Its per-PID coverage
        // is sufficient; an unrelated unvisited PID must not invalidate the completed check.
        engine = new RiskEngine(20, 3, 2000);
        for (int sample = 0; sample < 3; sample++) {
            JSONObject partial = frame(sample, row(ANOMALY_PID, -1, "held:complete-row", 0, "MISSING", sample));
            partial.getJSONObject("cgroupScan").put("complete", false).put("status", "partial");
            output = engine.process(partial);
        }
        check(output.getInt("cgroupAnomalyCount") == 1, "complete PID was discarded due to unrelated batch limits");
        controls.put(new JSONObject().put("case", "complete_pid_in_partial_batch").put("report", output));
    }

    private static JSONObject rootCpu(int pid, String identity, double cpu, long avcAge) throws Exception {
        return new JSONObject().put("pid", pid).put("identityVerified", true).put("identityToken", identity)
                .put("cpuPercent", cpu).put("avcRootDomainHint", true).put("avcTargetContext", "u:r:magisk:s0")
                .put("avcIdentityToken", identity).put("avcEvidenceAgeMs", avcAge);
    }

    private static JSONObject cpuOnlyFrame(int sample, JSONObject... rows) throws Exception {
        JSONArray cpu = new JSONArray();
        for (JSONObject row : rows) cpu.put(row);
        return frame(sample).put("cpuSamples", cpu);
    }

    private void verifyCollector(Bundle result) throws Exception {
        File files = getTargetContext().getFilesDir();
        File binary = new File(getTargetContext().getApplicationInfo().nativeLibraryDir, "libgpu_probe.so");
        File selfOutput = new File(files, "cgroup-native-selftest.json");
        run(binary, selfOutput, new File(files, "cgroup-native-selftest.err"), "--self-test");
        check(new JSONObject(new String(Files.readAllBytes(selfOutput.toPath()), StandardCharsets.UTF_8))
                .getBoolean("selfTest"), "native self-test failed");

        File output = new File(files, "cgroup-real.jsonl");
        // A second, independent same-UID process must also be excluded, not just the
        // collector PID and its App parent. No root shell or external target is used.
        java.lang.Process sibling = new ProcessBuilder("/system/bin/sh", "-c", "echo $$; exec /system/bin/sleep 20").start();
        int siblingPid;
        try (java.io.BufferedReader reader = new java.io.BufferedReader(
                new java.io.InputStreamReader(sibling.getInputStream(), StandardCharsets.UTF_8))) {
            siblingPid = Integer.parseInt(reader.readLine().trim());
            check(siblingPid > 0 && sibling.isAlive(), "same-UID test process failed to start");
            String status = new String(Files.readAllBytes(new File("/proc/" + siblingPid + "/status").toPath()), StandardCharsets.UTF_8);
            check(status.matches("(?s).*\\nUid:\\s+" + android.os.Process.myUid() + "\\s+"
                    + android.os.Process.myUid() + "\\s+.*"), "test process did not inherit the App UID");
            run(binary, output, new File(files, "cgroup-real.err"), "--samples", "5", "--interval-ms", "1000");
            check(sibling.isAlive(), "same-UID test process exited before capture ended");
        } finally {
            sibling.destroy();
            if (!sibling.waitFor(3, TimeUnit.SECONDS)) sibling.destroyForcibly();
        }
        List<String> lines = Files.readAllLines(output.toPath(), StandardCharsets.UTF_8);
        check(lines.size() == 5, "native sample count differs from requested five");
        RiskEngine engine = new RiskEngine(20, 3, 1000);
        StringBuilder processed = new StringBuilder();
        int incomplete = 0, available = 0, missingObservations = 0, maxAnomalies = 0;
        long maxCollectionMs = 0, maxCgroupMs = 0;
        for (String line : lines) {
            JSONObject raw = new JSONObject(line);
            check(!raw.getBoolean("root") && raw.getInt("collectorUid") == android.os.Process.myUid(),
                    "collector did not run in the ordinary application UID");
            assertSelfExcluded(raw, siblingPid);
            check(raw.getJSONObject("capabilities").getString("collectorSelinux").contains(":untrusted_app:"),
                    "collector did not use actual untrusted_app domain");
            JSONObject scan = raw.getJSONObject("cgroupScan");
            check(CgroupWatchPolicy.METHOD.equals(scan.getString("method")), "collector used the obsolete membership method");
            if (!scan.getBoolean("complete")) incomplete++;
            if (scan.getBoolean("available")) {
                check(scan.getBoolean("calibrationValid"), "available path probe lacked calibration");
                available++;
            }
            JSONArray processes = raw.getJSONArray("processes");
            for (int i = 0; i < processes.length(); i++) {
                JSONObject process = processes.getJSONObject(i);
                JSONObject evidence = process.getJSONObject("cgroupCheck");
                if ("MISSING".equals(evidence.getString("state"))) {
                    validateMissing(process, evidence);
                    missingObservations++;
                }
            }
            maxCollectionMs = Math.max(maxCollectionMs, raw.optLong("collectionMs"));
            maxCgroupMs = Math.max(maxCgroupMs, scan.optLong("durationMs"));
            JSONObject report = engine.process(raw);
            assertSelfExcluded(report, siblingPid);
            maxAnomalies = Math.max(maxAnomalies, report.getInt("cgroupAnomalyCount"));
            JSONArray monitored = report.getJSONArray("processes");
            double lastCpu = Double.POSITIVE_INFINITY;
            for (int i = 0; i < monitored.length(); i++) {
                JSONObject process = monitored.getJSONObject(i);
                double cpu = process.optDouble("cpuPercent", -1);
                if (cpu < 0 || !Double.isFinite(cpu)) cpu = -1;
                check(cpu <= lastCpu, "actual unified queue was not sorted by CPU");
                lastCpu = cpu;
                if (process.optBoolean("cgroupAnomaly")) {
                    validateMissing(process, process.getJSONObject("cgroupCheck"));
                    check(process.getJSONObject("cgroupWatch").getInt("consecutive") >= 3,
                            "actual anomaly lacked continuous confirmation");
                }
            }
            processed.append(report).append('\n');
        }
        check(available >= 3, "stat UID/PID path probe was not available for three ordinary-App samples");
        Files.write(new File(files, "cgroup-real-processed.jsonl").toPath(),
                processed.toString().getBytes(StandardCharsets.UTF_8));
        result.putInt("realSamples", lines.size());
        result.putInt("excludedSameUidTestPid", siblingPid);
        result.putBoolean("selfCpuExclusionVerified", true);
        result.putInt("incompleteCgroupSamples", incomplete);
        result.putInt("availablePathSamples", available);
        result.putInt("missingPathObservations", missingObservations);
        result.putInt("maxPathAnomalies", maxAnomalies);
        result.putLong("maxCollectionMs", maxCollectionMs);
        result.putLong("maxCgroupMs", maxCgroupMs);
    }

    static void assertSelfExcluded(JSONObject report, int siblingPid) throws Exception {
        java.util.Set<Integer> ownIds = new java.util.HashSet<>();
        ownIds.add(android.os.Process.myPid());
        ownIds.add(report.getInt("collectorPid"));
        if (siblingPid > 0) ownIds.add(siblingPid);
        String[] tasks = new File("/proc/self/task").list();
        check(tasks != null && tasks.length > 0, "cannot enumerate App threads for verification");
        for (String tid : tasks) ownIds.add(Integer.parseInt(tid));
        for (String key : new String[]{"processes", "cpuSamples", "processEvents"}) {
            JSONArray rows = report.optJSONArray(key);
            for (int i = 0; rows != null && i < rows.length(); i++) {
                JSONObject row = rows.getJSONObject(i);
                check(!ownIds.contains(row.getInt("pid")) && row.optInt("uid", -1) != android.os.Process.myUid(),
                        "own process/thread leaked into " + key + ": " + row.getInt("pid"));
            }
        }
        check(report.getInt("cpuExclusionUid") == android.os.Process.myUid()
                        && report.getInt("cpuExcludedPidTidCount") >= 2,
                "collector did not report its self exclusion scope");
    }

    private static void validateMissing(JSONObject process, JSONObject evidence) throws Exception {
        JSONObject proc = evidence.getJSONObject("procEvidence");
        check(process.getBoolean("identityVerified") && evidence.getBoolean("procPresent")
                        && evidence.getBoolean("stableIdentity") && evidence.getBoolean("nonZombie")
                        && proc.getBoolean("pidfdLiveBefore") && proc.getBoolean("pidfdLiveAfter")
                        && process.getString("identityToken").equals(evidence.getString("identityToken")),
                "missing-path observation lacked a stable live PID identity");
        check(evidence.getBoolean("pathCalibrationValid") && evidence.getBoolean("pathCoverageComplete")
                        && evidence.getBoolean("uidCoverageComplete") && !evidence.getBoolean("pathFound")
                        && evidence.getInt("testedUidCount") > 0
                        && evidence.getInt("testedPathCount") >= evidence.getInt("testedUidCount")
                        && evidence.getInt("missingPathCount") == evidence.getInt("testedPathCount")
                        && evidence.getLong("uidCatalogGeneration") >= 0
                        && CgroupWatchPolicy.SCOPE.equals(evidence.getString("coverageScope")),
                "missing-path observation lacked calibrated complete scope coverage");
    }

    private static void run(File binary, File output, File errors, String... args) throws Exception {
        java.util.List<String> command = new java.util.ArrayList<>();
        command.add(binary.getAbsolutePath());
        java.util.Collections.addAll(command, args);
        java.lang.Process child = new ProcessBuilder(command).redirectOutput(output).redirectError(errors).start();
        try {
            check(child.waitFor(25, TimeUnit.SECONDS), "native test exceeded its deadline");
            check(child.exitValue() == 0, "native test returned " + child.exitValue());
        } finally {
            if (child.isAlive()) child.destroyForcibly();
        }
    }

    private static JSONObject row(int pid, int uid, String identity, double cpu, String state, int sample)
            throws Exception {
        JSONObject check = new JSONObject().put("state", state).put("procPresent", true)
                .put("stableIdentity", true).put("nonZombie", true).put("pathCalibrationValid", true)
                .put("pathCoverageComplete", true).put("uidCoverageComplete", true)
                .put("pathFound", "PRESENT".equals(state)).put("identityToken", identity)
                .put("testedUidCount", 5).put("testedPathCount", 5)
                .put("missingPathCount", "PRESENT".equals(state) ? 4 : 5)
                .put("uidCatalogGeneration", 7).put("coverageScope", CgroupWatchPolicy.SCOPE)
                .put("procEvidence", new JSONObject().put("pidfdLiveBefore", true).put("pidfdLiveAfter", true))
                .put("sampleIndex", sample).put("reason", "synthetic test control");
        return new JSONObject().put("pid", pid).put("uid", uid).put("identityVerified", true)
                .put("identityToken", identity).put("identitySource", "held_pidfd")
                .put("cpuPercent", cpu).put("startTimeTicks", 123).put("name", "synthetic control")
                .put("cgroupCheck", check).put("background", "unknown");
    }

    private static JSONObject frame(int sample, JSONObject... rows) throws Exception {
        JSONArray processes = new JSONArray(), cpu = new JSONArray();
        for (JSONObject row : rows) {
            processes.put(row);
            cpu.put(new JSONObject(row.toString()));
        }
        return new JSONObject().put("sampleIndex", sample).put("elapsedMs", sample * 2000L)
                .put("intervalMs", 2000).put("collectorPid", android.os.Process.myPid())
                .put("collectorUid", android.os.Process.myUid()).put("root", false)
                .put("processes", processes).put("cpuSamples", cpu).put("processEvents", new JSONArray())
                .put("globalGpu", new JSONObject().put("supported", false).put("sampled", false)
                        .put("sampleMonotonicNs", (sample + 1L) * 2_000_000_000L).put("intervalNs", 2_000_000_000L))
                .put("cgroupScan", new JSONObject().put("complete", true).put("available", true)
                        .put("calibrationValid", true).put("method", CgroupWatchPolicy.METHOD)
                        .put("errno", 0).put("status", "complete").put("sampleIndex", sample));
    }

    private static JSONObject onlyProcess(JSONObject report) throws Exception {
        check(report.getJSONArray("processes").length() == 1, "expected exactly one monitored process");
        return report.getJSONArray("processes").getJSONObject(0);
    }

    private static boolean hasCpu(JSONObject report, int pid, double expected) throws Exception {
        JSONArray samples = report.getJSONArray("cpuSamples");
        for (int i = 0; i < samples.length(); i++) {
            JSONObject row = samples.getJSONObject(i);
            if (row.getInt("pid") == pid && row.getDouble("cpuPercent") == expected) return true;
        }
        return false;
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
