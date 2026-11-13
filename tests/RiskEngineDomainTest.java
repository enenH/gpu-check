package com.gpucheck.app;

import org.json.JSONArray;
import org.json.JSONObject;

/** Synthetic integration test; host runner supplies only the app's PID/UID. */
public final class RiskEngineDomainTest {
    private static int checks;
    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
    private static JSONObject frame(int sample, String identity) throws Exception {
        long time = 100_000L + sample * 1000L;
        JSONObject row = new JSONObject().put("pid", 1234).put("uid", -1).put("identityToken", identity)
                .put("identityVerified", true).put("cpuPercent", 60).put("metadataProbeAttempted", true)
                .put("selinuxEvidenceVerified", true).put("selinuxProcfsVerified", true)
                .put("selinuxIdentityToken", identity).put("selinuxSampleIndex", sample)
                .put("xattrErrno", 0).put("selinuxAttrErrno", 0).put("selinuxXattrContext", "u:r:su:s0").put("selinuxAttrContext", "u:r:su:s0")
                .put("probeEpochMs", time - 20).put("probeEndEpochMs", time - 10);
        return new JSONObject().put("sampleIndex", sample).put("elapsedMs", sample * 1000L)
                .put("timestampEpochMs", time).put("collectorPid", 5555).put("processes", new JSONArray().put(row))
                .put("globalGpu", new JSONObject().put("sampled", true).put("activityKnown", true).put("active", true));
    }
    private static JSONObject row(JSONObject frame) throws Exception { return frame.getJSONArray("processes").getJSONObject(0); }
    public static void main(String[] args) throws Exception {
        RiskEngine engine = new RiskEngine(20, 3, 1000);
        JSONObject result = null;
        for (int i = 0; i < 3; ++i) result = engine.process(frame(i, "A"));
        check(row(result).getBoolean("rootCandidate"), "direct domain must enter candidate scope");
        check("HIGH".equals(row(result).getString("risk")), "three matching windows must reach combination rule");
        check("selinux_root_domain_cpu_global_memstore".equals(row(result).getString("riskBasis")), "wrong source basis");
        check(row(result).getInt("uid") == -1, "must not invent UID zero");
        check("global_unattributed".equals(row(result).getString("gpuAttribution")), "must not invent GPU ownership");
        JSONObject export = new JSONObject(ReportExport.snapshot(result, 102001));
        check("direct_xattr_and_attr".equals(row(export).getString("domainEvidenceSource")), "export lost evidence source");
        check(row(export).getLong("selinuxSampleIndex") == 2, "export lost sample binding");

        JSONObject conflict = frame(3, "A");
        row(conflict).put("avcTargetContext", "u:r:untrusted_app:s0").put("avcIdentityToken", "A").put("avcEvidenceAgeMs", 0);
        result = engine.process(conflict);
        check(!row(result).getBoolean("rootCandidate"), "conflict must withdraw domain candidate");
        check(result.getInt("domainEvidenceConflictCount") == 1, "conflict must be visible");
        check(!result.getBoolean("environmentAnomaly"), "a changing execution domain is not proof of tampering");
        check(!row(result).has("riskBasis"), "conflict retained high-risk basis");
        result = engine.process(frame(4, "A"));
        check(!"HIGH".equals(row(result).getString("risk")), "conflict must break streak");
        result = engine.process(frame(5, "B"));
        check(row(result).getInt("consecutiveHigh") == 1, "PID reuse must reset streak");

        JSONObject stale = frame(6, "B"); row(stale).put("selinuxSampleIndex", 5);
        check(!row(engine.process(stale)).getBoolean("rootCandidate"), "replayed direct evidence accepted");
        JSONObject nonroot = frame(7, "B"); row(nonroot).put("uid", 1000);
        check(!row(engine.process(nonroot)).getBoolean("rootCandidate"), "known nonroot UID ignored");

        engine = new RiskEngine(20, 3, 1000);
        engine.process(frame(0, "C")); engine.process(frame(1, "C"));
        JSONObject unknownGpu = frame(2, "C"); unknownGpu.getJSONObject("globalGpu").put("activityKnown", false);
        check(!"HIGH".equals(row(engine.process(unknownGpu)).getString("risk")), "unknown GPU activity accepted");

        engine = new RiskEngine(20, 3, 1000);
        for (int i = 0; i < 3; ++i) {
            JSONObject avc = frame(i, "D");
            row(avc).put("metadataProbeAttempted", false).put("avcRootDomainHint", true)
                    .put("avcTargetContext", "u:r:su:s0").put("avcIdentityToken", "D").put("avcEvidenceAgeMs", 20);
            result = engine.process(avc);
        }
        check("HIGH".equals(row(result).getString("risk")), "legacy valid AVC path broken");
        check("avc_root_domain_cpu_global_memstore".equals(row(result).getString("riskBasis")), "AVC basis changed");
        System.out.println("RiskEngineDomain: " + checks + " integration checks passed.");
    }
}
