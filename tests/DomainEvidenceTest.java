package com.gpucheck.app;

import org.json.JSONObject;

public final class DomainEvidenceTest {
    private static int passed;
    private static JSONObject row() throws Exception {
        return new JSONObject().put("uid", -1).put("identityVerified", true).put("identityToken", "pid:42:A")
                .put("metadataProbeAttempted", true).put("selinuxEvidenceVerified", true)
                .put("selinuxProcfsVerified", true).put("selinuxIdentityToken", "pid:42:A")
                .put("selinuxSampleIndex", 7).put("probeEpochMs", 1000).put("probeEndEpochMs", 1100)
                .put("xattrErrno", 0).put("selinuxAttrErrno", 0).put("selinuxXattrContext", "u:r:su:s0").put("selinuxAttrContext", "u:r:su:s0");
    }
    private static JSONObject avc(JSONObject p, String context) throws Exception {
        return p.put("avcTargetContext", context).put("avcIdentityToken", "pid:42:A")
                .put("avcEvidenceAgeMs", 50).put("avcRootDomainHint", RootProcessFilter.rootContext(context));
    }
    private static void expect(JSONObject p, long timestamp, long sample, String state, boolean root) throws Exception {
        int originalUid = p.optInt("uid", -1);
        DomainEvidence.Result r = DomainEvidence.apply(p, timestamp, sample);
        if (!state.equals(r.state) || r.root != root) throw new AssertionError(p.toString());
        if (p.optInt("uid", -1) < 0 && DomainEvidence.accepts(p) != root) throw new AssertionError("scope mismatch");
        if (p.optInt("uid", -1) != originalUid) throw new AssertionError("invented UID");
        passed++;
    }
    private static void expect(JSONObject p, String state, boolean root) throws Exception { expect(p, 1200, 7, state, root); }
    public static void main(String[] args) throws Exception {
        expect(row(), "VALID", true);
        expect(row().put("xattrErrno", 13).put("selinuxAttrErrno", 13), "UNKNOWN", false);
        expect(row().put("xattrErrno", 13), "VALID", true);
        expect(row().put("selinuxAttrErrno", 13), "VALID", true);
        expect(row().put("selinuxXattrContext", ""), "VALID", true);
        expect(row().put("selinuxAttrContext", ""), "VALID", true);
        expect(row().put("selinuxXattrContext", "").put("selinuxAttrContext", ""), "UNKNOWN", false);
        expect(row().put("selinuxXattrContext", "u:r:untrusted_app:s0"), "CONFLICT", false);
        expect(avc(row(), "u:r:su:s0"), "VALID", true);
        expect(avc(row(), "u:r:untrusted_app:s0"), "CONFLICT", false);
        expect(avc(row(), "u:r:untrusted_app:s0").put("avcEvidenceAgeMs", 30001), "VALID", true);
        expect(avc(row(), "u:r:untrusted_app:s0").put("avcIdentityToken", "pid:42:old"), "VALID", true);
        expect(avc(row().put("metadataProbeAttempted", false), "u:r:ksu:s0"), "VALID", true);
        expect(avc(row().put("metadataProbeAttempted", false), "u:r:su:s0").put("avcRootDomainHint", false), "UNKNOWN", false);
        for (String field : new String[]{"metadataProbeAttempted", "identityVerified", "selinuxEvidenceVerified", "selinuxProcfsVerified"}) {
            expect(row().put(field, false), "UNKNOWN", false);
            expect(row().put(field, "true"), "UNKNOWN", false);
        }
        expect(row().put("selinuxIdentityToken", "pid:42:old"), "UNKNOWN", false);
        expect(row().put("identityToken", ""), "UNKNOWN", false);
        expect(row(), 1200, 8, "UNKNOWN", false);
        expect(row(), 1200, -1, "UNKNOWN", false);
        expect(row(), 999, 7, "UNKNOWN", false);
        expect(row(), 31001, 7, "UNKNOWN", false);
        expect(row().put("probeEndEpochMs", 999), "UNKNOWN", false);
        for (String context : new String[]{"u:r:su:s0 bad", "u:r:su:s0\n", "u:r:su:", "u:object_r:su:s0", "u:r:su:s0:c"}) {
            expect(row().put("selinuxAttrContext", context), "MALFORMED", false);
        }
        expect(row().put("selinuxXattrContext", "").put("selinuxAttrContext", "u:r:ksu:s0:c1,c2"), "VALID", true);
        expect(row().put("selinuxXattrContext", "u:r:system_server:s0").put("selinuxAttrContext", "u:r:system_server:s0"), "VALID", false);
        JSONObject knownUser = row().put("uid", 1000);
        DomainEvidence.apply(knownUser, 1200, 7);
        if (DomainEvidence.accepts(knownUser)) throw new AssertionError("domain overrides known UID");
        JSONObject knownRoot = row().put("uid", 0).put("selinuxAttrContext", "u:r:init:s0");
        DomainEvidence.apply(knownRoot, 1200, 7);
        if (!DomainEvidence.accepts(knownRoot)) throw new AssertionError("numeric root lost on label conflict");
        System.out.println("DomainEvidence: " + passed + " scenarios and numeric UID precedence checks passed.");
    }
}
