package com.gpucheck.app;

import org.json.JSONException;
import org.json.JSONObject;

/** Fuses current read-only label evidence. Never infers a numeric UID from a label. */
public final class DomainEvidence {
    public static final long MAX_AGE_MS = 30_000;

    public static final class Result {
        public final String state, source, context;
        public final boolean root;
        Result(String state, String source, String context) {
            this.state = state; this.source = source; this.context = context;
            root = "VALID".equals(state) && RootProcessFilter.rootContext(context);
        }
    }

    private DomainEvidence() { }
    private static boolean yes(JSONObject p, String field) { return Boolean.TRUE.equals(p.opt(field)); }

    public static Result evaluate(JSONObject p, long reportEpochMs, long sampleIndex) {
        String identity = p.optString("identityToken", "");
        if (!yes(p, "identityVerified") || identity.trim().isEmpty()) return new Result("UNKNOWN", "none", "");
        long begin = p.optLong("probeEpochMs", -1), end = p.optLong("probeEndEpochMs", -1);
        boolean direct = yes(p, "metadataProbeAttempted") && yes(p, "selinuxEvidenceVerified")
                && yes(p, "selinuxProcfsVerified") && identity.equals(p.optString("selinuxIdentityToken"))
                && sampleIndex >= 0 && p.optLong("selinuxSampleIndex", -1) == sampleIndex
                && begin > 0 && end >= begin && reportEpochMs >= end
                && reportEpochMs - begin <= MAX_AGE_MS;
        String xattr = direct && p.optInt("xattrErrno", -1) == 0 ? p.optString("selinuxXattrContext", "") : "";
        String attr = direct && p.optInt("selinuxAttrErrno", -1) == 0 ? p.optString("selinuxAttrContext", "") : "";
        if ((!xattr.isEmpty() && !RootProcessFilter.validContext(xattr))
                || (!attr.isEmpty() && !RootProcessFilter.validContext(attr))) {
            return new Result("MALFORMED", "direct", "");
        }
        if (!xattr.isEmpty() && !attr.isEmpty() && !xattr.equals(attr)) return new Result("CONFLICT", "direct", "");
        String context = !attr.isEmpty() ? attr : xattr;
        String source = !xattr.isEmpty() && !attr.isEmpty() ? "direct_xattr_and_attr"
                : !attr.isEmpty() ? "direct_attr" : !xattr.isEmpty() ? "direct_xattr" : "none";
        long avcAge = p.optLong("avcEvidenceAgeMs", -1);
        String avc = p.optString("avcTargetContext", "");
        boolean currentAvc = avcAge >= 0 && avcAge <= MAX_AGE_MS
                && identity.equals(p.optString("avcIdentityToken")) && RootProcessFilter.validContext(avc)
                && (!RootProcessFilter.rootContext(avc) || yes(p, "avcRootDomainHint"));
        if (currentAvc) {
            if (!context.isEmpty() && !context.equals(avc)) return new Result("CONFLICT", "direct_and_avc", "");
            source = context.isEmpty() ? "avc" : "direct_and_avc";
            context = avc;
        }
        return new Result(context.isEmpty() ? "UNKNOWN" : "VALID", source, context);
    }

    public static Result apply(JSONObject p, long reportEpochMs, long sampleIndex) throws JSONException {
        Result r = evaluate(p, reportEpochMs, sampleIndex);
        p.put("domainEvidenceState", r.state).put("domainEvidenceSource", r.source)
                .put("domainEvidenceContext", r.context).put("domainEvidenceRoot", r.root)
                .put("domainEvidenceIdentityToken", p.optString("identityToken", ""))
                .put("selinuxRootDomainHint", r.root && r.source.startsWith("direct"));
        return r;
    }

    public static boolean accepts(JSONObject p) {
        int uid = p.optInt("uid", -1);
        if (uid >= 0) return uid == 0;
        if (!p.has("domainEvidenceState")) {
            // Compatibility for unprocessed legacy UI snapshots. RiskEngine always applies first.
            return RootProcessFilter.accepts(uid, yes(p, "identityVerified"), p.optString("identityToken", ""),
                    yes(p, "avcRootDomainHint"), p.optString("avcTargetContext", ""), p.optString("avcIdentityToken", ""));
        }
        return "VALID".equals(p.optString("domainEvidenceState")) && yes(p, "domainEvidenceRoot")
                && RootProcessFilter.accepts(-1, yes(p, "identityVerified"), p.optString("identityToken", ""),
                    true, p.optString("domainEvidenceContext", ""), p.optString("domainEvidenceIdentityToken", ""));
    }
}
