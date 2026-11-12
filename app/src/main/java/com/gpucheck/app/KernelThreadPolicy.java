package com.gpucheck.app;

import org.json.JSONObject;
import java.util.regex.Pattern;

/** Current-snapshot evidence only. Failure/exit/unsupported operations stay UNKNOWN. */
final class KernelThreadPolicy {
    static final String METHOD = "futex_trylock_pi";
    static final String UNKNOWN = "UNKNOWN", KERNEL = "KERNEL", USER = "USER";
    private static final String CATEGORY = "c[0-9]+(?:\\.c[0-9]+)?";
    private static final String LEVEL = "s[0-9]+(?::" + CATEGORY + "(?:," + CATEGORY + ")*)?";
    private static final Pattern KERNEL_CONTEXT = Pattern.compile("u:r:kernel:" + LEVEL + "(?:-" + LEVEL + ")?");

    private KernelThreadPolicy() { }

    static boolean calibrated(JSONObject report) {
        JSONObject probe = report.optJSONObject("futexPi");
        long sample = report.optLong("sampleIndex", -1);
        if (sample < 0 || probe == null || !METHOD.equals(probe.optString("method"))
                || !Boolean.TRUE.equals(probe.opt("available"))
                || !Boolean.TRUE.equals(probe.opt("private"))
                || sample != probe.optLong("sampleIndex", -1)) return false;
        JSONObject controls = probe.optJSONObject("controls");
        if (controls == null) return false;
        JSONObject zero = controls.optJSONObject("zero");
        return result(zero, 0, 0) && zero.optInt("unlockRet", -2) == 0
                && zero.optInt("unlockErrno", -1) == 0
                && result(controls.optJSONObject("self"), -1, 35)
                && result(controls.optJSONObject("peer"), -1, 11)
                && result(controls.optJSONObject("missing"), -1, 3);
    }

    static String classify(JSONObject row, JSONObject report) {
        if (!calibrated(report) || !Boolean.TRUE.equals(row.opt("identityVerified"))) return UNKNOWN;
        JSONObject check = row.optJSONObject("threadTypeCheck");
        int pid = row.optInt("pid", -1);
        String identity = row.optString("identityToken");
        if (pid <= 0 || pid > 0x3fffffff || identity.trim().isEmpty() || check == null
                || !METHOD.equals(check.optString("method")) || pid != check.optInt("tid", -1)
                || report.optLong("sampleIndex", -1) != check.optLong("sampleIndex", -1)
                || !identity.equals(check.optString("identityToken"))
                || !Boolean.TRUE.equals(check.opt("calibrated"))
                || !Boolean.TRUE.equals(check.opt("pidfdLiveBefore"))
                || !Boolean.TRUE.equals(check.opt("pidfdLiveAfter"))) return UNKNOWN;
        JSONObject outcome = check.optJSONObject("result");
        if (result(outcome, -1, 1)) return KERNEL;
        if (result(outcome, -1, 11)) return USER;
        return UNKNOWN;
    }

    static boolean kernelDomainMismatch(JSONObject row, String type) {
        String context = row.optString("avcTargetContext");
        String identity = row.optString("identityToken");
        long age = row.optLong("avcEvidenceAgeMs", -1);
        return USER.equals(type) && context.length() <= 4096 && KERNEL_CONTEXT.matcher(context).matches()
                && "kernel".equals(row.optString("avcTargetDomain"))
                && row.optInt("pid", -1) == row.optInt("avcTargetPid", -2)
                && !identity.isEmpty() && identity.equals(row.optString("avcIdentityToken"))
                && age >= 0 && age <= AvcEvidence.MAX_AGE_MS;
    }

    private static boolean result(JSONObject value, int ret, int error) {
        return value != null && value.optInt("ret", -2) == ret && value.optInt("errno", -1) == error;
    }
}
