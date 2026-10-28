package com.gpucheck.app;

import java.util.regex.Pattern;

/** Scope filter only: an AVC target-domain hint is never converted into a numeric UID. */
public final class RootProcessFilter {
    private static final String CATEGORY = "c[0-9]+(?:\\.c[0-9]+)?";
    private static final String CATEGORIES = CATEGORY + "(?:," + CATEGORY + ")*";
    private static final String LEVEL = "s[0-9]+(?::" + CATEGORIES + ")?";
    // Exact user, role and type fields; optional MLS categories/range have structural validation.
    private static final Pattern ROOT_TARGET_CONTEXT = Pattern.compile(
            "u:r:(?:su|magisk|zygisk|ksu):" + LEVEL + "(?:-" + LEVEL + ")?");

    private RootProcessFilter() { }

    /**
     * AvcEvidence must establish target-PID association and freshness before calling.
     * An observed numeric UID takes precedence over any domain hint. A UID-zero
     * observation admits the current row; correlation still requires its own
     * verified lifecycle and temporal evidence.
     */
    public static boolean accepts(int uid, boolean identityVerified, String identityToken,
                                  boolean avcRootDomainHint, String avcTargetContext,
                                  String avcIdentityToken) {
        if (uid >= 0) return uid == 0;
        if (!identityVerified || !avcRootDomainHint || identityToken == null
                || identityToken.trim().isEmpty() || !identityToken.equals(avcIdentityToken)) {
            return false;
        }
        return avcTargetContext != null && avcTargetContext.length() <= 4096
                && ROOT_TARGET_CONTEXT.matcher(avcTargetContext).matches();
    }
}
