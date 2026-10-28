package com.gpucheck.app;

/** Host-only scope regression checks. No Android runtime or SELinux policy changes. */
public final class RootProcessFilterTest {
    private static int passed;

    public static void main(String[] args) {
        run("numeric UID zero is sufficient at this instant", RootProcessFilterTest::numericRoot);
        run("numeric UID wins over unrelated AVC evidence", RootProcessFilterTest::numericPrecedence);
        run("known non-root UID rejects every root domain", RootProcessFilterTest::nonRootConflict);
        run("su target domain with matching lifecycle is accepted", () -> acceptedDomain("su"));
        run("magisk target domain with matching lifecycle is accepted", () -> acceptedDomain("magisk"));
        run("zygisk target domain with matching lifecycle is accepted", () -> acceptedDomain("zygisk"));
        run("ksu target domain with matching lifecycle is accepted", () -> acceptedDomain("ksu"));
        run("unknown lifecycle is rejected", RootProcessFilterTest::unverifiedIdentity);
        run("missing root-domain hint is rejected", RootProcessFilterTest::missingHint);
        run("PID lifecycle token mismatch is rejected", RootProcessFilterTest::tokenMismatch);
        run("missing and whitespace tokens are rejected", RootProcessFilterTest::missingTokens);
        run("partial or substituted user-role prefixes are rejected", RootProcessFilterTest::badPrefixes);
        run("domain substrings and other domains are rejected", RootProcessFilterTest::otherDomains);
        run("source-context and full log text cannot masquerade as target context", RootProcessFilterTest::sourceContext);
        run("malformed and incomplete contexts are rejected", RootProcessFilterTest::malformedContext);
        run("MLS categories and level ranges retain exact root domain", RootProcessFilterTest::validMls);
        run("malformed MLS suffixes are rejected", RootProcessFilterTest::invalidMls);
        run("context matching is exact and case-sensitive", RootProcessFilterTest::exactContext);
        System.out.println("RootProcessFilter: " + passed + " tests passed.");
    }

    private static boolean hint(String context) {
        return RootProcessFilter.accepts(-1, true, "42:epoch-A", true, context, "42:epoch-A");
    }

    private static void numericRoot() {
        check(RootProcessFilter.accepts(0, false, null, false, null, null),
                "current numeric UID zero should not require lifecycle evidence");
    }

    private static void numericPrecedence() {
        check(RootProcessFilter.accepts(0, false, "A", true, "u:r:untrusted_app:s0", "B"),
                "numeric root must not be overridden by unrelated AVC hints");
        check(RootProcessFilter.accepts(0, false, "", false, "malformed", ""),
                "numeric root should not depend on AVC parsing");
    }

    private static void nonRootConflict() {
        for (int uid : new int[]{1, 1000, 2000, 10276, 65534, Integer.MAX_VALUE}) {
            for (String domain : new String[]{"su", "magisk", "zygisk", "ksu"}) {
                check(!RootProcessFilter.accepts(uid, true, "A", true, "u:r:" + domain + ":s0", "A"),
                        "known non-root UID was overridden by domain " + domain);
            }
        }
    }

    private static void acceptedDomain(String domain) {
        check(hint("u:r:" + domain + ":s0"), "valid target domain rejected: " + domain);
    }

    private static void unverifiedIdentity() {
        check(!RootProcessFilter.accepts(-1, false, "A", true, "u:r:su:s0", "A"),
                "unverified process identity must not enter scope");
    }

    private static void missingHint() {
        check(!RootProcessFilter.accepts(-1, true, "A", false, "u:r:su:s0", "A"),
                "a domain string alone must not replace validated AVC evidence");
    }

    private static void tokenMismatch() {
        check(!RootProcessFilter.accepts(-1, true, "42:new", true, "u:r:su:s0", "42:old"),
                "AVC for a reused PID must not carry forward");
        check(!RootProcessFilter.accepts(-1, true, "42:A", true, "u:r:su:s0", "43:A"),
                "AVC for another PID must not qualify");
        check(!RootProcessFilter.accepts(-1, true, "A ", true, "u:r:su:s0", "A"),
                "tokens must match exactly rather than after normalization");
    }

    private static void missingTokens() {
        for (String token : new String[]{null, "", " \t\n"}) {
            check(!RootProcessFilter.accepts(-1, true, token, true, "u:r:su:s0", token),
                    "empty lifecycle evidence must not qualify");
        }
        check(!RootProcessFilter.accepts(-1, true, "A", true, "u:r:su:s0", null),
                "missing AVC lifecycle token must not qualify");
    }

    private static void badPrefixes() {
        for (String context : new String[]{"x:u:r:su:s0", "prefixu:r:su:s0", "u:x:su:s0",
                "x:r:su:s0", "u:rfoo:su:s0", "u:object_r:su:s0", "r:su:s0"}) {
            check(!hint(context), "invalid prefix accepted: " + context);
        }
    }

    private static void otherDomains() {
        for (String domain : new String[]{"shell", "init", "untrusted_app", "system_server",
                "root", "superuser", "su_helper", "magiskd", "ksud", "zygisk32", "xsu"}) {
            check(!hint("u:r:" + domain + ":s0"), "non-listed domain accepted: " + domain);
        }
    }

    private static void sourceContext() {
        for (String context : new String[]{"scontext=u:r:su:s0", "tcontext=u:r:su:s0",
                "avc: denied scontext=u:r:su:s0 tcontext=u:r:untrusted_app:s0",
                "u:r:untrusted_app:s0 u:r:su:s0"}) {
            check(!hint(context), "log/source text accepted as exact target context");
        }
    }

    private static void malformedContext() {
        for (String context : new String[]{null, "", "u:r:su", "u:r:su:", "u:r::s0",
                "u::su:s0", "u:r:su:s0:", "u:r:su::s0", "u:r:su:s0:unknown"}) {
            check(!hint(context), "malformed context accepted: " + context);
        }
    }

    private static void validMls() {
        for (String suffix : new String[]{"s0", "s1", "s0:c1", "s0:c1,c2", "s0:c0.c1023",
                "s0:c1,c3.c7", "s0-s1", "s0:c1-s1:c1,c2"}) {
            check(hint("u:r:ksu:" + suffix), "structurally valid MLS suffix rejected: " + suffix);
        }
    }

    private static void invalidMls() {
        for (String suffix : new String[]{"s", "s-1", "0", "s0:c", "s0:c-1", "s0:c1,",
                "s0:c1.c2.c3", "s0::c1", "s0-s", "s0-s1-s2", "s0;c1", "s0:c1 c2"}) {
            check(!hint("u:r:su:" + suffix), "malformed MLS suffix accepted: " + suffix);
        }
    }

    private static void exactContext() {
        for (String context : new String[]{"U:r:su:s0", "u:R:su:s0", "u:r:SU:s0",
                " u:r:su:s0", "u:r:su:s0 ", "u:r:su:s0\n", "u:r:su:s0\0"}) {
            check(!hint(context), "non-exact context accepted: " + context);
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static void run(String name, Runnable test) {
        try { test.run(); }
        catch (Throwable failure) { throw new AssertionError("FAILED: " + name, failure); }
        passed++;
        System.out.println("PASS " + name);
    }
}
