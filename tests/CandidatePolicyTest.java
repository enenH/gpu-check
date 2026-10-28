package com.gpucheck.app;

/** JDK-only checks for leads which must not be presented as confirmed root/GPU findings. */
public final class CandidatePolicyTest {
    private static int passed;

    public static void main(String[] args) {
        run("three stable inaccessible windows produce SUSPECT", CandidatePolicyTest::threeWindows);
        run("CPU drop resets the candidate", CandidatePolicyTest::cpuDrop);
        run("same PID with a new identity starts over", CandidatePolicyTest::identityChange);
        run("returning old identity does not restore its streak", CandidatePolicyTest::identityReturns);
        run("disappearance resets the candidate", CandidatePolicyTest::disappearance);
        run("accessible metadata excludes this rule", CandidatePolicyTest::accessibleMetadata);
        run("the observer itself is excluded", CandidatePolicyTest::selfExcluded);
        run("invalid CPU cannot accumulate", CandidatePolicyTest::invalidCpu);
        run("missing identity cannot accumulate", CandidatePolicyTest::missingIdentity);
        run("invalid PID cannot accumulate", CandidatePolicyTest::invalidPid);
        run("one-core CPU values above 100 are valid", CandidatePolicyTest::aboveOneCore);
        run("threshold equality and streak cap", CandidatePolicyTest::thresholdBoundary);
        run("parallel process histories stay separate", CandidatePolicyTest::independentProcesses);
        run("duplicate rows do not become multiple windows", CandidatePolicyTest::duplicateRows);
        run("candidate text keeps identity and GPU unconfirmed", CandidatePolicyTest::unconfirmedClaims);
        run("configurable windows are honored", CandidatePolicyTest::configuration);
        run("invalid configuration is rejected", CandidatePolicyTest::invalidConfiguration);
        System.out.println("CandidatePolicy: " + passed + " tests passed.");
    }

    private static CandidatePolicy policy() { return new CandidatePolicy(25, 3); }

    private static CandidatePolicy.Decision sample(CandidatePolicy policy, int pid, String identity,
            double cpu, boolean accessible, boolean self) {
        policy.beginSnapshot();
        CandidatePolicy.Decision decision = policy.evaluate(pid, identity, cpu, accessible, self);
        policy.endSnapshot();
        return decision;
    }

    private static CandidatePolicy.Decision candidate(CandidatePolicy policy, double cpu) {
        return sample(policy, 42, "identity-A", cpu, false, false);
    }

    private static void threeWindows() {
        CandidatePolicy policy = policy();
        expect(candidate(policy, 60), "WATCH", 1);
        expect(candidate(policy, 60), "WATCH", 2);
        expect(candidate(policy, 60), "SUSPECT", 3);
        expect(candidate(policy, 60), "SUSPECT", 3);
    }

    private static void cpuDrop() {
        CandidatePolicy policy = policy();
        candidate(policy, 60);
        candidate(policy, 60);
        candidate(policy, 60);
        expect(candidate(policy, 0), "LOW", 0);
        expect(candidate(policy, 60), "WATCH", 1);
        expect(candidate(policy, 60), "WATCH", 2);
    }

    private static void identityChange() {
        CandidatePolicy policy = policy();
        candidate(policy, 60);
        candidate(policy, 60);
        expect(sample(policy, 42, "identity-B", 60, false, false), "WATCH", 1);
        expect(sample(policy, 42, "identity-B", 60, false, false), "WATCH", 2);
        expect(sample(policy, 42, "identity-B", 60, false, false), "SUSPECT", 3);
    }

    private static void identityReturns() {
        CandidatePolicy policy = policy();
        candidate(policy, 60);
        candidate(policy, 60);
        expect(sample(policy, 42, "identity-B", 60, false, false), "WATCH", 1);
        expect(candidate(policy, 60), "WATCH", 1);
    }

    private static void disappearance() {
        CandidatePolicy policy = policy();
        candidate(policy, 60);
        candidate(policy, 60);
        policy.beginSnapshot();
        policy.endSnapshot();
        expect(candidate(policy, 60), "WATCH", 1);
    }

    private static void accessibleMetadata() {
        CandidatePolicy policy = policy();
        candidate(policy, 60);
        candidate(policy, 60);
        for (int i = 0; i < 4; i++) {
            expect(sample(policy, 42, "identity-A", 90, true, false), "LOW", 0);
        }
        expect(candidate(policy, 60), "WATCH", 1);
    }

    private static void selfExcluded() {
        CandidatePolicy policy = policy();
        candidate(policy, 60);
        candidate(policy, 60);
        for (int i = 0; i < 4; i++) {
            expect(sample(policy, 42, "identity-A", 900, false, true), "LOW", 0);
        }
        expect(candidate(policy, 60), "WATCH", 1);
    }

    private static void invalidCpu() {
        CandidatePolicy policy = policy();
        for (double cpu : new double[]{Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY, -1}) {
            candidate(policy, 60);
            candidate(policy, 60);
            expect(candidate(policy, cpu), "UNKNOWN", 0);
            expect(candidate(policy, 60), "WATCH", 1);
            expect(candidate(policy, 0), "LOW", 0);
        }
    }

    private static void missingIdentity() {
        CandidatePolicy policy = policy();
        candidate(policy, 60);
        candidate(policy, 60);
        for (String token : new String[]{null, "", " \t\n"}) {
            expect(sample(policy, 42, token, 60, false, false), "UNKNOWN", 0);
        }
        expect(candidate(policy, 60), "WATCH", 1);
    }

    private static void invalidPid() {
        CandidatePolicy policy = policy();
        for (int pid : new int[]{0, -1}) {
            for (int i = 0; i < 4; i++) {
                expect(sample(policy, pid, "identity-A", 60, false, false), "UNKNOWN", 0);
            }
        }
    }

    private static void aboveOneCore() {
        CandidatePolicy policy = policy();
        expect(candidate(policy, 150), "WATCH", 1);
        expect(candidate(policy, 240), "WATCH", 2);
        expect(candidate(policy, 350), "SUSPECT", 3);
    }

    private static void thresholdBoundary() {
        CandidatePolicy policy = policy();
        expect(candidate(policy, 24.999), "LOW", 0);
        expect(candidate(policy, 25), "WATCH", 1);
        expect(candidate(policy, 25), "WATCH", 2);
        expect(candidate(policy, 25), "SUSPECT", 3);
        expect(candidate(policy, 25), "SUSPECT", 3);
    }

    private static void independentProcesses() {
        CandidatePolicy policy = policy();
        for (int window = 1; window <= 3; window++) {
            policy.beginSnapshot();
            expect(policy.evaluate(42, "identity-A", 60, false, false),
                    window == 3 ? "SUSPECT" : "WATCH", window);
            expect(policy.evaluate(43, "identity-A", window == 2 ? 0 : 60, false, false),
                    window == 2 ? "LOW" : "WATCH", window == 2 ? 0 : 1);
            policy.endSnapshot();
        }
    }

    private static void duplicateRows() {
        CandidatePolicy policy = policy();
        for (int window = 1; window <= 3; window++) {
            policy.beginSnapshot();
            for (int duplicate = 0; duplicate < 4; duplicate++) {
                expect(policy.evaluate(42, "identity-A", 60, false, false),
                        window == 3 ? "SUSPECT" : "WATCH", window);
            }
            policy.endSnapshot();
        }
    }

    private static void unconfirmedClaims() {
        CandidatePolicy policy = policy();
        candidate(policy, 60);
        candidate(policy, 60);
        CandidatePolicy.Decision decision = candidate(policy, 60);
        expect(decision, "SUSPECT", 3);
        check("持续高 CPU 的不可访问进程；UID、后台状态及 GPU 归属尚未确认。".equals(decision.reason),
                "candidate reason must retain all attribution limits");
        check(!decision.reason.contains("root"), "candidate must not claim root");
        check(!decision.reason.contains("已验证"), "candidate must not claim verified activity");
    }

    private static void configuration() {
        CandidatePolicy immediate = new CandidatePolicy(150, 1);
        expect(candidate(immediate, 149), "LOW", 0);
        expect(candidate(immediate, 150), "SUSPECT", 1);
        CandidatePolicy longer = new CandidatePolicy(25, 30);
        for (int i = 1; i <= 30; i++) {
            expect(candidate(longer, 25), i == 30 ? "SUSPECT" : "WATCH", i);
        }
    }

    private static void invalidConfiguration() {
        for (double threshold : new double[]{0, -1, 10001, Double.NaN, Double.POSITIVE_INFINITY}) {
            reject(() -> new CandidatePolicy(threshold, 3));
        }
        reject(() -> new CandidatePolicy(25, 0));
        reject(() -> new CandidatePolicy(25, 31));
    }

    private static void reject(Runnable action) {
        try {
            action.run();
        } catch (IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError("Expected IllegalArgumentException");
    }

    private static void expect(CandidatePolicy.Decision decision, String risk, int count) {
        check(risk.equals(decision.risk), "expected " + risk + ", got " + decision.risk);
        check(count == decision.consecutiveHigh,
                "expected streak " + count + ", got " + decision.consecutiveHigh);
        check(!"HIGH".equals(decision.risk), "ordinary-access policy must never produce HIGH");
        check(decision.reason != null && !decision.reason.isEmpty(), "reason must be present");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static void run(String name, Runnable test) {
        try {
            test.run();
        } catch (Throwable failure) {
            throw new AssertionError("FAILED: " + name, failure);
        }
        passed++;
        System.out.println("PASS " + name);
    }
}
