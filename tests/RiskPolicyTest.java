package com.gpucheck.app;

/** Runs with the JDK only; no Android runtime or test libraries are required. */
public final class RiskPolicyTest {
    private static int passed;

    public static void main(String[] args) {
        run("three consecutive windows and bounded streak", RiskPolicyTest::threeWindows);
        run("CPU drop resets qualification", RiskPolicyTest::cpuDropResets);
        run("PID reuse starts a new history", RiskPolicyTest::pidReuse);
        run("a missing process loses its history", RiskPolicyTest::disappearance);
        run("process histories remain independent", RiskPolicyTest::independentProcesses);
        run("non-root cannot become high risk", RiskPolicyTest::nonRoot);
        run("foreground resets qualification", RiskPolicyTest::foreground);
        run("unknown background remains inconclusive", RiskPolicyTest::unknownBackground);
        run("missing GPU ownership never qualifies", RiskPolicyTest::missingGpu);
        run("unreadable evidence remains inconclusive", RiskPolicyTest::unreadableEvidence);
        run("NaN CPU resets qualification", RiskPolicyTest::nanCpu);
        run("invalid CPU and identity cannot qualify", RiskPolicyTest::invalidSamples);
        run("per-core CPU above 100 percent qualifies", RiskPolicyTest::aboveOneCore);
        run("the exact CPU threshold qualifies", RiskPolicyTest::thresholdBoundary);
        run("GPU ownership does not claim activity", RiskPolicyTest::ownershipReason);
        run("verified GPU activity is reported", RiskPolicyTest::activeReason);
        run("activity claim changes with current evidence", RiskPolicyTest::currentActivityReason);
        run("configured windows and threshold are honored", RiskPolicyTest::configuration);
        run("invalid configuration is rejected", RiskPolicyTest::invalidConfiguration);
        System.out.println("RiskPolicy: " + passed + " tests passed.");
    }

    private static RiskPolicy policy() { return new RiskPolicy(25.0, 3); }

    private static RiskPolicy.Decision sample(RiskPolicy policy, int pid, long startTime,
            int uid, double cpu, String background, boolean gpu, boolean active, boolean readable) {
        policy.beginSnapshot();
        RiskPolicy.Decision decision = policy.evaluate(
                pid, startTime, uid, cpu, background, gpu, active, readable);
        policy.endSnapshot();
        return decision;
    }

    private static RiskPolicy.Decision candidate(RiskPolicy policy, double cpu) {
        return sample(policy, 42, 1000L, 0, cpu, "background", true, false, true);
    }

    private static void threeWindows() {
        RiskPolicy policy = policy();
        expect(candidate(policy, 70), "WATCH", 1);
        expect(candidate(policy, 70), "WATCH", 2);
        expect(candidate(policy, 70), "HIGH", 3);
        expect(candidate(policy, 70), "HIGH", 3);
    }

    private static void cpuDropResets() {
        RiskPolicy policy = policy();
        candidate(policy, 60);
        candidate(policy, 60);
        candidate(policy, 60);
        expect(candidate(policy, 24.99), "WATCH", 0);
        expect(candidate(policy, 60), "WATCH", 1);
        expect(candidate(policy, 60), "WATCH", 2);
        expect(candidate(policy, 60), "HIGH", 3);
    }

    private static void pidReuse() {
        RiskPolicy policy = policy();
        candidate(policy, 60);
        candidate(policy, 60);
        candidate(policy, 60);
        expect(sample(policy, 42, 2000, 0, 60, "background", true, false, true), "WATCH", 1);
        expect(sample(policy, 42, 2000, 0, 60, "background", true, false, true), "WATCH", 2);
        expect(sample(policy, 42, 2000, 0, 60, "background", true, false, true), "HIGH", 3);
    }

    private static void disappearance() {
        RiskPolicy policy = policy();
        candidate(policy, 60);
        candidate(policy, 60);
        policy.beginSnapshot();
        policy.endSnapshot();
        expect(candidate(policy, 60), "WATCH", 1);
        expect(candidate(policy, 60), "WATCH", 2);
    }

    private static void independentProcesses() {
        RiskPolicy policy = policy();
        for (int window = 1; window <= 3; window++) {
            policy.beginSnapshot();
            expect(policy.evaluate(42, 1000, 0, 60, "background", true, false, true),
                    window == 3 ? "HIGH" : "WATCH", window);
            expect(policy.evaluate(43, 1000, 0, window == 2 ? 0 : 60,
                    "background", true, false, true), "WATCH", window == 2 ? 0 : 1);
            policy.endSnapshot();
        }
    }

    private static void nonRoot() {
        RiskPolicy policy = policy();
        candidate(policy, 60);
        candidate(policy, 60);
        for (int i = 0; i < 4; i++) {
            expect(sample(policy, 42, 1000, 10001, 200,
                    "background", true, true, true), "LOW", 0);
        }
        expect(candidate(policy, 60), "WATCH", 1);
    }

    private static void foreground() {
        RiskPolicy policy = policy();
        candidate(policy, 60);
        candidate(policy, 60);
        for (int i = 0; i < 4; i++) {
            expect(sample(policy, 42, 1000, 0, 100,
                    "foreground", true, true, true), "LOW", 0);
        }
        expect(candidate(policy, 60), "WATCH", 1);
    }

    private static void unknownBackground() {
        RiskPolicy policy = policy();
        candidate(policy, 60);
        candidate(policy, 60);
        for (int i = 0; i < 4; i++) {
            expect(sample(policy, 42, 1000, 0, 60,
                    "unknown", true, true, true), "UNKNOWN", 0);
        }
        expect(candidate(policy, 60), "WATCH", 1);
    }

    private static void missingGpu() {
        RiskPolicy policy = policy();
        candidate(policy, 60);
        candidate(policy, 60);
        for (int i = 0; i < 4; i++) {
            expect(sample(policy, 42, 1000, 0, 100,
                    "background", false, false, true), "WATCH", 0);
        }
        expect(candidate(policy, 60), "WATCH", 1);
        // An activity boolean alone cannot replace per-process GPU ownership.
        expect(sample(policy, 42, 1000, 0, 100,
                "background", false, true, true), "WATCH", 0);
    }

    private static void unreadableEvidence() {
        RiskPolicy policy = policy();
        candidate(policy, 60);
        candidate(policy, 60);
        for (int i = 0; i < 4; i++) {
            expect(sample(policy, 42, 1000, 0, 200,
                    "background", true, true, false), "UNKNOWN", 0);
        }
        expect(sample(policy, 42, 1000, 0, 0,
                "background", false, false, false), "UNKNOWN", 0);
        expect(candidate(policy, 60), "WATCH", 1);
    }

    private static void nanCpu() {
        RiskPolicy policy = policy();
        candidate(policy, 60);
        candidate(policy, 60);
        expect(candidate(policy, Double.NaN), "UNKNOWN", 0);
        expect(candidate(policy, 60), "WATCH", 1);
    }

    private static void invalidSamples() {
        RiskPolicy policy = policy();
        for (double cpu : new double[]{Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY, -1}) {
            expect(candidate(policy, cpu), "UNKNOWN", 0);
        }
        expect(sample(policy, 42, 0, 0, 100, "background", true, true, true), "UNKNOWN", 0);
        expect(sample(policy, 0, 1000, 0, 100, "background", true, true, true), "UNKNOWN", 0);
        expect(candidate(policy, 60), "WATCH", 1);
    }

    private static void aboveOneCore() {
        RiskPolicy policy = policy();
        expect(candidate(policy, 170), "WATCH", 1);
        expect(candidate(policy, 220), "WATCH", 2);
        expect(candidate(policy, 350), "HIGH", 3);
    }

    private static void thresholdBoundary() {
        RiskPolicy policy = policy();
        expect(candidate(policy, 24.999), "WATCH", 0);
        expect(candidate(policy, 25), "WATCH", 1);
        expect(candidate(policy, 25), "WATCH", 2);
        expect(candidate(policy, 25), "HIGH", 3);
    }

    private static void ownershipReason() {
        RiskPolicy policy = policy();
        candidate(policy, 60);
        candidate(policy, 60);
        RiskPolicy.Decision decision = candidate(policy, 60);
        expect(decision, "HIGH", 3);
        check(decision.reason.contains("持有 GPU 设备"), "ownership evidence missing from reason");
        check(decision.reason.contains("GPU 活动未确认"), "unconfirmed activity must be explicit");
        check(!decision.reason.contains("已验证 GPU 活动"), "ownership must not claim verified activity");
    }

    private static void activeReason() {
        RiskPolicy policy = policy();
        candidate(policy, 60);
        candidate(policy, 60);
        RiskPolicy.Decision decision = sample(policy, 42, 1000, 0, 60,
                "background", true, true, true);
        expect(decision, "HIGH", 3);
        check(decision.reason.contains("已验证 GPU 活动"), "verified activity missing from reason");
        check(!decision.reason.contains("活动未确认"), "verified activity reason contradicts evidence");
    }

    private static void currentActivityReason() {
        RiskPolicy policy = policy();
        for (int i = 0; i < 3; i++) {
            sample(policy, 42, 1000, 0, 60, "background", true, true, true);
        }
        RiskPolicy.Decision decision = candidate(policy, 60);
        expect(decision, "HIGH", 3);
        check(decision.reason.contains("GPU 活动未确认"), "old activity must not be presented as current");
        check(!decision.reason.contains("已验证 GPU 活动"), "stale activity claim");
    }

    private static void configuration() {
        RiskPolicy policy = new RiskPolicy(150, 1);
        expect(candidate(policy, 149), "WATCH", 0);
        expect(candidate(policy, 150), "HIGH", 1);
        RiskPolicy longer = new RiskPolicy(25, 30);
        for (int i = 1; i <= 30; i++) {
            expect(candidate(longer, 25), i == 30 ? "HIGH" : "WATCH", i);
        }
    }

    private static void invalidConfiguration() {
        for (double threshold : new double[]{0, -1, 10001, Double.NaN, Double.POSITIVE_INFINITY}) {
            reject(() -> new RiskPolicy(threshold, 3));
        }
        reject(() -> new RiskPolicy(25, 0));
        reject(() -> new RiskPolicy(25, 31));
    }

    private static void reject(Runnable action) {
        try {
            action.run();
        } catch (IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError("Expected IllegalArgumentException");
    }

    private static void expect(RiskPolicy.Decision decision, String risk, int streak) {
        check(risk.equals(decision.risk), "expected risk " + risk + ", got " + decision.risk);
        check(streak == decision.consecutiveHigh,
                "expected streak " + streak + ", got " + decision.consecutiveHigh);
        check(decision.reason != null && !decision.reason.isEmpty(), "reason must be available");
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
