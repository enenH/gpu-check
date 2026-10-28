package com.gpucheck.app;

/** Tests the requested correlation rule without claiming UID or per-process GPU confirmation. */
public final class AvcRiskPolicyTest {
    private static int passed;

    public static void main(String[] args) {
        run("both sustained counters and current AVC produce HIGH", AvcRiskPolicyTest::sustainedEvidence);
        run("CPU drop resets process qualification", AvcRiskPolicyTest::cpuDrop);
        run("GPU inactivity resets global qualification", AvcRiskPolicyTest::gpuStop);
        run("an unavailable GPU sample breaks the streak", AvcRiskPolicyTest::gpuUnavailable);
        run("instant GPU activity cannot promote sustained CPU", AvcRiskPolicyTest::instantGpu);
        run("missing root-domain evidence never produces HIGH", AvcRiskPolicyTest::missingAvc);
        run("expired AVC immediately withdraws HIGH", AvcRiskPolicyTest::expiredAvc);
        run("current AVC can use independent sustained windows", AvcRiskPolicyTest::currentAvc);
        run("same-PID identity change starts CPU history over", AvcRiskPolicyTest::identityChange);
        run("disappearance discards CPU history", AvcRiskPolicyTest::disappearance);
        run("observer itself is excluded", AvcRiskPolicyTest::selfExcluded);
        run("invalid CPU and missing identity cannot qualify", AvcRiskPolicyTest::invalidEvidence);
        run("low CPU cannot qualify with AVC and GPU activity", AvcRiskPolicyTest::lowCpu);
        run("exact threshold and more than one-core CPU", AvcRiskPolicyTest::cpuBoundary);
        run("duplicate rows do not inflate CPU windows", AvcRiskPolicyTest::duplicateRows);
        run("different processes retain separate CPU streaks", AvcRiskPolicyTest::independentProcesses);
        run("HIGH text discloses global GPU attribution limit", AvcRiskPolicyTest::reasonScope);
        run("configured one-window policy remains explicit", AvcRiskPolicyTest::configuration);
        run("invalid configuration is rejected", AvcRiskPolicyTest::invalidConfiguration);
        System.out.println("AvcRiskPolicy: " + passed + " tests passed.");
    }

    private static AvcRiskPolicy policy() { return new AvcRiskPolicy(25, 3); }

    private static AvcRiskPolicy.Decision sample(AvcRiskPolicy policy, boolean gpuSampled,
            boolean gpuActive, int pid, String identity, double cpu, boolean avc, boolean self) {
        policy.beginSnapshot(gpuSampled, gpuActive);
        AvcRiskPolicy.Decision decision = policy.evaluate(pid, identity, cpu, avc, self);
        policy.endSnapshot();
        return decision;
    }

    private static AvcRiskPolicy.Decision candidate(AvcRiskPolicy policy, double cpu) {
        return sample(policy, true, true, 42, "identity-A", cpu, true, false);
    }

    private static void sustainedEvidence() {
        AvcRiskPolicy policy = policy();
        expect(candidate(policy, 60), "WATCH", 1);
        expect(candidate(policy, 60), "WATCH", 2);
        expect(candidate(policy, 60), "HIGH", 3);
        expect(candidate(policy, 60), "HIGH", 3);
    }

    private static void cpuDrop() {
        AvcRiskPolicy policy = policy();
        candidate(policy, 60);
        candidate(policy, 60);
        candidate(policy, 60);
        expect(candidate(policy, 20), "LOW", 0);
        expect(candidate(policy, 60), "WATCH", 1);
        expect(candidate(policy, 60), "WATCH", 2);
        expect(candidate(policy, 60), "HIGH", 3);
    }

    private static void gpuStop() {
        AvcRiskPolicy policy = policy();
        candidate(policy, 60);
        candidate(policy, 60);
        candidate(policy, 60);
        expect(sample(policy, true, false, 42, "identity-A", 60, true, false), "WATCH", 3);
        expect(candidate(policy, 60), "WATCH", 3);
        expect(candidate(policy, 60), "WATCH", 3);
        expect(candidate(policy, 60), "HIGH", 3);
    }

    private static void gpuUnavailable() {
        AvcRiskPolicy policy = policy();
        candidate(policy, 60);
        candidate(policy, 60);
        // A stale active flag cannot overcome a failed sample.
        expect(sample(policy, false, true, 42, "identity-A", 60, true, false), "WATCH", 3);
        expect(candidate(policy, 60), "WATCH", 3);
        expect(candidate(policy, 60), "WATCH", 3);
        expect(candidate(policy, 60), "HIGH", 3);
    }

    private static void instantGpu() {
        AvcRiskPolicy policy = policy();
        for (int i = 1; i <= 3; i++) {
            expect(sample(policy, true, false, 42, "identity-A", 60, true, false), "WATCH", i);
        }
        expect(candidate(policy, 60), "WATCH", 3);
        expect(sample(policy, true, false, 42, "identity-A", 60, true, false), "WATCH", 3);
        expect(candidate(policy, 60), "WATCH", 3);
    }

    private static void missingAvc() {
        AvcRiskPolicy policy = policy();
        for (int i = 1; i <= 6; i++) {
            expect(sample(policy, true, true, 42, "identity-A", 60, false, false),
                    "WATCH", Math.min(i, 3));
        }
    }

    private static void expiredAvc() {
        AvcRiskPolicy policy = policy();
        candidate(policy, 60);
        candidate(policy, 60);
        expect(candidate(policy, 60), "HIGH", 3);
        expect(sample(policy, true, true, 42, "identity-A", 60, false, false), "WATCH", 3);
    }

    private static void currentAvc() {
        AvcRiskPolicy policy = policy();
        for (int i = 0; i < 3; i++) {
            sample(policy, true, true, 42, "identity-A", 60, false, false);
        }
        // The caller validates PID association and TTL; it need not supply a new log every window.
        expect(candidate(policy, 60), "HIGH", 3);
    }

    private static void identityChange() {
        AvcRiskPolicy policy = policy();
        candidate(policy, 60);
        candidate(policy, 60);
        expect(sample(policy, true, true, 42, "identity-B", 60, true, false), "WATCH", 1);
        expect(candidate(policy, 60), "WATCH", 1);
        expect(candidate(policy, 60), "WATCH", 2);
        expect(candidate(policy, 60), "HIGH", 3);
    }

    private static void disappearance() {
        AvcRiskPolicy policy = policy();
        candidate(policy, 60);
        candidate(policy, 60);
        policy.beginSnapshot(true, true);
        policy.endSnapshot();
        expect(candidate(policy, 60), "WATCH", 1);
    }

    private static void selfExcluded() {
        AvcRiskPolicy policy = policy();
        candidate(policy, 60);
        candidate(policy, 60);
        for (int i = 0; i < 4; i++) {
            expect(sample(policy, true, true, 42, "identity-A", 900, true, true), "LOW", 0);
        }
        expect(candidate(policy, 60), "WATCH", 1);
    }

    private static void invalidEvidence() {
        AvcRiskPolicy policy = policy();
        for (double cpu : new double[]{Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY, -1}) {
            candidate(policy, 60);
            candidate(policy, 60);
            expect(candidate(policy, cpu), "UNKNOWN", 0);
            expect(candidate(policy, 60), "WATCH", 1);
            candidate(policy, 0);
        }
        for (String identity : new String[]{null, "", " \t\n"}) {
            expect(sample(policy, true, true, 42, identity, 60, true, false), "UNKNOWN", 0);
        }
        expect(sample(policy, true, true, 0, "identity-A", 60, true, false), "UNKNOWN", 0);
        expect(sample(policy, true, true, -1, "identity-A", 60, true, false), "UNKNOWN", 0);
    }

    private static void lowCpu() {
        AvcRiskPolicy policy = policy();
        for (int i = 0; i < 5; i++) expect(candidate(policy, 24.999), "LOW", 0);
    }

    private static void cpuBoundary() {
        AvcRiskPolicy policy = policy();
        expect(candidate(policy, 25), "WATCH", 1);
        expect(candidate(policy, 180), "WATCH", 2);
        expect(candidate(policy, 350), "HIGH", 3);
    }

    private static void duplicateRows() {
        AvcRiskPolicy policy = policy();
        for (int window = 1; window <= 3; window++) {
            policy.beginSnapshot(true, true);
            for (int duplicate = 0; duplicate < 5; duplicate++) {
                expect(policy.evaluate(42, "identity-A", 60, true, false),
                        window == 3 ? "HIGH" : "WATCH", window);
            }
            policy.endSnapshot();
        }
    }

    private static void independentProcesses() {
        AvcRiskPolicy policy = policy();
        for (int window = 1; window <= 3; window++) {
            policy.beginSnapshot(true, true);
            expect(policy.evaluate(42, "identity-A", 60, true, false),
                    window == 3 ? "HIGH" : "WATCH", window);
            expect(policy.evaluate(43, "identity-A", window == 2 ? 0 : 60, true, false),
                    window == 2 ? "LOW" : "WATCH", window == 2 ? 0 : 1);
            expect(policy.evaluate(44, "identity-A", 60, false, false), "WATCH", window);
            policy.endSnapshot();
        }
    }

    private static void reasonScope() {
        AvcRiskPolicy policy = policy();
        candidate(policy, 60);
        candidate(policy, 60);
        AvcRiskPolicy.Decision decision = candidate(policy, 60);
        expect(decision, "HIGH", 3);
        check(("AVC 指向 root 执行域 + CPU 持续高占用 + 全局 memstore 持续推进；"
                + "按进程 GPU 归属未确认。").equals(decision.reason), "HIGH reason changed evidence scope");
        check(!decision.reason.contains("UID 0"), "AVC domain must not become numeric UID confirmation");
        check(!decision.reason.contains("已验证 GPU"), "global activity must not become PID GPU proof");
    }

    private static void configuration() {
        AvcRiskPolicy policy = new AvcRiskPolicy(150, 1);
        expect(candidate(policy, 149), "LOW", 0);
        expect(candidate(policy, 150), "HIGH", 1);
        expect(sample(policy, false, true, 42, "identity-A", 150, true, false), "WATCH", 1);
    }

    private static void invalidConfiguration() {
        for (double threshold : new double[]{0, -1, 10001, Double.NaN, Double.POSITIVE_INFINITY}) {
            reject(() -> new AvcRiskPolicy(threshold, 3));
        }
        reject(() -> new AvcRiskPolicy(25, 0));
        reject(() -> new AvcRiskPolicy(25, 31));
    }

    private static void reject(Runnable action) {
        try {
            action.run();
        } catch (IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError("Expected IllegalArgumentException");
    }

    private static void expect(AvcRiskPolicy.Decision decision, String risk, int count) {
        check(risk.equals(decision.risk), "expected " + risk + ", got " + decision.risk);
        check(count == decision.consecutiveHigh,
                "expected CPU streak " + count + ", got " + decision.consecutiveHigh);
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
