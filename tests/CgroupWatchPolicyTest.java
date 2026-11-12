package com.gpucheck.app;

public final class CgroupWatchPolicyTest {
    private static int passed;
    private static final int PID = 42;

    public static void main(String[] args) {
        run("three consecutive stable missing observations confirm", CgroupWatchPolicyTest::confirmation);
        run("known non-root and unknown UID anomalies can be monitored", CgroupWatchPolicyTest::admission);
        run("PID reuse cannot inherit a streak", CgroupWatchPolicyTest::pidReuse);
        run("missing PID rows clear a streak", CgroupWatchPolicyTest::missingRow);
        run("missing sample indices restart confirmation", CgroupWatchPolicyTest::indexGap);
        run("duplicate and reversed sample indices restart confirmation", CgroupWatchPolicyTest::invalidIndex);
        run("long and nonmonotonic elapsed gaps restart confirmation", CgroupWatchPolicyTest::timeGap);
        run("unavailable path methods clear confirmed observations", CgroupWatchPolicyTest::incompleteScan);
        run("matched UID/PID paths clear anomalies", CgroupWatchPolicyTest::present);
        run("zombies and exited processes cannot become anomalies", CgroupWatchPolicyTest::zombieAndExit);
        run("per-row invalid evidence cannot advance a streak", CgroupWatchPolicyTest::invalidEvidence);
        run("mismatching identity and sample index are rejected", CgroupWatchPolicyTest::mismatch);
        run("same PID duplicates are not counted twice", CgroupWatchPolicyTest::duplicatePid);
        run("application, collector and shared UID are excluded", CgroupWatchPolicyTest::self);
        run("CPU monitoring excludes self without requiring risk evidence", CgroupWatchPolicyTest::cpuScope);
        run("independent identities retain separate streaks", CgroupWatchPolicyTest::independent);
        run("catalog changes restart confirmation", CgroupWatchPolicyTest::catalogChange);
        run("calibration and coverage failures clear confirmation", CgroupWatchPolicyTest::invalidPaths);
        run("reset removes all confirmation and timing state", CgroupWatchPolicyTest::reset);
        System.out.println("CgroupWatchPolicy: " + passed + " tests passed.");
    }

    private static CgroupWatchPolicy.Check missing(long index, String identity) {
        return new CgroupWatchPolicy.Check("MISSING", true, true, true, paths(7),
                identity, index, "not_in_calibrated_uid_pid_paths");
    }

    private static CgroupWatchPolicy.Paths paths(long generation) {
        return new CgroupWatchPolicy.Paths(true, true, true, false,
                5, 5, 5, generation, CgroupWatchPolicy.SCOPE);
    }

    private static CgroupWatchPolicy.Decision sample(CgroupWatchPolicy policy, long index,
                                                    String identity, CgroupWatchPolicy.Check check) {
        return sample(policy, index, index * 2000, true, identity, check, false);
    }

    private static CgroupWatchPolicy.Decision sample(CgroupWatchPolicy policy, long index, long elapsed,
                                                    boolean complete, String identity,
                                                    CgroupWatchPolicy.Check check, boolean self) {
        policy.beginSnapshot(index, elapsed, complete);
        CgroupWatchPolicy.Decision result = policy.evaluate(PID, identity, check, self);
        policy.endSnapshot();
        return result;
    }

    private static CgroupWatchPolicy confirmed() {
        CgroupWatchPolicy policy = new CgroupWatchPolicy(2000);
        for (int i = 0; i < 3; i++) sample(policy, i, "A", missing(i, "A"));
        return policy;
    }

    private static void confirmation() {
        CgroupWatchPolicy policy = new CgroupWatchPolicy(2000);
        for (int i = 0; i < 5; i++) {
            CgroupWatchPolicy.Decision d = sample(policy, i, "A", missing(i, "A"));
            check(d.consecutive == Math.min(3, i + 1), "wrong consecutive count");
            check(d.anomaly == (i >= 2) && d.validMissing, "wrong confirmation state");
            check(d.first == 0 && d.last == i * 2000L && d.firstSampleIndex == 0
                    && d.lastSampleIndex == i, "first/last evidence was not preserved");
        }
    }

    private static void admission() {
        CgroupWatchPolicy policy = confirmed();
        CgroupWatchPolicy.Decision d = sample(policy, 3, "A", missing(3, "A"));
        for (int uid : new int[]{-1, 10001, 10123}) {
            boolean root = RootProcessFilter.accepts(uid, true, "A", false, "", "");
            check(!root && MonitoredProcessFilter.accepts(false, root, d.anomaly), "anomaly requires root identity");
        }
        check(!MonitoredProcessFilter.accepts(false, false, false), "unknown/high CPU alone was admitted");
        check(MonitoredProcessFilter.accepts(false, true, false), "existing root admission changed");
        // Neither confirmation nor admission accepts a CPU argument: idle, zero and unavailable
        // CPU measurements use exactly the same admission path (RiskEngine integration tests cover JSON).
    }

    private static void pidReuse() {
        CgroupWatchPolicy policy = confirmed();
        CgroupWatchPolicy.Decision d = sample(policy, 3, "B", missing(3, "B"));
        check(!d.anomaly && d.consecutive == 1 && d.firstSampleIndex == 3, "PID reuse inherited confirmation");
    }

    private static void missingRow() {
        CgroupWatchPolicy policy = confirmed();
        policy.beginSnapshot(3, 6000, true); policy.endSnapshot();
        check(sample(policy, 4, "A", missing(4, "A")).consecutive == 1, "omitted PID kept history");
    }

    private static void indexGap() {
        CgroupWatchPolicy policy = confirmed();
        check(sample(policy, 4, 6000, true, "A", missing(4, "A"), false).consecutive == 1, "index gap kept history");
    }

    private static void invalidIndex() {
        for (long index : new long[]{2, 1, -1}) {
            CgroupWatchPolicy.Decision d = sample(confirmed(), index, 6000, true, "A", missing(index, "A"), false);
            check(!d.anomaly && d.consecutive == (index < 0 ? 0 : 1), "invalid index inherited history");
        }
    }

    private static void timeGap() {
        for (long elapsed : new long[]{9000, 4000, 3000, -1}) {
            CgroupWatchPolicy.Decision d = sample(confirmed(), 3, elapsed, true, "A", missing(3, "A"), false);
            check(!d.anomaly && d.consecutive == (elapsed < 0 ? 0 : 1), "time gap inherited history");
        }
    }

    private static void incompleteScan() {
        CgroupWatchPolicy policy = confirmed();
        CgroupWatchPolicy.Decision d = sample(policy, 3, 6000, false, "A", missing(3, "A"), false);
        check(!d.anomaly && d.consecutive == 0 && "UNKNOWN".equals(d.status), "partial scan became absence");
        check(sample(policy, 4, "A", missing(4, "A")).consecutive == 1, "partial scan did not clear streak");
    }

    private static void present() {
        CgroupWatchPolicy policy = confirmed();
        CgroupWatchPolicy.Check present = new CgroupWatchPolicy.Check("PRESENT", true, true,
                true, new CgroupWatchPolicy.Paths(true, true, true, true, 5, 5, 4, 7,
                CgroupWatchPolicy.SCOPE), "A", 3, "named_path_matched");
        CgroupWatchPolicy.Decision d = sample(policy, 3, "A", present);
        check(!d.anomaly && d.consecutive == 0 && "PRESENT".equals(d.status), "matched path remained anomalous");
        check(sample(policy, 4, "A", missing(4, "A")).consecutive == 1, "recovery did not clear confirmation");
    }

    private static void zombieAndExit() {
        CgroupWatchPolicy.Check zombie = new CgroupWatchPolicy.Check("MISSING", true, true,
                false, paths(7), "A", 3, "zombie");
        check(!sample(confirmed(), 3, "A", zombie).anomaly, "zombie admitted");
        CgroupWatchPolicy.Check exited = new CgroupWatchPolicy.Check("EXITED", false, false,
                false, paths(7), "A", 3, "pidfd_readable");
        CgroupWatchPolicy.Decision d = sample(confirmed(), 3, "A", exited);
        check(!d.anomaly && "EXITED".equals(d.status) && d.consecutive == 0, "exit kept confirmation");
    }

    private static void invalidEvidence() {
        for (int field = 0; field < 4; field++) {
            CgroupWatchPolicy.Check invalid = new CgroupWatchPolicy.Check("MISSING", field != 0,
                    field != 1, field != 2, field == 3 ? null : paths(7), "A", 3, "incomplete");
            CgroupWatchPolicy.Decision d = sample(confirmed(), 3, "A", invalid);
            check(!d.anomaly && d.consecutive == 0, "incomplete field " + field + " accepted");
        }
        CgroupWatchPolicy.Check unknown = new CgroupWatchPolicy.Check("UNKNOWN", true, true,
                true, paths(7), "A", 3, "permission_denied");
        check(sample(confirmed(), 3, "A", unknown).consecutive == 0, "UNKNOWN retained history");
        check(sample(confirmed(), 3, "A", null).consecutive == 0, "missing/rejected check retained history");
    }

    private static void mismatch() {
        check(sample(confirmed(), 3, "A", missing(3, "B")).consecutive == 0, "identity mismatch accepted");
        check(sample(confirmed(), 3, "A", missing(2, "A")).consecutive == 0, "stale check accepted");
        check(sample(confirmed(), 3, "", missing(3, "")).consecutive == 0, "empty identity accepted");
    }

    private static void duplicatePid() {
        CgroupWatchPolicy policy = new CgroupWatchPolicy(2000);
        policy.beginSnapshot(0, 0, true);
        check(policy.evaluate(PID, "A", missing(0, "A"), false).consecutive == 1, "first observation absent");
        check(policy.evaluate(PID, "A", missing(0, "A"), false).consecutive == 0, "duplicate advanced count");
        policy.endSnapshot();
        check(sample(policy, 1, "A", missing(1, "A")).consecutive == 1, "duplicate did not invalidate round");
    }

    private static void self() {
        check(MonitoredProcessFilter.isSelf(42, 10100, 42, 43, 10101), "collector not excluded");
        check(MonitoredProcessFilter.isSelf(43, 10100, 42, 43, 10101), "App PID not excluded");
        check(MonitoredProcessFilter.isSelf(44, 10101, 42, 43, 10101), "shared App UID not excluded");
        check(!MonitoredProcessFilter.isSelf(44, -1, 42, 43, 10101), "unknown UID treated as self");
        check(!MonitoredProcessFilter.accepts(true, true, true), "self admitted by combined filter");
        CgroupWatchPolicy.Decision d = sample(confirmed(), 3, 6000, true, "A", missing(3, "A"), true);
        check(!d.anomaly && d.consecutive == 0 && "EXCLUDED".equals(d.status), "self retained confirmation");
    }

    private static void cpuScope() {
        check(MonitoredProcessFilter.acceptsCpu(42, false), "external CPU sample requires risk evidence");
        check(!MonitoredProcessFilter.acceptsCpu(42, true), "self CPU sample was admitted");
        check(!MonitoredProcessFilter.acceptsCpu(0, false) && !MonitoredProcessFilter.acceptsCpu(-1, false),
                "invalid PID was admitted");
        check(MonitoredProcessFilter.isSelf(42, -1, 42, 43, 10101), "collector with unknown UID leaked");
        check(MonitoredProcessFilter.isSelf(43, -1, 42, 43, 10101), "App with unknown UID leaked");
    }

    private static void independent() {
        CgroupWatchPolicy policy = new CgroupWatchPolicy(2000);
        for (int i = 0; i < 3; i++) {
            policy.beginSnapshot(i, i * 2000, true);
            CgroupWatchPolicy.Decision a = policy.evaluate(42, "A", missing(i, "A"), false);
            CgroupWatchPolicy.Decision b = policy.evaluate(43, "B" + i, missing(i, "B" + i), false);
            check(a.anomaly == (i == 2) && b.consecutive == 1, "histories crossed process identities");
            policy.endSnapshot();
        }
    }

    private static void reset() {
        CgroupWatchPolicy policy = confirmed(); policy.reset();
        check(sample(policy, 0, "A", missing(0, "A")).consecutive == 1, "reset kept confirmation");
    }

    private static void catalogChange() {
        CgroupWatchPolicy policy = confirmed();
        CgroupWatchPolicy.Check changed = new CgroupWatchPolicy.Check("MISSING", true, true, true,
                paths(8), "A", 3, "new_uid_catalog");
        CgroupWatchPolicy.Decision decision = sample(policy, 3, "A", changed);
        check(decision.consecutive == 1 && !decision.anomaly && decision.firstSampleIndex == 3,
                "changed UID catalog inherited old confirmation");
    }

    private static void invalidPaths() {
        for (int field = 0; field < 10; field++) {
            CgroupWatchPolicy.Paths invalid = new CgroupWatchPolicy.Paths(field != 0, field != 1,
                    field != 2, field == 3, field == 4 ? 0 : 5, field == 5 ? 0 : 5,
                    field == 6 ? 4 : 5, field == 7 ? -1 : 7,
                    field == 8 ? "all_kernel_memberships" : CgroupWatchPolicy.SCOPE);
            if (field == 9) invalid = new CgroupWatchPolicy.Paths(true, true, true, false,
                    6, 5, 5, 7, CgroupWatchPolicy.SCOPE);
            CgroupWatchPolicy.Check row = new CgroupWatchPolicy.Check("MISSING", true, true,
                    true, invalid, "A", 3, "incomplete_paths");
            CgroupWatchPolicy policy = confirmed();
            check(sample(policy, 3, "A", row).consecutive == 0,
                    "invalid path evidence " + field + " retained confirmation");
            check(sample(policy, 4, "A", missing(4, "A")).consecutive == 1,
                    "invalid path evidence did not clear confirmation");
        }
    }

    private static void run(String name, Runnable test) {
        test.run(); passed++; System.out.println("PASS " + name);
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
