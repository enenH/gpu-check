package com.gpucheck.app;

import java.util.Arrays;

public final class SelfGpuFilterTest {
    private static final long SECOND = 1_000_000_000L;
    private static final long PERIOD = 2 * SECOND, ORIGIN = 100 * SECOND;
    private static final int SLOT_COUNT = 16, END = SLOT_COUNT - 7, PID = 1024, UID = 10100;
    private static int passed;

    public static void main(String[] args) {
        run("self-only high activity never triggers a hint", SelfGpuFilterTest::selfOnly);
        run("an external slot can qualify while self slots stay excluded", SelfGpuFilterTest::externalActivity);
        run("new self ownership clears an existing external streak immediately", SelfGpuFilterTest::ownershipAcquired);
        run("released self slots wait one query then start a new duration", SelfGpuFilterTest::ownershipReleased);
        run("changed ownership excludes both current and previous owners", SelfGpuFilterTest::ownershipMoves);
        run("multiple and duplicate self IDs are filtered as one sorted set", SelfGpuFilterTest::multipleSlots);
        run("an incomplete query retracts the hint and restarts external observation", SelfGpuFilterTest::incompleteQuery);
        run("missing queries and missing owner arrays fail closed", SelfGpuFilterTest::missingQuery);
        run("failed queries retain only the last successful owner set", SelfGpuFilterTest::failureBetweenQueries);
        run("a complete empty owner query is valid without a GPU fd", SelfGpuFilterTest::emptyOwnership);
        run("owner IDs without a valid GPU fd count are rejected", SelfGpuFilterTest::invalidFdCount);
        run("global reserved and invalid slot IDs reject the full query", SelfGpuFilterTest::invalidIds);
        run("query PID and UID must both match the observer", SelfGpuFilterTest::identityMismatch);
        run("query must cover the exact effective user-slot range", SelfGpuFilterTest::rangeMismatch);
        run("layout changes discard stale owner IDs", SelfGpuFilterTest::layoutChanged);
        run("layout changes also restart high-frequency duration", SelfGpuFilterTest::frequencyLayoutChanged);
        run("queries must follow the current sample and finish within its interval", SelfGpuFilterTest::queryTiming);
        run("replayed and reversed samples cannot release a previous self slot", SelfGpuFilterTest::sampleReplay);
        run("baseline invalid timing and invalid layouts never enable detection", SelfGpuFilterTest::invalidSamples);
        run("session reset discards previous ownership", SelfGpuFilterTest::sessionReset);
        run("caller array mutations cannot change remembered owners", SelfGpuFilterTest::arrayIsolation);
        System.out.println("SelfGpuFilter: " + passed + " tests passed.");
    }

    private static long time(int tick) { return ORIGIN + tick * PERIOD; }

    private static SelfGpuFilter.Query query(int tick, int... slots) {
        return new SelfGpuFilter.Query(true, slots, 1, END,
                time(tick) + 1_000_000, time(tick) + 2_000_000, PID, UID, 1);
    }

    private static SelfGpuFilter.Result sample(SelfGpuFilter filter, int tick, SelfGpuFilter.Query query) {
        return filter.update(time(tick), PERIOD, SLOT_COUNT, 1, END, PID, UID, query);
    }

    private static GpuHighFrequency.Result frequency(SelfGpuFilter filter, GpuHighFrequency detector,
                                                     int tick, SelfGpuFilter.Query query,
                                                     double first, double second) {
        SelfGpuFilter.Result owners = sample(filter, tick, query);
        return detector.update(time(tick), PERIOD, owners.ready, deltas(SLOT_COUNT, first, second),
                1, END, owners.excludedSlots);
    }

    private static double[] deltas(int length, double first, double second) {
        double[] values = new double[length];
        values[1] = first;
        values[2] = second;
        return values;
    }

    private static void selfOnly() {
        SelfGpuFilter filter = new SelfGpuFilter();
        GpuHighFrequency detector = new GpuHighFrequency();
        for (int tick = 1; tick <= 20; tick++) {
            check(!frequency(filter, detector, tick, query(tick, 1, 2), 600, 120).active,
                    "self activity must never qualify");
        }
    }

    private static void externalActivity() {
        SelfGpuFilter filter = new SelfGpuFilter();
        GpuHighFrequency detector = new GpuHighFrequency();
        for (int tick = 1; tick <= 6; tick++) {
            GpuHighFrequency.Result result = frequency(filter, detector, tick, query(tick, 1), 600, 60);
            check(result.active == (tick >= 5), "external slot uses the unchanged ten-second threshold");
            if (result.active) check(result.slots.size() == 1 && result.slots.get(0).id == 2,
                    "the owner slot must stay absent");
        }
    }

    private static void ownershipAcquired() {
        SelfGpuFilter filter = new SelfGpuFilter();
        GpuHighFrequency detector = new GpuHighFrequency();
        for (int tick = 1; tick <= 5; tick++) frequency(filter, detector, tick, query(tick), 60, 0);
        check(!frequency(filter, detector, 6, query(6, 1), 60, 0).active,
                "newly discovered self ownership must immediately retract the hint");
    }

    private static void ownershipReleased() {
        SelfGpuFilter filter = new SelfGpuFilter();
        GpuHighFrequency detector = new GpuHighFrequency();
        for (int tick = 1; tick <= 5; tick++) frequency(filter, detector, tick, query(tick, 1), 60, 0);
        check(!frequency(filter, detector, 6, query(6), 60, 0).active, "first owner-free query still holds the slot");
        for (int tick = 7; tick <= 10; tick++) {
            check(!frequency(filter, detector, tick, query(tick), 60, 0).active,
                    "reused external slot must rebuild ten seconds from release");
        }
        check(frequency(filter, detector, 11, query(11), 60, 0).active,
                "released slot must not remain excluded permanently");
    }

    private static void ownershipMoves() {
        SelfGpuFilter filter = new SelfGpuFilter();
        ids(sample(filter, 1, query(1, 1)), 1);
        ids(sample(filter, 2, query(2, 2)), 1, 2);
        ids(sample(filter, 3, query(3)), 2);
        ids(sample(filter, 4, query(4)));
    }

    private static void multipleSlots() {
        SelfGpuFilter.Result result = sample(new SelfGpuFilter(), 1, query(1, 7, 2, 2, 1, 7));
        ids(result, 1, 2, 7);
        check(Arrays.equals(result.currentSlots, new int[]{1, 2, 7}), "current ownership must also be deduplicated");
    }

    private static void incompleteQuery() {
        SelfGpuFilter filter = new SelfGpuFilter();
        GpuHighFrequency detector = new GpuHighFrequency();
        for (int tick = 1; tick <= 5; tick++) frequency(filter, detector, tick, query(tick), 0, 60);
        SelfGpuFilter.Query partial = new SelfGpuFilter.Query(false, new int[0], 1, END,
                time(6) + 1, time(6) + 2, PID, UID, 1);
        check(!frequency(filter, detector, 6, partial, 0, 60).active, "partial owner knowledge must hide an active hint");
        for (int tick = 7; tick <= 10; tick++) {
            check(!frequency(filter, detector, tick, query(tick), 0, 60).active,
                    "unfiltered windows must not bridge an external streak");
        }
        check(frequency(filter, detector, 11, query(11), 0, 60).active, "five new filtered windows may qualify");
    }

    private static void missingQuery() {
        check(!sample(new SelfGpuFilter(), 1, null).ready, "missing owner query is not an empty successful query");
        SelfGpuFilter.Query absentIds = new SelfGpuFilter.Query(true, null, 1, END,
                time(1) + 1, time(1) + 2, PID, UID, 1);
        check(!sample(new SelfGpuFilter(), 1, absentIds).ready, "missing owner array must fail closed");
    }

    private static void failureBetweenQueries() {
        SelfGpuFilter filter = new SelfGpuFilter();
        ids(sample(filter, 1, query(1, 1)), 1);
        check(!sample(filter, 2, null).ready, "missing query must disable detection");
        ids(sample(filter, 3, query(3, 2)), 1, 2);
        ids(sample(filter, 4, query(4)), 2);
        ids(sample(filter, 5, query(5)));
    }

    private static void emptyOwnership() {
        SelfGpuFilter.Query empty = new SelfGpuFilter.Query(true, new int[0], 1, END,
                time(1) + 1, time(1) + 2, PID, UID, 0);
        ids(sample(new SelfGpuFilter(), 1, empty));
    }

    private static void invalidFdCount() {
        for (int count : new int[]{-1, 0}) {
            SelfGpuFilter.Query invalid = new SelfGpuFilter.Query(true, new int[]{1}, 1, END,
                    time(1) + 1, time(1) + 2, PID, UID, count);
            check(!sample(new SelfGpuFilter(), 1, invalid).ready, "owner IDs require an enumerated GPU fd");
        }
    }

    private static void invalidIds() {
        for (int invalid : new int[]{-1, 0, END, SLOT_COUNT - 1, Integer.MAX_VALUE}) {
            SelfGpuFilter.Result result = sample(new SelfGpuFilter(), 1, query(1, 1, invalid));
            check(!result.ready && result.excludedSlots.length == 0, "a malformed owner set cannot partially pass");
        }
    }

    private static void identityMismatch() {
        for (int[] owner : new int[][]{{PID + 1, UID}, {PID, UID + 1}, {-1, UID}, {PID, -1}}) {
            SelfGpuFilter.Query invalid = new SelfGpuFilter.Query(true, new int[]{1}, 1, END,
                    time(1) + 1, time(1) + 2, owner[0], owner[1], 1);
            check(!sample(new SelfGpuFilter(), 1, invalid).ready, "owner query must come from this process and UID");
        }
    }

    private static void rangeMismatch() {
        for (int[] range : new int[][]{{0, END}, {2, END}, {1, END - 1}, {1, END + 1}}) {
            SelfGpuFilter.Query invalid = new SelfGpuFilter.Query(true, new int[]{2}, range[0], range[1],
                    time(1) + 1, time(1) + 2, PID, UID, 1);
            check(!sample(new SelfGpuFilter(), 1, invalid).ready, "query must enumerate the complete effective range");
        }
        SelfGpuFilter.Query clipped = new SelfGpuFilter.Query(true, new int[0], 1, 5,
                time(1) + 1, time(1) + 2, PID, UID, 1);
        check(new SelfGpuFilter().update(time(1), PERIOD, SLOT_COUNT, 1, 5, PID, UID, clipped).ready,
                "a narrower native user range is accepted when the query exactly covers it");
    }

    private static void layoutChanged() {
        SelfGpuFilter filter = new SelfGpuFilter();
        ids(sample(filter, 1, query(1, 1)), 1);
        SelfGpuFilter.Query changed = new SelfGpuFilter.Query(true, new int[0], 1, 17,
                time(2) + 1, time(2) + 2, PID, UID, 1);
        ids(filter.update(time(2), PERIOD, 24, 1, 17, PID, UID, changed));
        check(!filter.update(time(3), PERIOD, 24, 1, 17, PID, UID, query(3)).ready,
                "old-range queries cannot be applied to a new layout");
    }

    private static void frequencyLayoutChanged() {
        SelfGpuFilter filter = new SelfGpuFilter();
        GpuHighFrequency detector = new GpuHighFrequency();
        for (int tick = 1; tick <= 4; tick++) frequency(filter, detector, tick, query(tick), 0, 60);
        SelfGpuFilter.Query changed = new SelfGpuFilter.Query(true, new int[0], 1, 17,
                time(5) + 1, time(5) + 2, PID, UID, 1);
        SelfGpuFilter.Result owners = filter.update(time(5), PERIOD, 24, 1, 17, PID, UID, changed);
        check(!detector.update(time(5), PERIOD, owners.ready, deltas(24, 0, 60),
                1, 17, owners.excludedSlots).active, "new layout must not complete the old streak");
    }

    private static void queryTiming() {
        for (long[] times : new long[][]{{0, 0}, {time(1) - 1, time(1) + 1},
                {time(1) + 2, time(1) + 1}, {time(1) + 1, time(1) + PERIOD + 1}}) {
            SelfGpuFilter.Query invalid = new SelfGpuFilter.Query(true, new int[0], 1, END,
                    times[0], times[1], PID, UID, 1);
            check(!sample(new SelfGpuFilter(), 1, invalid).ready, "stale, inverted and late queries must fail closed");
        }
    }

    private static void sampleReplay() {
        SelfGpuFilter filter = new SelfGpuFilter();
        ids(sample(filter, 2, query(2, 1)), 1);
        check(!sample(filter, 2, query(2)).ready, "duplicate sample must not release a self slot");
        check(!sample(filter, 1, query(1)).ready, "reversed sample must not release a self slot");
        ids(sample(filter, 3, query(3)), 1);
        ids(sample(filter, 4, query(4)));
    }

    private static void invalidSamples() {
        for (long interval : new long[]{0, -1, 11 * SECOND, Long.MAX_VALUE}) {
            check(!new SelfGpuFilter().update(time(1), interval, SLOT_COUNT, 1, END, PID, UID, query(1)).ready,
                    "invalid intervals cannot enable a filter");
        }
        for (int length : new int[]{Integer.MIN_VALUE, -1, 0, 8, 4097}) {
            check(!new SelfGpuFilter().update(time(1), PERIOD, length, 1, END, PID, UID, query(1)).ready,
                    "invalid slot counts cannot enable a filter");
        }
        check(!new SelfGpuFilter().update(0, PERIOD, SLOT_COUNT, 1, END, PID, UID, query(1)).ready,
                "missing sample clock must fail closed");
    }

    private static void sessionReset() {
        SelfGpuFilter filter = new SelfGpuFilter();
        ids(sample(filter, 1, query(1, 1)), 1);
        filter.reset();
        ids(sample(filter, 1, query(1)));
    }

    private static void arrayIsolation() {
        SelfGpuFilter filter = new SelfGpuFilter();
        int[] input = {1};
        SelfGpuFilter.Query first = new SelfGpuFilter.Query(true, input, 1, END,
                time(1) + 1, time(1) + 2, PID, UID, 1);
        input[0] = 2;
        SelfGpuFilter.Result result = sample(filter, 1, first);
        ids(result, 1);
        result.currentSlots[0] = 3;
        result.excludedSlots[0] = 4;
        ids(sample(filter, 2, query(2)), 1);
    }

    private static void ids(SelfGpuFilter.Result result, int... expected) {
        check(result.ready, "expected a complete valid query, got " + result.reason);
        check(Arrays.equals(result.excludedSlots, expected),
                "expected exclusions " + Arrays.toString(expected) + ", got " + Arrays.toString(result.excludedSlots));
    }

    private static void run(String name, Runnable test) {
        test.run();
        passed++;
        System.out.println("PASS " + name);
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
