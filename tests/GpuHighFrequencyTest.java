package com.gpucheck.app;

public final class GpuHighFrequencyTest {
    private static final long SECOND = 1_000_000_000L;
    private static final long ORIGIN = 1_000_000_000_000L;
    private static final long PERIOD = 2 * SECOND;
    private static int passed;

    public static void main(String[] args) {
        run("same slot needs ten seconds of sustained high activity", GpuHighFrequencyTest::sustained);
        run("threshold is inclusive and rates below it never qualify", GpuHighFrequencyTest::threshold);
        run("a short burst cannot trigger the hint", GpuHighFrequencyTest::burst);
        run("long windows still require three independent samples", GpuHighFrequencyTest::minimumSamples);
        run("activity alternating between slots does not accumulate", GpuHighFrequencyTest::alternatingSlots);
        run("rates from multiple slots are never added together", GpuHighFrequencyTest::separateRates);
        run("an invalid slot does not erase another slot's sustained activity", GpuHighFrequencyTest::independentSlots);
        run("a rate drop clears the active hint and restarts the duration", GpuHighFrequencyTest::rateDrop);
        run("nonfinite and negative counters break a streak", GpuHighFrequencyTest::invalidCounters);
        run("failed or baseline sampling clears the hint", GpuHighFrequencyTest::unavailable);
        run("appearance disappearance reset and wrap restart the slot", GpuHighFrequencyTest::slotEpoch);
        run("internal and trailing reserved slots are excluded", GpuHighFrequencyTest::reservedSlots);
        run("variable intervals use actual elapsed duration and rate", GpuHighFrequencyTest::variableIntervals);
        run("sampling gaps cannot bridge an incomplete streak", GpuHighFrequencyTest::gap);
        run("duplicate and reversed timestamps cannot accumulate duration", GpuHighFrequencyTest::replayedSamples);
        run("layout and user-slot range changes restart observation", GpuHighFrequencyTest::layoutChange);
        run("invalid layout and interval values fail closed", GpuHighFrequencyTest::invalidInput);
        run("new monitoring sessions do not retain activity", GpuHighFrequencyTest::sessionReset);
        System.out.println("GpuHighFrequency: " + passed + " tests passed.");
    }

    private static double[] deltas(double rate1, double rate2, long interval) {
        double[] values = new double[24];
        values[1] = rate1 * interval / SECOND;
        values[2] = rate2 * interval / SECOND;
        return values;
    }
    private static GpuHighFrequency.Result sample(GpuHighFrequency detector, int tick,
                                                   double rate1, double rate2, int[]... changed) {
        return detector.update(ORIGIN + tick * PERIOD, PERIOD, true, deltas(rate1, rate2, PERIOD), 1, 17, changed);
    }
    private static void warmup(GpuHighFrequency detector) {
        for (int tick = 1; tick <= 4; tick++) inactive(sample(detector, tick, 60, 0));
    }
    private static void sustained() {
        GpuHighFrequency detector = new GpuHighFrequency();
        warmup(detector);
        GpuHighFrequency.Result result = sample(detector, 5, 60, 0);
        check(result.active && result.slots.size() == 1, "expected one high-frequency slot");
        GpuHighFrequency.Slot slot = result.slots.get(0);
        check(slot.id == 1 && slot.ratePerSecond == 60 && slot.sustainedMs == 10_000 && slot.sampleCount == 5,
                "incorrect rate or duration evidence");
        check(sample(detector, 6, 120, 0).slots.get(0).sustainedMs == 12_000, "sustained duration did not continue");
    }
    private static void threshold() {
        for (double rate : new double[]{0, 29.999, 30}) {
            GpuHighFrequency detector = new GpuHighFrequency();
            for (int tick = 1; tick <= 20; tick++) {
                check(sample(detector, tick, rate, 0).active == (rate >= 30 && tick >= 5), "threshold boundary mismatch");
            }
        }
    }
    private static void burst() {
        GpuHighFrequency detector = new GpuHighFrequency();
        inactive(sample(detector, 1, 100_000, 0));
        for (int tick = 2; tick < 10; tick++) inactive(sample(detector, tick, 0, 0));
    }
    private static void minimumSamples() {
        GpuHighFrequency detector = new GpuHighFrequency();
        for (int tick = 1; tick <= 3; tick++) {
            GpuHighFrequency.Result result = detector.update(ORIGIN + tick * 10 * SECOND, 10 * SECOND,
                    true, deltas(60, 0, 10 * SECOND), 1, 17);
            check(result.active == (tick == 3), "long interval bypassed the minimum sample count");
        }
    }
    private static void alternatingSlots() {
        GpuHighFrequency detector = new GpuHighFrequency();
        for (int tick = 1; tick <= 20; tick++) {
            inactive(sample(detector, tick, tick % 2 == 0 ? 60 : 0, tick % 2 == 0 ? 0 : 60));
        }
    }
    private static void separateRates() {
        GpuHighFrequency detector = new GpuHighFrequency();
        for (int tick = 1; tick <= 20; tick++) inactive(sample(detector, tick, 25, 25));
    }
    private static void independentSlots() {
        GpuHighFrequency detector = new GpuHighFrequency();
        for (int tick = 1; tick <= 4; tick++) inactive(sample(detector, tick, 60, 120));
        GpuHighFrequency.Result result = sample(detector, 5, Double.NaN, 120, new int[]{1});
        check(result.active && result.slots.size() == 1 && result.slots.get(0).id == 2,
                "one slot's reset affected another slot");
    }
    private static void rateDrop() {
        GpuHighFrequency detector = new GpuHighFrequency();
        warmup(detector);
        check(sample(detector, 5, 60, 0).active, "expected initial match");
        inactive(sample(detector, 6, 29, 0));
        for (int tick = 7; tick <= 10; tick++) inactive(sample(detector, tick, 60, 0));
        check(sample(detector, 11, 60, 0).active, "new sustained interval did not qualify");
    }
    private static void invalidCounters() {
        for (double rate : new double[]{Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY, -10}) {
            GpuHighFrequency detector = new GpuHighFrequency();
            warmup(detector);
            inactive(sample(detector, 5, rate, 0));
            inactive(sample(detector, 6, 60, 0));
        }
    }
    private static void unavailable() {
        GpuHighFrequency detector = new GpuHighFrequency();
        warmup(detector);
        check(sample(detector, 5, 60, 0).active, "expected initial match");
        inactive(detector.update(ORIGIN + 6 * PERIOD, PERIOD, false, deltas(60, 0, PERIOD), 1, 17));
        for (int tick = 7; tick <= 10; tick++) inactive(sample(detector, tick, 60, 0));
        check(sample(detector, 11, 60, 0).active, "failed sampling poisoned future observations");
    }
    private static void slotEpoch() {
        for (int source = 0; source < 4; source++) {
            GpuHighFrequency detector = new GpuHighFrequency();
            warmup(detector);
            int[][] changed = {new int[0], new int[0], new int[0], new int[0]};
            changed[source] = new int[]{1};
            inactive(sample(detector, 5, 60, 0, changed));
            for (int tick = 6; tick <= 9; tick++) inactive(sample(detector, tick, 60, 0));
            check(sample(detector, 10, 60, 0).active, "slot epoch did not restart duration");
        }
    }
    private static void reservedSlots() {
        GpuHighFrequency detector = new GpuHighFrequency();
        double[] values = new double[24];
        values[0] = 240;
        for (int id = 17; id < 24; id++) values[id] = 240;
        for (int tick = 1; tick <= 10; tick++) {
            inactive(detector.update(ORIGIN + tick * PERIOD, PERIOD, true, values, 0, 24));
        }
    }
    private static void variableIntervals() {
        GpuHighFrequency detector = new GpuHighFrequency();
        long time = ORIGIN;
        long[] intervals = {2 * SECOND, 3 * SECOND, 2 * SECOND, 3 * SECOND};
        for (int i = 0; i < intervals.length; i++) {
            time += intervals[i];
            GpuHighFrequency.Result result = detector.update(time, intervals[i], true,
                    deltas(60, 0, intervals[i]), 1, 17);
            check(result.active == (i == 3), "duration was based on window count instead of elapsed time");
            if (result.active) check(result.slots.get(0).ratePerSecond == 60
                    && result.slots.get(0).sustainedMs == 10_000, "variable interval conversion is incorrect");
        }
    }
    private static void gap() {
        GpuHighFrequency detector = new GpuHighFrequency();
        warmup(detector);
        for (int tick = 10; tick <= 13; tick++) inactive(sample(detector, tick, 60, 0));
        check(sample(detector, 14, 60, 0).active, "post-gap streak did not start over");
    }
    private static void replayedSamples() {
        GpuHighFrequency detector = new GpuHighFrequency();
        warmup(detector);
        for (int i = 0; i < 5; i++) inactive(sample(detector, 4, 60, 0));
        inactive(sample(detector, 3, 60, 0));
        for (int tick = 5; tick <= 8; tick++) inactive(sample(detector, tick, 60, 0));
        check(sample(detector, 9, 60, 0).active, "valid samples did not recover after replays");
    }
    private static void layoutChange() {
        for (boolean resize : new boolean[]{true, false}) {
            GpuHighFrequency detector = new GpuHighFrequency();
            warmup(detector);
            double[] values = new double[resize ? 32 : 24];
            values[1] = 120;
            int end = resize ? 25 : 16;
            for (int tick = 5; tick <= 8; tick++) {
                inactive(detector.update(ORIGIN + tick * PERIOD, PERIOD, true, values, 1, end));
            }
            check(detector.update(ORIGIN + 9 * PERIOD, PERIOD, true, values, 1, end).active,
                    "layout change failed to rebuild the streak");
        }
    }
    private static void invalidInput() {
        for (long interval : new long[]{0, -1, 11 * SECOND}) {
            GpuHighFrequency detector = new GpuHighFrequency();
            warmup(detector);
            inactive(detector.update(ORIGIN + 5 * PERIOD, interval, true, deltas(60, 0, PERIOD), 1, 17));
            inactive(sample(detector, 6, 60, 0));
        }
        GpuHighFrequency detector = new GpuHighFrequency();
        inactive(detector.update(0, PERIOD, true, deltas(60, 0, PERIOD), 1, 17));
        inactive(detector.update(ORIGIN, PERIOD, true, null, 1, 17));
        inactive(detector.update(ORIGIN, PERIOD, true, new double[4097], 1, 4090));
        inactive(detector.update(ORIGIN, PERIOD, true, new double[8], 1, 1));
        inactive(detector.update(ORIGIN, PERIOD, true, new double[24], 20, 17));
    }
    private static void sessionReset() {
        GpuHighFrequency detector = new GpuHighFrequency();
        warmup(detector);
        check(sample(detector, 5, 60, 0).active, "expected initial match");
        detector.reset();
        inactive(sample(detector, 6, 60, 0));
    }
    private static void inactive(GpuHighFrequency.Result result) {
        check(!result.active && result.slots.isEmpty(), "unexpected high-frequency hint");
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
