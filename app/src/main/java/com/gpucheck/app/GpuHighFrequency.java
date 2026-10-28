package com.gpucheck.app;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** Sustained retired-counter activity in individual GPU slots; no PID or frame attribution. */
public final class GpuHighFrequency {
    public static final double MIN_RATE_PER_SECOND = 30;
    public static final long MIN_DURATION_MS = 10_000;
    public static final int MIN_SAMPLES = 3;
    private static final long SECOND = 1_000_000_000L;
    private static final long MAX_INTERVAL_NS = 10 * SECOND;
    private static final long TIMING_TOLERANCE_NS = 100_000_000L;
    private static final int MAX_SLOTS = 4096;

    public static final class Slot {
        public final int id, sampleCount;
        public final double ratePerSecond;
        public final long sustainedMs;
        Slot(int id, double ratePerSecond, long sustainedMs, int sampleCount) {
            this.id = id;
            this.ratePerSecond = ratePerSecond;
            this.sustainedMs = sustainedMs;
            this.sampleCount = sampleCount;
        }
    }

    public static final class Result {
        public final boolean active;
        public final List<Slot> slots;
        Result(List<Slot> slots) {
            this.slots = Collections.unmodifiableList(slots);
            this.active = !slots.isEmpty();
        }
    }

    private long[] sustainedNs = new long[0];
    private int[] samples = new int[0];
    private long lastNs;
    private int lastFirst = -1, lastEnd = -1;

    public void reset() {
        sustainedNs = new long[0];
        samples = new int[0];
        lastNs = 0;
        lastFirst = lastEnd = -1;
    }

    public Result update(long now, long intervalNs, boolean sampled, double[] deltas,
                         int firstSlot, int endExclusive, int[]... invalidatedSlots) {
        if (!sampled || now <= 0 || intervalNs <= 0 || intervalNs > MAX_INTERVAL_NS
                || now <= intervalNs || deltas == null || deltas.length > MAX_SLOTS) {
            reset();
            return new Result(Collections.emptyList());
        }
        int first = Math.max(1, firstSlot);
        int end = Math.min(endExclusive, deltas.length - 7);
        if (first >= end) {
            reset();
            return new Result(Collections.emptyList());
        }
        if (lastNs > 0 && now <= lastNs) {
            // Replayed or out-of-order windows cannot add sustained time.
            Arrays.fill(sustainedNs, 0);
            Arrays.fill(samples, 0);
            return new Result(Collections.emptyList());
        }
        boolean layoutChanged = sustainedNs.length != deltas.length || lastFirst != first || lastEnd != end;
        boolean gap = lastNs > 0 && Math.abs(now - lastNs - intervalNs) > TIMING_TOLERANCE_NS;
        if (layoutChanged) {
            sustainedNs = new long[deltas.length];
            samples = new int[deltas.length];
        } else if (gap) {
            Arrays.fill(sustainedNs, 0);
            Arrays.fill(samples, 0);
        }
        long coveredNs = lastNs > 0 && !gap && !layoutChanged ? Math.min(intervalNs, now - lastNs) : intervalNs;
        lastNs = now;
        lastFirst = first;
        lastEnd = end;

        boolean[] invalid = new boolean[deltas.length];
        if (invalidatedSlots != null) for (int[] ids : invalidatedSlots) {
            if (ids == null) continue;
            for (int id : ids) if (id >= first && id < end) invalid[id] = true;
        }
        List<Slot> active = new ArrayList<>();
        for (int id = first; id < end; id++) {
            double rate = deltas[id] * SECOND / intervalNs;
            if (invalid[id] || !Double.isFinite(rate) || rate < MIN_RATE_PER_SECOND) {
                sustainedNs[id] = 0;
                samples[id] = 0;
                continue;
            }
            sustainedNs[id] = Math.min(Long.MAX_VALUE - coveredNs, sustainedNs[id]) + coveredNs;
            if (samples[id] < Integer.MAX_VALUE) samples[id]++;
            if (sustainedNs[id] >= MIN_DURATION_MS * 1_000_000L && samples[id] >= MIN_SAMPLES) {
                active.add(new Slot(id, rate, sustainedNs[id] / 1_000_000L, samples[id]));
            }
        }
        return new Result(active);
    }
}
