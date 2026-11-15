package com.gpucheck.app;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Stateful heuristic over consecutive measured windows, never over timestamp increments. */
public final class GpuSlotFrequency {
    public static final double THRESHOLD_FPS = 90.0;
    public static final long SUSTAIN_NS = 3_000_000_000L;
    public static final long MAX_GAP_NS = 100_000_000L;
    private static final long MIN_WINDOW_NS = 450_000_000L, MAX_WINDOW_NS = 1_000_000_000L;
    private static final long MAX_ADVANCE = 1L << 24;

    public static final class Observation {
        public final int slot;
        public final boolean eligible;
        public final double fps;
        public final long startedCounter, finishedCounter, retiredStart, retiredEnd;
        public Observation(int slot, boolean eligible, double fps, long startedCounter, long finishedCounter,
                           long retiredStart, long retiredEnd) {
            this.slot = slot; this.eligible = eligible; this.fps = fps;
            this.startedCounter = startedCounter; this.finishedCounter = finishedCounter;
            this.retiredStart = retiredStart; this.retiredEnd = retiredEnd;
        }
    }
    public static final class Result {
        public final Observation observation;
        public final long stableForMs;
        public final boolean alert;
        private Result(Observation observation, long stableNs) {
            this.observation = observation; stableForMs = stableNs / 1_000_000L;
            alert = stableNs >= SUSTAIN_NS;
        }
    }
    private static final class Streak {
        long durationNs, counter, retired;
    }
    private final Map<Integer, Streak> streaks = new HashMap<>();
    private long previousEndNs;

    public void reset() { streaks.clear(); previousEndNs = 0; }
    public void invalidate(Set<Integer> slots) { for (int slot : slots) streaks.remove(slot); }

    public List<Result> update(long startNs, long endNs, List<Observation> observations) {
        List<Result> results = new ArrayList<>();
        long duration = endNs - startNs;
        if (startNs <= 0 || endNs <= startNs || duration < MIN_WINDOW_NS || duration > MAX_WINDOW_NS) {
            reset(); return results;
        }
        // Replayed/overlapping windows cannot seed a new streak, either.
        if (previousEndNs > 0 && startNs < previousEndNs) { reset(); return results; }
        if (previousEndNs > 0 && startNs - previousEndNs > MAX_GAP_NS) streaks.clear();
        previousEndNs = endNs;
        Set<Integer> present = new HashSet<>();
        for (Observation row : observations) {
            if (row.slot < 1 || !present.add(row.slot)) { reset(); return new ArrayList<>(); }
        }
        streaks.keySet().retainAll(present);
        for (Observation row : observations) {
            long sustained = 0;
            boolean high = row.eligible && Double.isFinite(row.fps) && row.fps > THRESHOLD_FPS
                    && continuous(row.startedCounter, row.finishedCounter) && continuous(row.retiredStart, row.retiredEnd);
            if (high) {
                Streak state = streaks.get(row.slot);
                if (state == null || !continuous(state.counter, row.startedCounter)
                        || !continuous(state.retired, row.retiredStart)) state = new Streak();
                state.durationNs = Math.min(Long.MAX_VALUE - duration, state.durationNs) + duration;
                state.counter = row.finishedCounter;
                state.retired = row.retiredEnd;
                streaks.put(row.slot, state); sustained = state.durationNs;
            } else streaks.remove(row.slot);
            results.add(new Result(row, sustained));
        }
        return results;
    }
    private static boolean continuous(long before, long after) {
        return before >= 0 && after <= 0xffffffffL && after >= before && after - before <= MAX_ADVANCE;
    }
}
