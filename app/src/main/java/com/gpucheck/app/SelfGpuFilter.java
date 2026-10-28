package com.gpucheck.app;

import java.util.Arrays;

/** Validates current-process KGSL ownership queries before filtering high-frequency hints. */
public final class SelfGpuFilter {
    private static final int MAX_SLOTS = 4096;
    private static final long MAX_INTERVAL_NS = 10_000_000_000L;

    public static final class Query {
        public final boolean complete;
        public final int[] slots;
        public final int firstSlot, endExclusive, pid, uid, gpuFdCount;
        public final long startedMonotonicNs, finishedMonotonicNs;

        public Query(boolean complete, int[] slots, int firstSlot, int endExclusive,
                     long startedMonotonicNs, long finishedMonotonicNs,
                     int pid, int uid, int gpuFdCount) {
            this.complete = complete;
            this.slots = slots == null ? null : slots.clone();
            this.firstSlot = firstSlot;
            this.endExclusive = endExclusive;
            this.startedMonotonicNs = startedMonotonicNs;
            this.finishedMonotonicNs = finishedMonotonicNs;
            this.pid = pid;
            this.uid = uid;
            this.gpuFdCount = gpuFdCount;
        }
    }

    public static final class Result {
        public final boolean ready;
        public final int[] excludedSlots;
        public final int[] currentSlots;
        public final String reason;

        private Result(boolean ready, int[] excludedSlots, int[] currentSlots, String reason) {
            this.ready = ready;
            this.excludedSlots = excludedSlots;
            this.currentSlots = currentSlots;
            this.reason = reason;
        }
    }

    private int[] previousSlots = new int[0];
    private int previousLength = -1, previousEnd = -1, previousPid = -1, previousUid = -1;
    private long latestSampleNs, previousQueryFinishedNs;

    public void reset() {
        previousSlots = new int[0];
        previousLength = previousEnd = previousPid = previousUid = -1;
        latestSampleNs = previousQueryFinishedNs = 0;
    }

    public Result update(long sampleMonotonicNs, long intervalNs, int slotCount,
                         int firstSlot, int endExclusive, int expectedPid, int expectedUid,
                         Query query) {
        int end = Math.min(endExclusive, slotCount - 7);
        if (sampleMonotonicNs <= 0 || intervalNs <= 0 || intervalNs > MAX_INTERVAL_NS
                || sampleMonotonicNs <= intervalNs || slotCount <= 8 || slotCount > MAX_SLOTS
                || firstSlot != 1 || end <= 1 || expectedPid <= 0 || expectedUid < 0) {
            reset();
            return unavailable("invalid_sample");
        }
        if (latestSampleNs > 0 && sampleMonotonicNs <= latestSampleNs) {
            return unavailable("replayed_sample");
        }
        latestSampleNs = sampleMonotonicNs;
        if (previousLength != slotCount || previousEnd != end
                || previousPid != expectedPid || previousUid != expectedUid) {
            previousSlots = new int[0];
            previousQueryFinishedNs = 0;
            previousLength = slotCount;
            previousEnd = end;
            previousPid = expectedPid;
            previousUid = expectedUid;
        }
        if (query == null) return unavailable("missing_query");
        if (!query.complete) return unavailable("incomplete_query");
        if (query.firstSlot != 1 || query.endExclusive != end) return unavailable("layout_mismatch");
        if (query.pid != expectedPid || query.uid != expectedUid) return unavailable("identity_mismatch");
        if (query.startedMonotonicNs < sampleMonotonicNs
                || query.finishedMonotonicNs < query.startedMonotonicNs
                || query.finishedMonotonicNs - sampleMonotonicNs > intervalNs
                || query.startedMonotonicNs < previousQueryFinishedNs) {
            return unavailable("invalid_query_time");
        }
        if (query.slots == null || query.slots.length > MAX_SLOTS || query.gpuFdCount < 0
                || (query.gpuFdCount == 0 && query.slots.length > 0)) {
            return unavailable("invalid_ownership");
        }
        boolean[] current = new boolean[slotCount];
        for (int id : query.slots) {
            if (id < 1 || id >= end) return unavailable("invalid_slot");
            current[id] = true;
        }
        int[] currentSlots = ids(current);
        for (int id : previousSlots) current[id] = true;
        int[] excludedSlots = ids(current);
        // Keep only this successful query, so a retired self slot is released after one query.
        // Failed queries suppress detection; retaining the last success bridges that uncertainty.
        previousSlots = currentSlots.clone();
        previousQueryFinishedNs = query.finishedMonotonicNs;
        return new Result(true, excludedSlots, currentSlots, "ready");
    }

    private static Result unavailable(String reason) {
        return new Result(false, new int[0], new int[0], reason);
    }

    private static int[] ids(boolean[] included) {
        int[] result = new int[included.length];
        int count = 0;
        for (int id = 1; id < included.length; id++) if (included[id]) result[count++] = id;
        return Arrays.copyOf(result, count);
    }
}
