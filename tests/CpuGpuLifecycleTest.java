package com.gpucheck.app;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** Deterministic lifecycle traces; no Android process or GPU operations. */
public final class CpuGpuLifecycleTest {
    private static final long ORIGIN = 1_000_000_000_000L;
    private static final long PERIOD = 2_000_000_000L;
    private static final int[] NONE = new int[0];
    private static int passed;

    public static void main(String[] args) {
        run("baseline is not a process or slot appearance", CpuGpuLifecycleTest::baseline);
        run("new active slot needs two subsequent CPU/GPU rounds", CpuGpuLifecycleTest::onset);
        run("confirmed onset survives the thirty-second event expiry", CpuGpuLifecycleTest::confirmedOnsetExpiry);
        run("confirmed onset survives idle load and slot disappearance or reuse", CpuGpuLifecycleTest::confirmedOnsetSlotChanges);
        run("confirmed onset survives unavailable GPU data and layout changes", CpuGpuLifecycleTest::confirmedOnsetMissingGpu);
        run("confirmed onset survives sampling gaps and window resets", CpuGpuLifecycleTest::confirmedOnsetSamplingReset);
        run("temporarily missing process rows retain the first onset match", CpuGpuLifecycleTest::confirmedOnsetMissingRows);
        run("later competition does not rewrite a recorded onset match", CpuGpuLifecycleTest::confirmedOnsetLaterCompetition);
        run("verified exit clears onset even when GPU sampling is unavailable", CpuGpuLifecycleTest::confirmedOnsetExit);
        run("unverified exits cannot clear a recorded onset match", CpuGpuLifecycleTest::confirmedOnsetInvalidExit);
        run("a new pidfd identity retires the previous onset match", CpuGpuLifecycleTest::confirmedOnsetReplacementEvent);
        run("session reset and explicit revocation clear recorded onset matches", CpuGpuLifecycleTest::confirmedOnsetCleanup);
        run("unrecognized root birth is cached until verified", CpuGpuLifecycleTest::delayedRoot);
        run("unrecognized process events never produce results", CpuGpuLifecycleTest::unknownRoot);
        run("appearance outside one window is not linked", CpuGpuLifecycleTest::outsideWindow);
        run("one-window plus 10 ms and inclusive 100 ms onset tolerance", CpuGpuLifecycleTest::onsetTolerance);
        run("more than one-window plus 100 ms is rejected", CpuGpuLifecycleTest::outsideTolerance);
        run("leading slot receives the same measurement tolerance", CpuGpuLifecycleTest::leadingSlotTolerance);
        run("competing roots use the same tolerance as onset matching", CpuGpuLifecycleTest::competitionTolerance);
        run("late root binding preserves the original tolerant event window", CpuGpuLifecycleTest::delayedRootTolerance);
        run("slot appearance one window before PID is allowed", CpuGpuLifecycleTest::slotBeforePid);
        run("CPU below threshold resets onset confirmation", CpuGpuLifecycleTest::lowCpu);
        run("GPU rate below threshold resets onset confirmation", CpuGpuLifecycleTest::lowRate);
        run("simultaneous root appearances remain ambiguous", CpuGpuLifecycleTest::multipleBirths);
        run("unconfirmed non-root event is not a root competitor", CpuGpuLifecycleTest::unknownCompetitor);
        run("pidfd exit plus three valid zeros produces an exit hint", CpuGpuLifecycleTest::threeZeros);
        run("disappearance needs a following valid zero", CpuGpuLifecycleTest::disappearanceConfirmation);
        run("slot reuse cancels disappearance confirmation", CpuGpuLifecycleTest::reuseAfterDisappearance);
        run("all busy slots stopping is ambiguous", CpuGpuLifecycleTest::globalStop);
        run("a single busy slot stopping is also ambiguous", CpuGpuLifecycleTest::singleBusySlot);
        run("simultaneous root exits remain ambiguous", CpuGpuLifecycleTest::multipleExits);
        run("missing process rows are not exit events", CpuGpuLifecycleTest::missingRow);
        run("poll errors and guessed exit evidence are rejected", CpuGpuLifecycleTest::invalidExitEvidence);
        run("unavailable GPU samples are not zero progress", CpuGpuLifecycleTest::missingSample);
        run("ordinary reset is not a slot disappearance", CpuGpuLifecycleTest::resetIsNotDeath);
        run("resumed progress immediately retracts an exit hint", CpuGpuLifecycleTest::resumeRetracts);
        run("exit confirmation is limited to eight seconds", CpuGpuLifecycleTest::exitDeadline);
        run("exit hints expire after ten seconds", CpuGpuLifecycleTest::exitDisplayTtl);
        run("remembered root identity expires after thirty seconds", CpuGpuLifecycleTest::rootTtl);
        run("unknown-root appearance cache expires", CpuGpuLifecycleTest::birthTtl);
        run("PID token reuse does not inherit onset evidence", CpuGpuLifecycleTest::tokenReuse);
        run("reset clears session events and root memory", CpuGpuLifecycleTest::sessionReset);
        run("global and trailing reserved slots cannot match", CpuGpuLifecycleTest::reservedSlots);
        run("forged APPEARED evidence is rejected", CpuGpuLifecycleTest::invalidBirthEvidence);
        run("explicit non-root revocation clears root binding", CpuGpuLifecycleTest::revokeRoot);
        run("revocation also retracts an existing exit hint", CpuGpuLifecycleTest::revokeExit);
        run("live candidate output is bounded", CpuGpuLifecycleTest::capacity);
        run("1024 monitored identities retain idle rows and allow onset confirmation", CpuGpuLifecycleTest::fullCapacityOnset);
        run("actual candidate overflow prevents confident onset attribution", CpuGpuLifecycleTest::overflowOnset);
        System.out.println("CpuGpuLifecycle: " + passed + " tests passed.");
    }

    private static long time(int tick) { return ORIGIN + tick * PERIOD; }
    private static List<CpuGpuLifecycle.RootSample> root(double cpu) {
        return Collections.singletonList(new CpuGpuLifecycle.RootSample(42, "A", cpu));
    }
    private static CpuGpuLifecycle.ProcessEvent event(String type, int pid, String token, int tick, String evidence) {
        return new CpuGpuLifecycle.ProcessEvent(type, pid, token, time(tick), evidence);
    }
    private static List<CpuGpuLifecycle.ProcessEvent> birth(int tick) {
        return Collections.singletonList(event("APPEARED", 42, "A", tick, "new_pidfd_after_baseline"));
    }
    private static List<CpuGpuLifecycle.ProcessEvent> death(int tick) {
        return Collections.singletonList(event("EXITED", 42, "A", tick, "pidfd_readable"));
    }
    private static CpuGpuLifecycle.Update sample(CpuGpuLifecycle detector, int tick, boolean sampled,
            double rate1, double rate2, int[] appeared, int[] disappeared, int[] reset,
            List<CpuGpuLifecycle.RootSample> roots, List<CpuGpuLifecycle.ProcessEvent> events) {
        double[] deltas = new double[24];
        deltas[1] = rate1 * 2;
        deltas[2] = rate2 * 2;
        CpuGpuLifecycle.GpuSample gpu = new CpuGpuLifecycle.GpuSample(time(tick), PERIOD, sampled,
                deltas, appeared, disappeared, reset, 1, deltas.length - 7);
        return detector.update(gpu, roots, events);
    }
    private static CpuGpuLifecycle.Update plain(CpuGpuLifecycle detector, int tick, double rate1, double rate2,
            List<CpuGpuLifecycle.RootSample> roots, List<CpuGpuLifecycle.ProcessEvent> events) {
        return sample(detector, tick, true, rate1, rate2, NONE, NONE, NONE, roots, events);
    }
    private static CpuGpuLifecycle.Update shifted(CpuGpuLifecycle detector, int tick, long shift,
            double rate, boolean appeared, List<CpuGpuLifecycle.RootSample> roots,
            List<CpuGpuLifecycle.ProcessEvent> events) {
        double[] deltas = new double[24]; deltas[1] = rate * 2; deltas[2] = 60;
        int[] appearance = appeared ? new int[]{1} : NONE;
        CpuGpuLifecycle.GpuSample gpu = new CpuGpuLifecycle.GpuSample(time(tick) + shift, PERIOD,
                true, deltas, appearance, NONE, appearance, 1, deltas.length - 7);
        return detector.update(gpu, roots, events);
    }
    private static void baselineForExit(CpuGpuLifecycle detector, boolean otherSlot) {
        plain(detector, 0, 20, otherSlot ? 30 : 0, root(50), Collections.emptyList());
        plain(detector, 1, 20, otherSlot ? 30 : 0, root(50), Collections.emptyList());
    }
    private static CpuGpuLifecycle.Result exit(CpuGpuLifecycle.Update update, int pid) {
        for (CpuGpuLifecycle.Result result : update.recentExits) if (result.pid == pid) return result;
        return null;
    }
    private static void baseline() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle();
        sample(detector, 0, true, Double.NaN, 30, new int[]{1}, NONE, new int[]{1}, root(50), birth(0));
        for (int i = 1; i < 5; i++) {
            state(plain(detector, i, 20, 30, root(50), Collections.emptyList()).liveResults.get(42), "NO_EVIDENCE");
        }
    }
    private static void onset() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle();
        plain(detector, 0, 0, 30, Collections.emptyList(), Collections.emptyList());
        CpuGpuLifecycle.Update first = sample(detector, 1, true, Double.NaN, 30, new int[]{1}, NONE,
                new int[]{1}, root(50), birth(1));
        state(first.liveResults.get(42), "PENDING");
        state(plain(detector, 2, 20, 30, root(50), Collections.emptyList()).liveResults.get(42), "PENDING");
        CpuGpuLifecycle.Result result = plain(detector, 3, 20, 30, root(50), Collections.emptyList()).liveResults.get(42);
        state(result, "ONSET_MATCH");
        check(Arrays.equals(result.slots, new int[]{1}) && !result.ownershipConfirmed, "onset scope is incorrect");
    }
    private static CpuGpuLifecycle.Result confirmOnset(CpuGpuLifecycle detector) {
        plain(detector, 0, 0, 30, Collections.emptyList(), Collections.emptyList());
        sample(detector, 1, true, Double.NaN, 30, new int[]{1}, NONE,
                new int[]{1}, root(50), birth(1));
        plain(detector, 2, 20, 30, root(50), Collections.emptyList());
        CpuGpuLifecycle.Result result = plain(detector, 3, 20, 30, root(50), Collections.emptyList()).liveResults.get(42);
        state(result, "ONSET_MATCH");
        return result;
    }
    private static void sameOnset(CpuGpuLifecycle.Result first, CpuGpuLifecycle.Result later) {
        state(later, "ONSET_MATCH");
        check(first.pid == later.pid && first.identityToken.equals(later.identityToken)
                && first.observedMonotonicNs == later.observedMonotonicNs
                && Arrays.equals(first.slots, later.slots) && first.reason.equals(later.reason)
                && !later.ownershipConfirmed, "first match evidence changed after confirmation");
    }
    private static void confirmedOnsetExpiry() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle();
        CpuGpuLifecycle.Result first = confirmOnset(detector);
        for (int i = 4; i <= 80; i++) {
            sameOnset(first, plain(detector, i, 20, 30, root(50), Collections.emptyList()).liveResults.get(42));
        }
    }
    private static void confirmedOnsetSlotChanges() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle();
        CpuGpuLifecycle.Result first = confirmOnset(detector);
        sameOnset(first, plain(detector, 4, 0, 0, root(0), Collections.emptyList()).liveResults.get(42));
        sameOnset(first, sample(detector, 5, true, Double.NaN, 0, NONE, new int[]{1}, new int[]{1},
                root(0), Collections.emptyList()).liveResults.get(42));
        sameOnset(first, sample(detector, 6, true, Double.NaN, 30, new int[]{1}, NONE, new int[]{1},
                root(0), Collections.emptyList()).liveResults.get(42));
        sameOnset(first, plain(detector, 7, 200, 30, root(0), Collections.emptyList()).liveResults.get(42));
    }
    private static void confirmedOnsetMissingGpu() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle();
        CpuGpuLifecycle.Result first = confirmOnset(detector);
        sameOnset(first, sample(detector, 4, false, Double.NaN, Double.NaN, NONE, NONE, NONE,
                root(0), Collections.emptyList()).liveResults.get(42));
        sameOnset(first, detector.update(null, root(0), Collections.emptyList()).liveResults.get(42));
        CpuGpuLifecycle.GpuSample missing = new CpuGpuLifecycle.GpuSample(time(5), PERIOD, false,
                new double[0], NONE, NONE, NONE, 1, 1);
        sameOnset(first, detector.update(missing, root(0), Collections.emptyList()).liveResults.get(42));
        double[] newLayout = new double[32];
        CpuGpuLifecycle.GpuSample resized = new CpuGpuLifecycle.GpuSample(time(6), PERIOD, true,
                newLayout, NONE, NONE, NONE, 1, 25);
        sameOnset(first, detector.update(resized, root(0), Collections.emptyList()).liveResults.get(42));
        sameOnset(first, plain(detector, 7, 20, 30, root(50), Collections.emptyList()).liveResults.get(42));
    }
    private static void confirmedOnsetSamplingReset() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle();
        CpuGpuLifecycle.Result first = confirmOnset(detector);
        sameOnset(first, plain(detector, 20, 0, 0, root(0), Collections.emptyList()).liveResults.get(42));
        detector.resetObservations();
        sameOnset(first, plain(detector, 21, 0, 0, root(0), Collections.emptyList()).liveResults.get(42));
        sameOnset(first, plain(detector, 21, 0, 0, root(0), Collections.emptyList()).liveResults.get(42));
    }
    private static void confirmedOnsetMissingRows() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle();
        CpuGpuLifecycle.Result first = confirmOnset(detector);
        for (int i = 4; i <= 24; i++) {
            check(plain(detector, i, 0, 30, Collections.emptyList(), Collections.emptyList()).liveResults.isEmpty(),
                    "a missing row must not be synthesized as a live process");
        }
        sameOnset(first, detector.confirmedOnset(42, "A"));
        sameOnset(first, plain(detector, 25, 0, 30, root(0), Collections.emptyList()).liveResults.get(42));
    }
    private static void confirmedOnsetLaterCompetition() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle();
        plain(detector, 0, 0, 30, Collections.emptyList(), Collections.emptyList());
        sample(detector, 1, true, Double.NaN, 30, new int[]{1}, NONE, new int[]{1}, root(50),
                Arrays.asList(event("APPEARED", 42, "A", 1, "new_pidfd_after_baseline"),
                        event("APPEARED", 43, "B", 1, "new_pidfd_after_baseline")));
        plain(detector, 2, 20, 30, root(50), Collections.emptyList());
        CpuGpuLifecycle.Result first = plain(detector, 3, 20, 30, root(50), Collections.emptyList()).liveResults.get(42);
        state(first, "ONSET_MATCH");
        List<CpuGpuLifecycle.RootSample> both = Arrays.asList(new CpuGpuLifecycle.RootSample(42, "A", 50),
                new CpuGpuLifecycle.RootSample(43, "B", 50));
        sameOnset(first, plain(detector, 4, 20, 30, both, Collections.emptyList()).liveResults.get(42));
    }
    private static void confirmedOnsetExit() {
        for (boolean gpuAvailable : new boolean[]{true, false}) {
            CpuGpuLifecycle detector = new CpuGpuLifecycle();
            confirmOnset(detector);
            if (gpuAvailable) plain(detector, 4, 0, 30, Collections.emptyList(), death(4));
            else detector.update(null, Collections.emptyList(), death(4));
            check(detector.confirmedOnset(42, "A") == null, "exited identity retained its live match");
            notMatch(plain(detector, 5, 20, 30, root(50), Collections.emptyList()).liveResults.get(42));
        }
    }
    private static void confirmedOnsetInvalidExit() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle();
        CpuGpuLifecycle.Result first = confirmOnset(detector);
        for (String evidence : new String[]{null, "", "poll_error", "missing_from_snapshot", "pidfd_poll_timeout"}) {
            sameOnset(first, plain(detector, 4, 0, 30, root(0),
                    Collections.singletonList(event("EXITED", 42, "A", 4, evidence))).liveResults.get(42));
        }
        sameOnset(first, plain(detector, 5, 0, 30, root(0),
                Collections.singletonList(event("EXITED", 42, "old", 5, "pidfd_readable"))).liveResults.get(42));
        sameOnset(first, plain(detector, 6, 0, 30, root(0),
                Collections.singletonList(event("EXITED", 42, "A", 40, "pidfd_readable"))).liveResults.get(42));
    }
    private static void confirmedOnsetReplacementEvent() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle();
        confirmOnset(detector);
        detector.update(null, Collections.emptyList(),
                Collections.singletonList(event("APPEARED", 42, "B", 4, "new_pidfd_after_baseline")));
        check(detector.confirmedOnset(42, "A") == null, "replacement pidfd retained the old match");
        check(detector.confirmedOnset(42, "B") == null, "replacement pidfd inherited the old match");
    }
    private static void confirmedOnsetCleanup() {
        for (boolean newSession : new boolean[]{true, false}) {
            CpuGpuLifecycle detector = new CpuGpuLifecycle();
            confirmOnset(detector);
            if (newSession) detector.reset();
            else detector.revoke(42, "A");
            check(detector.confirmedOnset(42, "A") == null, "explicit cleanup retained the match");
            notMatch(plain(detector, 4, 20, 30, root(50), Collections.emptyList()).liveResults.get(42));
        }
    }
    private static void delayedRoot() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle();
        plain(detector, 0, 0, 30, Collections.emptyList(), Collections.emptyList());
        sample(detector, 1, true, Double.NaN, 30, new int[]{1}, NONE, new int[]{1}, Collections.emptyList(), birth(1));
        plain(detector, 2, 20, 30, Collections.emptyList(), Collections.emptyList());
        state(plain(detector, 3, 20, 30, root(50), Collections.emptyList()).liveResults.get(42), "PENDING");
        state(plain(detector, 4, 20, 30, root(50), Collections.emptyList()).liveResults.get(42), "ONSET_MATCH");
    }
    private static void unknownRoot() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle();
        plain(detector, 0, 0, 30, Collections.emptyList(), Collections.emptyList());
        sample(detector, 1, true, Double.NaN, 30, new int[]{1}, NONE, new int[]{1}, Collections.emptyList(), birth(1));
        for (int i = 2; i < 6; i++) {
            CpuGpuLifecycle.Update update = plain(detector, i, 20, 30, Collections.emptyList(), Collections.emptyList());
            check(update.liveResults.isEmpty() && update.recentExits.isEmpty(), "unverified root produced a result");
        }
    }
    private static void outsideWindow() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle();
        plain(detector, 0, 0, 30, Collections.emptyList(), Collections.emptyList());
        plain(detector, 1, 0, 30, root(50), birth(1));
        plain(detector, 2, 0, 30, root(50), Collections.emptyList());
        sample(detector, 3, true, Double.NaN, 30, new int[]{1}, NONE, new int[]{1}, root(50), Collections.emptyList());
        plain(detector, 4, 20, 30, root(50), Collections.emptyList());
        notMatch(plain(detector, 5, 20, 30, root(50), Collections.emptyList()).liveResults.get(42));
    }
    private static void slotBeforePid() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle();
        plain(detector, 0, 0, 30, Collections.emptyList(), Collections.emptyList());
        sample(detector, 1, true, Double.NaN, 30, new int[]{1}, NONE, new int[]{1}, Collections.emptyList(), Collections.emptyList());
        plain(detector, 2, 20, 30, root(50), birth(2));
        state(plain(detector, 3, 20, 30, root(50), Collections.emptyList()).liveResults.get(42), "ONSET_MATCH");
    }
    private static void onsetTolerance() {
        for (long shift : new long[]{10_000_000L, 100_000_000L}) {
            CpuGpuLifecycle detector = new CpuGpuLifecycle();
            plain(detector, 0, 0, 30, Collections.emptyList(), Collections.emptyList());
            plain(detector, 1, 0, 30, root(50), birth(1));
            shifted(detector, 2, shift, Double.NaN, true, root(50), Collections.emptyList());
            state(shifted(detector, 3, shift, 20, false, root(50), Collections.emptyList()).liveResults.get(42), "PENDING");
            state(shifted(detector, 4, shift, 20, false, root(50), Collections.emptyList()).liveResults.get(42), "ONSET_MATCH");
        }
    }
    private static void outsideTolerance() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle();
        long shift = 100_000_001L;
        plain(detector, 0, 0, 30, Collections.emptyList(), Collections.emptyList());
        plain(detector, 1, 0, 30, root(50), birth(1));
        shifted(detector, 2, shift, Double.NaN, true, root(50), Collections.emptyList());
        shifted(detector, 3, shift, 20, false, root(50), Collections.emptyList());
        notMatch(shifted(detector, 4, shift, 20, false, root(50), Collections.emptyList()).liveResults.get(42));
    }
    private static void leadingSlotTolerance() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle();
        long shift = 10_000_000L;
        plain(detector, 0, 0, 30, Collections.emptyList(), Collections.emptyList());
        sample(detector, 1, true, Double.NaN, 30, new int[]{1}, NONE, new int[]{1}, Collections.emptyList(), Collections.emptyList());
        List<CpuGpuLifecycle.ProcessEvent> appeared = Collections.singletonList(new CpuGpuLifecycle.ProcessEvent(
                "APPEARED", 42, "A", time(2) + shift, "new_pidfd_after_baseline"));
        state(shifted(detector, 2, shift, 20, false, root(50), appeared).liveResults.get(42), "PENDING");
        state(shifted(detector, 3, shift, 20, false, root(50), Collections.emptyList()).liveResults.get(42), "ONSET_MATCH");
    }
    private static void competitionTolerance() {
        for (long shift : new long[]{10_000_000L, 100_000_001L}) {
            CpuGpuLifecycle detector = new CpuGpuLifecycle();
            plain(detector, 0, 0, 30, Collections.emptyList(), Collections.emptyList());
            sample(detector, 1, true, Double.NaN, 30, new int[]{1}, NONE, new int[]{1}, root(50), birth(1));
            List<CpuGpuLifecycle.RootSample> roots = Arrays.asList(new CpuGpuLifecycle.RootSample(42, "A", 50),
                    new CpuGpuLifecycle.RootSample(43, "B", 50));
            List<CpuGpuLifecycle.ProcessEvent> later = Collections.singletonList(new CpuGpuLifecycle.ProcessEvent(
                    "APPEARED", 43, "B", time(2) + shift, "new_pidfd_after_baseline"));
            shifted(detector, 2, shift, 20, false, roots, later);
            CpuGpuLifecycle.Update update = shifted(detector, 3, shift, 20, false, roots, Collections.emptyList());
            if (shift <= 100_000_000L) {
                state(update.liveResults.get(42), "AMBIGUOUS");
                state(update.liveResults.get(43), "AMBIGUOUS");
            } else {
                state(update.liveResults.get(42), "ONSET_MATCH");
                notMatch(update.liveResults.get(43));
            }
        }
    }
    private static void delayedRootTolerance() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle();
        long shift = 10_000_000L;
        plain(detector, 0, 0, 30, Collections.emptyList(), Collections.emptyList());
        plain(detector, 1, 0, 30, Collections.emptyList(), birth(1));
        shifted(detector, 2, shift, Double.NaN, true, Collections.emptyList(), Collections.emptyList());
        state(shifted(detector, 3, shift, 20, false, root(50), Collections.emptyList()).liveResults.get(42), "PENDING");
        CpuGpuLifecycle.Result result = shifted(detector, 4, shift, 20, false, root(50), Collections.emptyList()).liveResults.get(42);
        state(result, "ONSET_MATCH");
        check(result.observedMonotonicNs == time(1), "late root binding must preserve the original event time");
    }
    private static void lowCpu() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle();
        plain(detector, 0, 0, 30, Collections.emptyList(), Collections.emptyList());
        sample(detector, 1, true, Double.NaN, 30, new int[]{1}, NONE, new int[]{1}, root(50), birth(1));
        plain(detector, 2, 20, 30, root(50), Collections.emptyList());
        plain(detector, 3, 20, 30, root(19), Collections.emptyList());
        state(plain(detector, 4, 20, 30, root(20), Collections.emptyList()).liveResults.get(42), "PENDING");
        state(plain(detector, 5, 20, 30, root(20), Collections.emptyList()).liveResults.get(42), "ONSET_MATCH");
    }
    private static void lowRate() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle();
        plain(detector, 0, 0, 30, Collections.emptyList(), Collections.emptyList());
        sample(detector, 1, true, Double.NaN, 30, new int[]{1}, NONE, new int[]{1}, root(50), birth(1));
        plain(detector, 2, 10, 30, root(50), Collections.emptyList());
        plain(detector, 3, 9.9, 30, root(50), Collections.emptyList());
        state(plain(detector, 4, 10, 30, root(50), Collections.emptyList()).liveResults.get(42), "PENDING");
        state(plain(detector, 5, 10, 30, root(50), Collections.emptyList()).liveResults.get(42), "ONSET_MATCH");
    }
    private static void multipleBirths() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle();
        List<CpuGpuLifecycle.RootSample> roots = Arrays.asList(new CpuGpuLifecycle.RootSample(42, "A", 50),
                new CpuGpuLifecycle.RootSample(43, "B", 50));
        plain(detector, 0, 0, 30, Collections.emptyList(), Collections.emptyList());
        sample(detector, 1, true, Double.NaN, 30, new int[]{1}, NONE, new int[]{1}, roots,
                Arrays.asList(event("APPEARED", 42, "A", 1, "new_pidfd_after_baseline"),
                        event("APPEARED", 43, "B", 1, "new_pidfd_after_baseline")));
        plain(detector, 2, 20, 30, roots, Collections.emptyList());
        CpuGpuLifecycle.Update update = plain(detector, 3, 20, 30, roots, Collections.emptyList());
        state(update.liveResults.get(42), "AMBIGUOUS"); state(update.liveResults.get(43), "AMBIGUOUS");
    }
    private static void unknownCompetitor() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle();
        plain(detector, 0, 0, 30, Collections.emptyList(), Collections.emptyList());
        sample(detector, 1, true, Double.NaN, 30, new int[]{1}, NONE, new int[]{1}, root(50),
                Arrays.asList(event("APPEARED", 42, "A", 1, "new_pidfd_after_baseline"),
                        event("APPEARED", 43, "B", 1, "new_pidfd_after_baseline")));
        plain(detector, 2, 20, 30, root(50), Collections.emptyList());
        state(plain(detector, 3, 20, 30, root(50), Collections.emptyList()).liveResults.get(42), "ONSET_MATCH");
    }
    private static void threeZeros() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle(); baselineForExit(detector, true);
        state(exit(plain(detector, 2, 0, 30, Collections.emptyList(), death(2)), 42), "PENDING");
        state(exit(plain(detector, 3, 0, 30, Collections.emptyList(), Collections.emptyList()), 42), "PENDING");
        CpuGpuLifecycle.Result result = exit(plain(detector, 4, 0, 30, Collections.emptyList(), Collections.emptyList()), 42);
        state(result, "EXIT_MATCH");
        check(Arrays.equals(result.slots, new int[]{1}) && !result.ownershipConfirmed, "exit scope is incorrect");
    }
    private static void disappearanceConfirmation() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle(); baselineForExit(detector, true);
        state(exit(sample(detector, 2, true, Double.NaN, 30, NONE, new int[]{1}, new int[]{1},
                Collections.emptyList(), death(2)), 42), "PENDING");
        state(exit(plain(detector, 3, 0, 30, Collections.emptyList(), Collections.emptyList()), 42), "EXIT_MATCH");
    }
    private static void reuseAfterDisappearance() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle(); baselineForExit(detector, true);
        sample(detector, 2, true, Double.NaN, 30, NONE, new int[]{1}, new int[]{1}, Collections.emptyList(), death(2));
        CpuGpuLifecycle.Update update = sample(detector, 3, true, Double.NaN, 30, new int[]{1}, NONE,
                new int[]{1}, Collections.emptyList(), Collections.emptyList());
        notMatch(exit(update, 42));
        notMatch(exit(plain(detector, 4, 0, 30, Collections.emptyList(), Collections.emptyList()), 42));
    }
    private static void globalStop() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle(); baselineForExit(detector, true);
        plain(detector, 2, 0, 0, Collections.emptyList(), death(2));
        plain(detector, 3, 0, 0, Collections.emptyList(), Collections.emptyList());
        state(exit(plain(detector, 4, 0, 0, Collections.emptyList(), Collections.emptyList()), 42), "AMBIGUOUS");
    }
    private static void singleBusySlot() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle(); baselineForExit(detector, false);
        plain(detector, 2, 0, 0, Collections.emptyList(), death(2));
        plain(detector, 3, 0, 0, Collections.emptyList(), Collections.emptyList());
        state(exit(plain(detector, 4, 0, 0, Collections.emptyList(), Collections.emptyList()), 42), "AMBIGUOUS");
    }
    private static void multipleExits() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle();
        List<CpuGpuLifecycle.RootSample> roots = Arrays.asList(new CpuGpuLifecycle.RootSample(42, "A", 50),
                new CpuGpuLifecycle.RootSample(43, "B", 50));
        plain(detector, 0, 20, 30, roots, Collections.emptyList()); plain(detector, 1, 20, 30, roots, Collections.emptyList());
        plain(detector, 2, 0, 30, Collections.emptyList(), Arrays.asList(event("EXITED", 42, "A", 2, "pidfd_readable"),
                event("EXITED", 43, "B", 2, "pidfd_hup")));
        plain(detector, 3, 0, 30, Collections.emptyList(), Collections.emptyList());
        CpuGpuLifecycle.Update update = plain(detector, 4, 0, 30, Collections.emptyList(), Collections.emptyList());
        state(exit(update, 42), "AMBIGUOUS"); state(exit(update, 43), "AMBIGUOUS");
    }
    private static void missingRow() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle(); baselineForExit(detector, true);
        for (int i = 2; i < 6; i++) check(plain(detector, i, 0, 30, Collections.emptyList(),
                Collections.emptyList()).recentExits.isEmpty(), "absence must not synthesize an exit");
    }
    private static void invalidExitEvidence() {
        for (String evidence : new String[]{null, "", "poll_error", "missing_from_snapshot", "pidfd_poll_timeout"}) {
            CpuGpuLifecycle detector = new CpuGpuLifecycle(); baselineForExit(detector, true);
            plain(detector, 2, 0, 30, Collections.emptyList(), Collections.singletonList(event("EXITED", 42, "A", 2, evidence)));
            for (int i = 3; i < 6; i++) check(plain(detector, i, 0, 30, Collections.emptyList(),
                    Collections.emptyList()).recentExits.isEmpty(), "non-confirming exit evidence accepted");
        }
    }
    private static void missingSample() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle(); baselineForExit(detector, true);
        sample(detector, 2, false, 0, 30, NONE, NONE, NONE, Collections.emptyList(), death(2));
        state(exit(plain(detector, 3, 0, 30, Collections.emptyList(), Collections.emptyList()), 42), "PENDING");
        state(exit(plain(detector, 4, 0, 30, Collections.emptyList(), Collections.emptyList()), 42), "PENDING");
        state(exit(plain(detector, 5, 0, 30, Collections.emptyList(), Collections.emptyList()), 42), "EXIT_MATCH");
    }
    private static void resetIsNotDeath() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle(); baselineForExit(detector, true);
        sample(detector, 2, true, Double.NaN, 30, NONE, NONE, new int[]{1}, Collections.emptyList(), death(2));
        for (int i = 3; i < 6; i++) notMatch(exit(plain(detector, i, 0, 30, Collections.emptyList(), Collections.emptyList()), 42));
    }
    private static void resumeRetracts() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle(); baselineForExit(detector, true);
        plain(detector, 2, 0, 30, Collections.emptyList(), death(2));
        plain(detector, 3, 0, 30, Collections.emptyList(), Collections.emptyList());
        state(exit(plain(detector, 4, 0, 30, Collections.emptyList(), Collections.emptyList()), 42), "EXIT_MATCH");
        check(plain(detector, 5, 1, 30, Collections.emptyList(), Collections.emptyList()).recentExits.isEmpty(),
                "any resumed progress must retract the exit hint");
    }
    private static void exitDeadline() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle(); baselineForExit(detector, true);
        plain(detector, 2, 20, 30, Collections.emptyList(), death(2));
        plain(detector, 3, 20, 30, Collections.emptyList(), Collections.emptyList());
        plain(detector, 4, 20, 30, Collections.emptyList(), Collections.emptyList());
        plain(detector, 5, 0, 30, Collections.emptyList(), Collections.emptyList());
        plain(detector, 6, 0, 30, Collections.emptyList(), Collections.emptyList());
        state(exit(plain(detector, 7, 0, 30, Collections.emptyList(), Collections.emptyList()), 42), "NO_EVIDENCE");
    }
    private static void exitDisplayTtl() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle(); baselineForExit(detector, true);
        plain(detector, 2, 0, 30, Collections.emptyList(), death(2));
        for (int i = 3; i < 8; i++) plain(detector, i, 0, 30, Collections.emptyList(), Collections.emptyList());
        check(plain(detector, 8, 0, 30, Collections.emptyList(), Collections.emptyList()).recentExits.isEmpty(),
                "exit evidence exceeded its ten-second display TTL");
    }
    private static void rootTtl() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle();
        plain(detector, 0, 20, 30, root(50), Collections.emptyList());
        for (int i = 1; i < 17; i++) plain(detector, i, 20, 30, Collections.emptyList(), Collections.emptyList());
        plain(detector, 17, 0, 30, Collections.emptyList(), death(17));
        for (int i = 18; i < 21; i++) check(plain(detector, i, 0, 30, Collections.emptyList(),
                Collections.emptyList()).recentExits.isEmpty(), "expired root identity was rebound");
    }
    private static void birthTtl() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle();
        plain(detector, 0, 0, 30, Collections.emptyList(), Collections.emptyList());
        sample(detector, 1, true, Double.NaN, 30, new int[]{1}, NONE, new int[]{1}, Collections.emptyList(), birth(1));
        for (int i = 2; i < 18; i++) plain(detector, i, 20, 30, Collections.emptyList(), Collections.emptyList());
        state(plain(detector, 18, 20, 30, root(50), Collections.emptyList()).liveResults.get(42), "NO_EVIDENCE");
    }
    private static void tokenReuse() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle();
        plain(detector, 0, 0, 30, Collections.emptyList(), Collections.emptyList());
        sample(detector, 1, true, Double.NaN, 30, new int[]{1}, NONE, new int[]{1}, root(50), birth(1));
        plain(detector, 2, 20, 30, root(50), Collections.emptyList());
        state(plain(detector, 3, 20, 30, root(50), Collections.emptyList()).liveResults.get(42), "ONSET_MATCH");
        List<CpuGpuLifecycle.RootSample> reused = Collections.singletonList(new CpuGpuLifecycle.RootSample(42, "B", 50));
        CpuGpuLifecycle.Result result = plain(detector, 4, 20, 30, reused, Collections.emptyList()).liveResults.get(42);
        state(result, "NO_EVIDENCE"); check("B".equals(result.identityToken), "wrong lifecycle token in result");
        check(detector.confirmedOnset(42, "A") == null, "reused PID retained its previous identity's match");
    }
    private static void sessionReset() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle(); baselineForExit(detector, true);
        detector.reset();
        CpuGpuLifecycle.Update update = plain(detector, 2, 0, 30, Collections.emptyList(), death(2));
        check(update.recentExits.isEmpty(), "new session reused old root identity");
    }
    private static void reservedSlots() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle();
        plain(detector, 0, 0, 30, Collections.emptyList(), Collections.emptyList());
        for (int i = 1; i < 5; i++) {
            double[] delta = new double[24]; delta[0] = delta[23] = 100;
            CpuGpuLifecycle.GpuSample gpu = new CpuGpuLifecycle.GpuSample(time(i), PERIOD, true, delta,
                    i == 1 ? new int[]{0, 23} : NONE, NONE, i == 1 ? new int[]{0, 23} : NONE, 0, 24);
            CpuGpuLifecycle.Update update = detector.update(gpu, root(50), i == 1 ? birth(1) : Collections.emptyList());
            notMatch(update.liveResults.get(42));
        }
    }
    private static void invalidBirthEvidence() {
        for (String evidence : new String[]{null, "", "APPEARED", "metadata_visible", "pidfd_poll_error"}) {
            CpuGpuLifecycle detector = new CpuGpuLifecycle();
            plain(detector, 0, 0, 30, Collections.emptyList(), Collections.emptyList());
            sample(detector, 1, true, Double.NaN, 30, new int[]{1}, NONE, new int[]{1}, Collections.emptyList(),
                    Collections.singletonList(event("APPEARED", 42, "A", 1, evidence)));
            plain(detector, 2, 20, 30, root(50), Collections.emptyList());
            state(plain(detector, 3, 20, 30, root(50), Collections.emptyList()).liveResults.get(42), "NO_EVIDENCE");
        }
    }
    private static void revokeRoot() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle(); baselineForExit(detector, true);
        detector.revoke(42, "A");
        plain(detector, 2, 0, 30, Collections.emptyList(), death(2));
        for (int i = 3; i < 6; i++) check(plain(detector, i, 0, 30, Collections.emptyList(),
                Collections.emptyList()).recentExits.isEmpty(), "explicit non-root evidence did not revoke cached root");
    }
    private static void revokeExit() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle(); baselineForExit(detector, true);
        plain(detector, 2, 0, 30, Collections.emptyList(), death(2));
        plain(detector, 3, 0, 30, Collections.emptyList(), Collections.emptyList());
        state(exit(plain(detector, 4, 0, 30, Collections.emptyList(), Collections.emptyList()), 42), "EXIT_MATCH");
        detector.revoke(42, "A");
        check(plain(detector, 5, 0, 30, Collections.emptyList(), Collections.emptyList()).recentExits.isEmpty(),
                "revocation failed to remove existing exit hint");
    }
    private static void capacity() {
        List<CpuGpuLifecycle.RootSample> many = new ArrayList<>();
        for (int i = 0; i < 1200; i++) many.add(new CpuGpuLifecycle.RootSample(100 + i, "A", 50));
        CpuGpuLifecycle.Update update = plain(new CpuGpuLifecycle(), 0, 20, 30, many, Collections.emptyList());
        check(update.liveResults.size() == 1024, "live candidate limit exceeded");
        check(update.liveResults.containsKey(100) && update.liveResults.containsKey(1123)
                && !update.liveResults.containsKey(1124), "capacity changed caller selection order");
    }
    private static void fullCapacityOnset() {
        List<CpuGpuLifecycle.RootSample> stable = new ArrayList<>();
        for (int i = 0; i < 1023; i++) stable.add(new CpuGpuLifecycle.RootSample(100 + i, "stable:" + i, 0));
        CpuGpuLifecycle detector = new CpuGpuLifecycle();
        plain(detector, 0, 0, 30, stable, Collections.emptyList());
        List<CpuGpuLifecycle.RootSample> current = new ArrayList<>(stable);
        current.add(new CpuGpuLifecycle.RootSample(42, "A", 50));
        sample(detector, 1, true, Double.NaN, 30, new int[]{1}, NONE, new int[]{1}, current, birth(1));
        plain(detector, 2, 20, 30, current, Collections.emptyList());
        CpuGpuLifecycle.Update update = plain(detector, 3, 20, 30, current, Collections.emptyList());
        check(update.liveResults.size() == 1024 && update.liveResults.containsKey(1122),
                "idle candidate disappeared inside the supported capacity");
        state(update.liveResults.get(1122), "NO_EVIDENCE");
        state(update.liveResults.get(42), "ONSET_MATCH");
    }
    private static void overflowOnset() {
        CpuGpuLifecycle detector = new CpuGpuLifecycle();
        plain(detector, 0, 0, 30, Collections.emptyList(), Collections.emptyList());
        List<CpuGpuLifecycle.RootSample> overflow = new ArrayList<>(root(50));
        for (int i = 0; i < 1100; i++) overflow.add(new CpuGpuLifecycle.RootSample(100 + i, "stable:" + i, 0));
        sample(detector, 1, true, Double.NaN, 30, new int[]{1}, NONE, new int[]{1}, overflow, birth(1));
        plain(detector, 2, 20, 30, overflow, Collections.emptyList());
        CpuGpuLifecycle.Update update = plain(detector, 3, 20, 30, overflow, Collections.emptyList());
        check(update.liveResults.size() == 1024, "overflow enlarged the bounded candidate set");
        state(update.liveResults.get(42), "AMBIGUOUS");
        check(detector.confirmedOnset(42, "A") == null, "overflow produced a retained onset match");
    }
    private static void state(CpuGpuLifecycle.Result result, String expected) {
        check(result != null && expected.equals(result.state), "expected " + expected + ", got "
                + (result == null ? "null" : result.state + " / " + result.reason));
    }
    private static void notMatch(CpuGpuLifecycle.Result result) {
        check(result == null || (!"ONSET_MATCH".equals(result.state) && !"EXIT_MATCH".equals(result.state)),
                "unexpected match: " + (result == null ? "null" : result.reason));
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
