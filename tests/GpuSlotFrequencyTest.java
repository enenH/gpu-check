import com.gpucheck.app.GpuSlotFrequency;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public final class GpuSlotFrequencyTest {
    private static int checks;
    private static final long HALF = 500_000_000L, BASE = 10_000_000_000L;
    private static GpuSlotFrequency.Observation row(int slot, double fps, boolean eligible, long counter) {
        return new GpuSlotFrequency.Observation(slot, eligible, fps, counter, counter + 60, counter, counter + 60);
    }
    private static GpuSlotFrequency.Result window(GpuSlotFrequency policy, int index, double rate) {
        return policy.update(BASE + HALF * index, BASE + HALF * (index + 1),
                Collections.singletonList(row(800, rate, true, 1000 + 60L * index))).get(0);
    }
    private static void check(boolean value, String message) {
        checks++; if (!value) throw new AssertionError(message);
    }
    public static void main(String[] args) {
        GpuSlotFrequency policy = new GpuSlotFrequency();
        for (int i = 0; i < 5; i++) check(!window(policy, i, 120).alert, "Early alert before 3 seconds");
        GpuSlotFrequency.Result hit = window(policy, 5, 120);
        check(hit.alert && hit.stableForMs == 3000, "Continuous 3-second high rate did not alert");
        check(!window(policy, 6, 90).alert, "Exactly 90 must clear");
        check(window(policy, 7, 120).stableForMs == 500, "Low rate did not reset streak");
        policy.reset();
        for (int i = 0; i < 6; i++) check(!window(policy, i, 90).alert, "90 must never alert");
        policy.reset();
        for (int i = 0; i < 5; i++) window(policy, i, 120);
        List<GpuSlotFrequency.Result> changed = policy.update(BASE + 5 * HALF, BASE + 6 * HALF,
                Arrays.asList(row(800, 120, false, 1300), row(801, 120, true, 4000)));
        check(!changed.get(0).alert && changed.get(0).stableForMs == 0, "Self/invalid slot not reset");
        check(changed.get(1).stableForMs == 500, "New slot inherited old streak");
        check(!policy.update(BASE + 6 * HALF, BASE + 7 * HALF, Collections.emptyList()).iterator().hasNext(), "Missing rows persisted");
        check(window(policy, 7, 120).stableForMs == 500, "Missing slot inherited streak");
        policy.reset(); window(policy, 0, 120);
        check(policy.update(BASE, BASE + HALF, Collections.singletonList(row(800, 120, true, 1000))).isEmpty(), "Replay counted");
        check(window(policy, 1, 120).stableForMs == 500, "Replay preserved streak");
        policy.reset(); window(policy, 0, 120);
        hit = policy.update(BASE + HALF + 101_000_000L, BASE + 2 * HALF + 101_000_000L,
                Collections.singletonList(row(800, 120, true, 1060))).get(0);
        check(hit.stableForMs == 500, "Long gap bridged streak");
        policy.reset();
        for (int i = 0; i < 5; i++) {
            long start = BASE + i * (HALF + 20_000_000L);
            hit = policy.update(start, start + HALF, Collections.singletonList(row(800, 120, true, 1000 + i * 60))).get(0);
        }
        check(hit.stableForMs == 2500 && !hit.alert, "Unobserved gaps counted toward sustain");
        policy.reset(); window(policy, 0, 120);
        hit = policy.update(BASE + HALF, BASE + 2 * HALF, Collections.singletonList(row(800, 120, true, 10))).get(0);
        check(hit.stableForMs == 500, "Between-window SOP reset was ignored");
        policy.reset(); window(policy, 0, 120);
        hit = policy.update(BASE + HALF, BASE + 2 * HALF, Collections.singletonList(
                new GpuSlotFrequency.Observation(800, true, 120, 1060, 1120, 10, 70))).get(0);
        check(hit.stableForMs == 500, "Between-window EOP reset was ignored");
        policy.reset(); window(policy, 0, 120);
        policy.invalidate(Collections.singleton(800));
        check(window(policy, 1, 120).stableForMs == 500, "Explicit invalidation did not reset");
        check(!window(policy, 2, Double.NaN).alert && window(policy, 3, 120).stableForMs == 500, "Invalid rate retained streak");
        check(policy.update(BASE + 4 * HALF, BASE + 4 * HALF + 100, Collections.singletonList(row(800, 120, true, 1240))).isEmpty(), "Partial window accepted");
        policy.reset(); window(policy, 0, 120);
        check(policy.update(BASE + HALF, BASE + 2 * HALF, Arrays.asList(row(800, 120, true, 1060), row(800, 120, true, 1060))).isEmpty(), "Duplicate slot accepted");
        check(window(policy, 2, 120).stableForMs == 500, "Malformed window retained streak");
        System.out.println("GPU slot frequency policy: PASS " + checks + " checks");
    }
}
