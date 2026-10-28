package com.gpucheck.app;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/** CPU-only leads for restricted observers; never establishes root or GPU ownership. */
public final class CandidatePolicy {
    public static final class Decision {
        public final String risk;
        public final int consecutiveHigh;
        public final String reason;

        Decision(String risk, int consecutiveHigh, String reason) {
            this.risk = risk;
            this.consecutiveHigh = consecutiveHigh;
            this.reason = reason;
        }
    }

    private static final class History {
        final String identity;
        final int count;
        final long window;

        History(String identity, int count, long window) {
            this.identity = identity;
            this.count = count;
            this.window = window;
        }
    }

    private static final String UNCONFIRMED = "UID、后台状态及 GPU 归属尚未确认。";
    private final double threshold;
    private final int windows;
    private final Map<Integer, History> histories = new HashMap<>();
    private final Set<Integer> seen = new HashSet<>();
    private long window;

    public CandidatePolicy(double threshold, int windows) {
        if (!Double.isFinite(threshold) || threshold <= 0 || threshold > 10000
                || windows < 1 || windows > 30) {
            throw new IllegalArgumentException("Invalid candidate policy");
        }
        this.threshold = threshold;
        this.windows = windows;
    }

    public void beginSnapshot() {
        seen.clear();
        window++;
    }

    public Decision evaluate(int pid, String identityToken, double cpu,
                             boolean metadataAccessible, boolean isSelf) {
        seen.add(pid);
        String identity = identityToken == null ? "" : identityToken;
        boolean valid = pid > 0 && !identity.trim().isEmpty() && Double.isFinite(cpu) && cpu >= 0;
        boolean qualifies = !isSelf && !metadataAccessible && valid && cpu >= threshold;
        History previous = histories.get(pid);
        int count = 0;
        if (qualifies) {
            boolean sameIdentity = previous != null && identity.equals(previous.identity);
            if (sameIdentity && previous.window == window) {
                // Multiple rows for one PID in a single snapshot are not multiple windows.
                count = previous.count;
            } else {
                int before = sameIdentity && previous.window == window - 1 ? previous.count : 0;
                count = Math.min(windows, before + 1);
            }
        }
        histories.put(pid, new History(identity, count, window));

        if (isSelf) return new Decision("LOW", 0, "本应用进程，不纳入普通权限候选。");
        if (metadataAccessible) {
            return new Decision("LOW", 0, "进程元数据可访问，不适用不可访问进程的 CPU 候选规则。");
        }
        if (!valid) {
            return new Decision("UNKNOWN", 0, "CPU 采样或进程身份基线无效，无法确认持续性；" + UNCONFIRMED);
        }
        if (count >= windows) {
            return new Decision("SUSPECT", count, "持续高 CPU 的不可访问进程；" + UNCONFIRMED);
        }
        if (cpu >= threshold) {
            return new Decision("WATCH", count, "不可访问进程的 CPU 达到阈值，等待持续采样 "
                    + count + "/" + windows + "；" + UNCONFIRMED);
        }
        return new Decision("LOW", 0, "当前 CPU 未达到候选阈值；" + UNCONFIRMED);
    }

    public void endSnapshot() {
        histories.keySet().retainAll(seen);
    }
}
