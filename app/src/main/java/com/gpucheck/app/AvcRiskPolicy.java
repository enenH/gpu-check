package com.gpucheck.app;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Combines a caller-validated, unexpired SELinux domain evidence with independent CPU
 * and global GPU observations. It never establishes a numeric UID or PID GPU ownership.
 */
public final class AvcRiskPolicy {
    public static final class Decision {
        public final String risk;
        /** Consecutive qualifying CPU windows for this process, capped at the configured count. */
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

    private static final String UNATTRIBUTED = "按进程 GPU 归属未确认。";
    private final double threshold;
    private final int windows;
    private final Map<Integer, History> histories = new HashMap<>();
    private final Set<Integer> seen = new HashSet<>();
    private long window;
    private int gpuStreak;

    public AvcRiskPolicy(double threshold, int windows) {
        if (!Double.isFinite(threshold) || threshold <= 0 || threshold > 10000
                || windows < 1 || windows > 30) {
            throw new IllegalArgumentException("Invalid AVC risk policy");
        }
        this.threshold = threshold;
        this.windows = windows;
    }

    public void beginSnapshot(boolean gpuSampled, boolean globalGpuActive) {
        seen.clear();
        window++;
        gpuStreak = gpuSampled && globalGpuActive ? Math.min(windows, gpuStreak + 1) : 0;
    }

    public Decision evaluate(int pid, String identityToken, double cpu,
                             boolean rootDomainEvidence, boolean isSelf) {
        seen.add(pid);
        String identity = identityToken == null ? "" : identityToken;
        boolean valid = pid > 0 && !identity.trim().isEmpty() && Double.isFinite(cpu) && cpu >= 0;
        History previous = histories.get(pid);
        int count = 0;
        if (!isSelf && valid && cpu >= threshold) {
            boolean sameIdentity = previous != null && identity.equals(previous.identity);
            if (sameIdentity && previous.window == window) {
                count = previous.count;
            } else {
                int before = sameIdentity && previous.window == window - 1 ? previous.count : 0;
                count = Math.min(windows, before + 1);
            }
        }
        histories.put(pid, new History(identity, count, window));

        if (isSelf) return new Decision("LOW", 0, "本应用进程，不纳入 SELinux 组合风险规则。");
        if (!valid) {
            return new Decision("UNKNOWN", 0, "CPU 或进程身份基线无效，无法确认持续性；" + UNATTRIBUTED);
        }
        if (cpu < threshold) {
            return new Decision("LOW", 0, "CPU 未达到阈值，不满足组合风险规则；" + UNATTRIBUTED);
        }
        if (!rootDomainEvidence) {
            return new Decision("WATCH", count, "缺少当前有效且关联本进程的 root 执行域证据；" + UNATTRIBUTED);
        }
        if (count >= windows && gpuStreak >= windows) {
            return new Decision("HIGH", count,
                    "SELinux 证据指向 root 执行域 + CPU 持续高占用 + 全局 memstore 持续推进；按进程 GPU 归属未确认。");
        }
        return new Decision("WATCH", count, "SELinux 证据指向 root 执行域，等待持续采样：CPU "
                + count + "/" + windows + "，全局 memstore " + gpuStreak + "/" + windows + "；" + UNATTRIBUTED);
    }

    public void endSnapshot() {
        histories.keySet().retainAll(seen);
    }
}
