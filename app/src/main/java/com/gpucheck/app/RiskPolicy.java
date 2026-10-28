package com.gpucheck.app;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/** Pure policy: GPU device ownership is evidence of a client, not GPU utilization. */
public final class RiskPolicy {
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

    private final double threshold;
    private final int windows;
    private final Map<String, Integer> streaks = new HashMap<>();
    private final Set<String> seen = new HashSet<>();

    public RiskPolicy(double threshold, int windows) {
        if (!Double.isFinite(threshold) || threshold <= 0 || threshold > 10000 || windows < 1 || windows > 30) {
            throw new IllegalArgumentException("Invalid risk policy");
        }
        this.threshold = threshold;
        this.windows = windows;
    }

    public void beginSnapshot() { seen.clear(); }

    public Decision evaluate(int pid, long startTime, int uid, double cpu, String background,
                             boolean gpuDeviceOpen, boolean gpuActive, boolean evidenceReadable) {
        String key = pid + ":" + startTime;
        seen.add(key);
        boolean sampleValid = Double.isFinite(cpu) && cpu >= 0 && startTime > 0 && pid > 0;
        boolean qualifies = uid == 0 && sampleValid && cpu >= threshold
                && "background".equals(background) && gpuDeviceOpen && evidenceReadable;
        int count = qualifies ? Math.min(windows, streaks.getOrDefault(key, 0) + 1) : 0;
        streaks.put(key, count);
        if (count >= windows) {
            return new Decision("HIGH", count, "后台 root 进程连续 " + windows + " 次 CPU 达到阈值，"
                    + (gpuActive ? "且已验证 GPU 活动。需核查。" : "且持有 GPU 设备；当期 GPU 活动未确认。需核查。"));
        }
        if (uid < 0) return new Decision("UNKNOWN", 0, "进程 UID 未确认。");
        if (uid != 0) return new Decision("LOW", 0, "不是 effective UID 0 进程。");
        if (!sampleValid) return new Decision("UNKNOWN", 0, "正在建立 CPU 基线，或进程身份尚未确认。");
        if (!evidenceReadable) return new Decision("UNKNOWN", 0, "GPU 证据读取不完整，不能判定无 GPU 使用。");
        if ("unknown".equals(background) && (gpuDeviceOpen || cpu >= threshold)) {
            return new Decision("UNKNOWN", 0, "后台身份不明确，保留观察。");
        }
        if ("foreground".equals(background)) return new Decision("LOW", 0, "前台进程，不满足后台风险规则。");
        if (count > 0) return new Decision("WATCH", count, "满足候选条件，等待持续采样 " + count + "/" + windows + "。");
        if (gpuDeviceOpen) return new Decision("WATCH", 0, "持有 GPU 设备，CPU 尚未连续达到阈值。");
        if (cpu >= threshold) return new Decision("WATCH", 0, "CPU 达到阈值，尚无按进程关联的 GPU 设备证据。");
        return new Decision("LOW", 0, "当前采样未满足高风险组合条件。");
    }

    public void endSnapshot() { streaks.keySet().retainAll(seen); }
}
