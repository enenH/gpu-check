package com.gpucheck.app;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/** Observes missing calibrated UID/PID names, never the absence of kernel cgroup membership. */
public final class CgroupWatchPolicy {
    public static final int REQUIRED = 3;
    public static final String METHOD = "stat_uid_pid_paths";
    public static final String SCOPE = "observed_uid_catalog";

    public static final class Paths {
        public final boolean calibrated, complete, uidCoverageComplete, found;
        public final int testedUidCount, testedPathCount, missingPathCount;
        public final long catalogGeneration;
        public final String scope;

        public Paths(boolean calibrated, boolean complete, boolean uidCoverageComplete, boolean found,
                     int testedUidCount, int testedPathCount, int missingPathCount,
                     long catalogGeneration, String scope) {
            this.calibrated = calibrated; this.complete = complete;
            this.uidCoverageComplete = uidCoverageComplete; this.found = found;
            this.testedUidCount = testedUidCount; this.testedPathCount = testedPathCount;
            this.missingPathCount = missingPathCount; this.catalogGeneration = catalogGeneration;
            this.scope = scope;
        }
    }

    public static final class Check {
        public final String state, identityToken, reason;
        public final boolean procPresent, stableIdentity, nonZombie;
        public final Paths paths;
        public final long sampleIndex;

        public Check(String state, boolean procPresent, boolean stableIdentity, boolean nonZombie,
                     Paths paths, String identityToken,
                     long sampleIndex, String reason) {
            this.state = state; this.procPresent = procPresent; this.stableIdentity = stableIdentity;
            this.nonZombie = nonZombie; this.paths = paths;
            this.identityToken = identityToken; this.sampleIndex = sampleIndex; this.reason = reason;
        }
    }

    public static final class Decision {
        public final String status, reason;
        public final boolean anomaly, validMissing;
        public final int consecutive;
        /** Report elapsed milliseconds, not wall-clock timestamps. */
        public final long first, last, firstSampleIndex, lastSampleIndex;

        private Decision(String status, int consecutive, long first, long last,
                         long firstSampleIndex, long lastSampleIndex, String reason) {
            this.status = status; this.consecutive = consecutive;
            this.first = first; this.last = last;
            this.firstSampleIndex = firstSampleIndex; this.lastSampleIndex = lastSampleIndex;
            this.reason = reason; this.anomaly = "ANOMALY".equals(status);
            this.validMissing = anomaly || "PENDING".equals(status);
        }
    }

    private static final class History {
        final String identity;
        final int count;
        final long first, firstIndex, catalogGeneration;
        History(String identity, int count, long first, long firstIndex, long catalogGeneration) {
            this.identity = identity; this.count = count; this.first = first; this.firstIndex = firstIndex;
            this.catalogGeneration = catalogGeneration;
        }
    }

    private final Map<Integer, History> histories = new HashMap<>();
    private final Set<Integer> seen = new HashSet<>();
    private final long maximumGapMs;
    private long previousIndex = -1, previousElapsed = -1, sampleIndex = -1, elapsedMs = -1;
    private boolean available;

    public CgroupWatchPolicy(long intervalMs) {
        if (intervalMs <= 0 || intervalMs > 3_600_000) throw new IllegalArgumentException("Invalid interval");
        maximumGapMs = intervalMs + Math.max(250, intervalMs / 2);
    }

    /** Availability identifies this stat-path method; coverage and calibration are per PID. */
    public void beginSnapshot(long index, long elapsed, boolean pathMethodAvailable) {
        seen.clear();
        boolean validTime = index >= 0 && elapsed >= 0;
        boolean continuous = previousIndex >= 0 && index == previousIndex + 1
                && elapsed > previousElapsed && elapsed - previousElapsed <= maximumGapMs;
        if (!validTime || !pathMethodAvailable || !continuous) histories.clear();
        sampleIndex = index; elapsedMs = elapsed;
        available = validTime && pathMethodAvailable;
        previousIndex = index; previousElapsed = elapsed;
    }

    public Decision evaluate(int pid, String processIdentity, Check check, boolean self) {
        if (!seen.add(pid)) return cleared(pid, "UNKNOWN", "同一轮 PID 重复，重新建立观察窗口。");
        if (self) return cleared(pid, "EXCLUDED", "本应用及同 UID 进程不纳入 cgroup 异常候选。");
        if (check != null && "EXITED".equals(check.state)) return cleared(pid, "EXITED", "进程已退出，清除 cgroup 观察。");
        if (check != null && "PRESENT".equals(check.state)) return cleared(pid, "PRESENT", "已匹配参考 cgroup UID/PID 命名路径。");
        if (!available) return cleared(pid, "UNKNOWN", "命名路径探测不可用或采样时序无效，不能判定路径缺失。");
        if (pid <= 0 || processIdentity == null || processIdentity.trim().isEmpty()
                || processIdentity.length() > 4096 || check == null) {
            return cleared(pid, "UNKNOWN", "缺少同一进程的有效身份或 cgroup 检查。");
        }
        if (!"MISSING".equals(check.state)) {
            return cleared(pid, "UNKNOWN", check.reason == null || check.reason.isEmpty()
                    ? "参考命名路径状态未知，清除连续观察。" : check.reason);
        }
        Paths paths = check.paths;
        if (!check.procPresent || !check.stableIdentity || !check.nonZombie || paths == null
                || !paths.calibrated || !paths.complete || !paths.uidCoverageComplete || paths.found
                || paths.testedUidCount <= 0 || paths.testedPathCount <= 0
                || paths.testedPathCount < paths.testedUidCount
                || paths.missingPathCount != paths.testedPathCount || paths.catalogGeneration < 0
                || !SCOPE.equals(paths.scope) || check.sampleIndex != sampleIndex
                || !processIdentity.equals(check.identityToken)) {
            return cleared(pid, "UNKNOWN", "路径校准、UID 范围或探测预算不完整，或未确认同一存活进程。");
        }
        History previous = histories.get(pid);
        boolean same = previous != null && processIdentity.equals(previous.identity)
                && paths.catalogGeneration == previous.catalogGeneration;
        int count = same ? Math.min(REQUIRED, previous.count + 1) : 1;
        long first = same ? previous.first : elapsedMs;
        long firstIndex = same ? previous.firstIndex : sampleIndex;
        histories.put(pid, new History(processIdentity, count, first, firstIndex, paths.catalogGeneration));
        return new Decision(count >= REQUIRED ? "ANOMALY" : "PENDING", count,
                first, elapsedMs, firstIndex, sampleIndex,
                count >= REQUIRED
                        ? "同一存活 PID 连续 3 次未匹配已校准 UID 范围内的参考命名路径；不表示没有内核 cgroup，也不证明 root 身份或 GPU 归属。"
                        : "已校准 UID 范围内的参考 UID/PID 命名路径未匹配，等待连续确认 " + count + "/" + REQUIRED + "。");
    }

    public void endSnapshot() { histories.keySet().retainAll(seen); }

    public void reset() {
        histories.clear(); seen.clear(); available = false;
        previousIndex = previousElapsed = sampleIndex = elapsedMs = -1;
    }

    private Decision cleared(int pid, String status, String reason) {
        histories.remove(pid);
        return new Decision(status, 0, -1, -1, -1, -1, reason);
    }
}
