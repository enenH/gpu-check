package com.gpucheck.app;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** In-memory lifecycle timing hints. These events never prove per-process GPU ownership. */
public final class CpuGpuLifecycle {
    private static final long SECOND = 1_000_000_000L;
    private static final long TTL = 30 * SECOND;
    private static final long EXIT_WINDOW = 8 * SECOND;
    private static final long EXIT_DISPLAY = 10 * SECOND;
    private static final long MEASUREMENT_TOLERANCE = 100_000_000L;
    private static final int MAX_ROOTS = 1024, MAX_EVENTS = 128, MAX_SLOTS = 4096;
    private static final int MAX_EVENT_SLOTS = 64;
    private static final double MIN_CPU = 20, MIN_RATE = 10;
    private static final String LIMIT = "仅为生命周期时序线索，不证明按进程 GPU 归属。";

    public static final class RootSample {
        public final int pid;
        public final String identityToken;
        public final double cpuPercent;
        public RootSample(int pid, String identityToken, double cpuPercent) {
            this.pid = pid; this.identityToken = identityToken; this.cpuPercent = cpuPercent;
        }
    }

    public static final class ProcessEvent {
        public final String type;
        public final int pid;
        public final String identityToken;
        public final long observedMonotonicNs;
        public final String evidence;
        public ProcessEvent(String type, int pid, String identityToken, long observedMonotonicNs, String evidence) {
            this.type = type; this.pid = pid; this.identityToken = identityToken;
            this.observedMonotonicNs = observedMonotonicNs; this.evidence = evidence;
        }
    }

    public static final class GpuSample {
        public final long sampleMonotonicNs, intervalNs;
        public final boolean sampled;
        public final double[] slotDeltas;
        public final int[] appearedSlots, disappearedSlots, resetSlots;
        public final int firstSlot, endExclusive;
        public GpuSample(long sampleMonotonicNs, long intervalNs, boolean sampled, double[] slotDeltas,
                         int[] appearedSlots, int[] disappearedSlots, int[] resetSlots,
                         int firstSlot, int endExclusive) {
            this.sampleMonotonicNs = sampleMonotonicNs; this.intervalNs = intervalNs;
            this.sampled = sampled; this.slotDeltas = slotDeltas;
            this.appearedSlots = appearedSlots; this.disappearedSlots = disappearedSlots;
            this.resetSlots = resetSlots; this.firstSlot = firstSlot; this.endExclusive = endExclusive;
        }
    }

    public static final class Result {
        public final String state, kind, identityToken, reason;
        public final int pid;
        public final int[] slots;
        public final long observedMonotonicNs;
        public final boolean ownershipConfirmed = false;
        public Result(String state, String kind, int pid, String identityToken, int[] slots,
                      long observedMonotonicNs, String reason) {
            this.state = state; this.kind = kind; this.pid = pid; this.identityToken = identityToken;
            this.slots = slots; this.observedMonotonicNs = observedMonotonicNs; this.reason = reason + LIMIT;
        }
    }

    public static final class Update {
        public final Map<Integer, Result> liveResults;
        public final List<Result> recentExits;
        Update(Map<Integer, Result> liveResults, List<Result> recentExits) {
            this.liveResults = Collections.unmodifiableMap(liveResults);
            this.recentExits = Collections.unmodifiableList(recentExits);
        }
    }

    private static final class RememberedRoot {
        long lastSeen;
        RememberedRoot(long time) { lastSeen = time; }
    }

    private static final class Slot {
        long generation, birthNs, lastSample;
        int activeRounds;
        boolean valid, present;
        double rate;
        Slot(long generation) { this.generation = generation; }
    }

    private static final class Link {
        final long generation;
        int rounds;
        long lastSequence = -1, disappearedAt;
        boolean confirmed, everConfirmed, cancelled;
        Link(long generation) { this.generation = generation; }
    }

    private static final class Record {
        final ProcessEvent event;
        final String rootKey;
        final long window;
        final TreeMap<Integer, Link> links = new TreeMap<>();
        final TreeMap<Integer, Long> busyBefore = new TreeMap<>();
        boolean rootBound, overflow, revoked;
        Record(ProcessEvent event, long window) {
            this.event = event; this.rootKey = key(event.pid, event.identityToken); this.window = window;
        }
    }

    private final LinkedHashMap<String, RememberedRoot> roots = new LinkedHashMap<>();
    private final LinkedHashMap<String, Record> events = new LinkedHashMap<>();
    private final TreeMap<Integer, Slot> slots = new TreeMap<>();
    // First matches belong to the process identity, not the expiring observation window.
    private final Map<Integer, Result> confirmedOnsets = new LinkedHashMap<>();
    private long baselineNs, lastNs, sequence, nextGeneration, limitedUntil;
    private long lastInterval = 2 * SECOND;
    private int lastLength = -1, lastFirst = -1, lastEnd = -1;

    public synchronized void reset() {
        confirmedOnsets.clear();
        resetObservations();
    }

    /** Restart sampling windows without losing matches already established in this session. */
    public synchronized void resetObservations() {
        roots.clear(); events.clear(); slots.clear();
        baselineNs = lastNs = sequence = nextGeneration = limitedUntil = 0;
        lastInterval = 2 * SECOND;
        lastLength = lastFirst = lastEnd = -1;
    }

    public synchronized Result confirmedOnset(int pid, String identityToken) {
        Result saved = confirmedOnsets.get(pid);
        return identity(pid, identityToken) && saved != null && saved.identityToken.equals(identityToken)
                ? saved : null;
    }

    /** Clear this identity when the caller obtains explicit contradictory root evidence. */
    public synchronized void revoke(int pid, String identityToken) {
        if (!identity(pid, identityToken)) return;
        String rootKey = key(pid, identityToken);
        roots.remove(rootKey);
        events.entrySet().removeIf(entry -> entry.getValue().rootKey.equals(rootKey));
        if (confirmedOnset(pid, identityToken) != null) confirmedOnsets.remove(pid);
    }

    public synchronized Update update(GpuSample gpu, List<RootSample> currentRoots, List<ProcessEvent> incoming) {
        LinkedHashMap<Integer, RootSample> current = selectRoots(currentRoots);
        discardRetiredOnsets(current, incoming, gpu == null ? 0 : gpu.sampleMonotonicNs,
                gpu != null && gpu.intervalNs > 0 ? gpu.intervalNs : lastInterval);
        if (gpu == null || gpu.sampleMonotonicNs <= 0 || gpu.slotDeltas == null) {
            resetObservations();
            return noEvidence(current, "GPU 生命周期采样不可用，等待重新建立观察窗口。");
        }
        long now = gpu.sampleMonotonicNs;
        long interval = gpu.intervalNs > 0 ? gpu.intervalNs : lastInterval;
        int first = Math.max(1, gpu.firstSlot);
        int end = Math.min(MAX_SLOTS, Math.min(gpu.endExclusive, gpu.slotDeltas.length - 7));
        if (first >= end) { resetObservations(); return noEvidence(current, "没有可用的用户 context 槽范围。"); }
        boolean layoutChanged = lastLength >= 0 && (lastLength != gpu.slotDeltas.length || lastFirst != first || lastEnd != end);
        if (lastNs > 0 && (now <= lastNs || now - lastNs > Math.max(8 * SECOND, lastInterval * 3) || layoutChanged)) resetObservations();
        boolean baseline = baselineNs == 0;
        if (baseline) baselineNs = now;
        sequence++;
        lastNs = now; lastInterval = interval;
        lastLength = gpu.slotDeltas.length; lastFirst = first; lastEnd = end;
        expire(now);
        if (currentRoots != null && currentRoots.size() > MAX_ROOTS) limitedUntil = now + TTL;
        for (RootSample row : current.values()) {
            if (!identity(row.pid, row.identityToken)) continue;
            String rootKey = key(row.pid, row.identityToken);
            roots.remove(rootKey);
            roots.put(rootKey, new RememberedRoot(now));
        }
        while (roots.size() > MAX_ROOTS) {
            roots.remove(roots.keySet().iterator().next()); limitedUntil = now + TTL;
        }

        if (!baseline && incoming != null) for (ProcessEvent event : incoming) {
            if (event == null || !identity(event.pid, event.identityToken)
                    || event.observedMonotonicNs <= baselineNs || event.observedMonotonicNs > now + interval
                    || now - event.observedMonotonicNs > TTL) continue;
            boolean birth = "APPEARED".equals(event.type), death = "EXITED".equals(event.type);
            if ((!birth && !death) || (birth && !"new_pidfd_after_baseline".equals(event.evidence))
                    || (death && !exitEvidence(event.evidence))) continue;
            String eventKey = event.type + ":" + key(event.pid, event.identityToken);
            if (events.containsKey(eventKey)) continue;
            Record record = new Record(event, interval);
            if (death) captureBeforeExit(record);
            events.put(eventKey, record);
            if (events.size() > MAX_EVENTS) {
                String oldestKey = null; long oldest = Long.MAX_VALUE;
                for (Map.Entry<String, Record> entry : events.entrySet()) {
                    if (entry.getValue().event.observedMonotonicNs < oldest) {
                        oldest = entry.getValue().event.observedMonotonicNs; oldestKey = entry.getKey();
                    }
                }
                if (oldestKey != null) events.remove(oldestKey);
                limitedUntil = now + TTL;
            }
        }
        boolean[] appeared = flags(gpu.appearedSlots, first, end);
        boolean[] disappeared = flags(gpu.disappearedSlots, first, end);
        boolean[] reset = flags(gpu.resetSlots, first, end);
        slots.entrySet().removeIf(entry -> entry.getKey() < first || entry.getKey() >= end);
        for (int id = first; id < end; id++) {
            Slot slot = slots.get(id);
            double delta = gpu.slotDeltas[id];
            boolean valid = gpu.sampled && gpu.intervalNs > 0 && Double.isFinite(delta) && delta >= 0;
            double rate = valid ? delta * SECOND / gpu.intervalNs : Double.NaN;
            valid &= Double.isFinite(rate);
            if (appeared[id] && !baseline && gpu.sampled) {
                slot = new Slot(++nextGeneration); slot.birthNs = now; slot.present = true; slots.put(id, slot);
            } else if (reset[id] && !disappeared[id]) {
                // A reset/wrap without a disappearance has no death meaning.
                slot = new Slot(++nextGeneration); slots.put(id, slot);
            } else if (slot == null && valid && rate > 0) {
                slot = new Slot(++nextGeneration); slots.put(id, slot);
            }
            if (slot == null) continue;
            if (disappeared[id] && gpu.sampled) {
                slot.present = false; slot.valid = false; slot.rate = Double.NaN; slot.activeRounds = 0;
            } else {
                slot.valid = valid; slot.rate = rate;
                if (valid && rate > 0) slot.present = true;
                slot.activeRounds = valid && rate >= MIN_RATE ? Math.min(3, slot.activeRounds + 1) : 0;
            }
            slot.lastSample = now;
        }
        for (Record record : events.values()) {
            RememberedRoot root = roots.get(record.rootKey);
            if (root != null && now - root.lastSeen <= TTL) record.rootBound = true;
            if ("APPEARED".equals(record.event.type)) updateBirth(record, current, now, gpu.sampled);
            else updateExit(record, now, gpu.sampled, disappeared);
        }

        LinkedHashMap<Integer, Result> live = new LinkedHashMap<>();
        for (RootSample row : current.values()) {
            Result saved = confirmedOnset(row.pid, row.identityToken);
            if (saved != null) {
                live.put(row.pid, saved);
                continue;
            }
            Record birth = events.get("APPEARED:" + key(row.pid, row.identityToken));
            Result result;
            if (birth == null || !birth.rootBound || !identity(row.pid, row.identityToken)) {
                result = result("NO_EVIDENCE", "ONSET", row.pid, row.identityToken, new int[0], now,
                        "未观察到可用的新进程与新活跃槽出现线索；监测基线不算新出现。");
            } else {
                int[] confirmed = links(birth, true);
                boolean ambiguous = birth.overflow || now < limitedUntil || simultaneous(birth);
                String state = ambiguous ? "AMBIGUOUS" : confirmed.length > 0 ? "ONSET_MATCH" : "PENDING";
                String reason = ambiguous ? "同一采样窗有多个 root 范围候选出现，或观测容量受限，不能归于单一进程。"
                        : confirmed.length > 0
                        ? "出现时序吻合：进程与新活跃槽在一个采样窗加 100 ms 测量容差内出现，随后至少两轮 CPU ≥ 20% 且 retired 速率 ≥ 10/s；新活跃槽不等于已证实创建了 context。"
                        : "已记录监测期间的进程出现，等待同窗新活跃槽及两轮有效 CPU/GPU 推进。";
                result = result(state, "ONSET", row.pid, row.identityToken, confirmed,
                        birth.event.observedMonotonicNs, reason);
            }
            if ("ONSET_MATCH".equals(result.state)) confirmedOnsets.put(row.pid, result);
            live.put(row.pid, result);
        }
        List<Result> exits = new ArrayList<>();
        for (Record record : events.values()) {
            if (!"EXITED".equals(record.event.type) || !record.rootBound || record.revoked
                    || now - record.event.observedMonotonicNs > EXIT_DISPLAY) continue;
            int[] stopped = links(record, true);
            boolean ambiguous = record.overflow || now < limitedUntil || simultaneous(record);
            if (stopped.length > 0 && !otherBusySlotContinues(record)) ambiguous = true;
            String state = ambiguous ? "AMBIGUOUS" : stopped.length > 0 ? "EXIT_MATCH"
                    : now - record.event.observedMonotonicNs <= EXIT_WINDOW && !record.links.isEmpty() ? "PENDING" : "NO_EVIDENCE";
            String reason = ambiguous ? "多个 root 范围进程同时退出，或退出前的忙槽整体停止/缺少持续忙槽对照，不能归于单一进程。"
                    : stopped.length > 0 ? "退出后停止推进：pidfd 已确认近期 root 范围进程退出；此前槽连续推进，8 秒内确认零进度或消失后持续为零，且另一原忙槽仍推进。"
                    : "PENDING".equals(state) ? "pidfd 已确认退出，等待有效零进度；缺失采样不计为停止。"
                    : "退出前推进证据不足，或 8 秒窗口内未确认槽停止。";
            exits.add(result(state, "EXIT", record.event.pid, record.event.identityToken, stopped,
                    record.event.observedMonotonicNs, reason));
        }
        return new Update(live, exits);
    }

    private void discardRetiredOnsets(Map<Integer, RootSample> current, List<ProcessEvent> incoming,
                                      long now, long interval) {
        for (RootSample row : current.values()) {
            Result saved = confirmedOnsets.get(row.pid);
            if (saved != null && identity(row.pid, row.identityToken)
                    && !saved.identityToken.equals(row.identityToken)) forgetOnset(saved);
        }
        if (incoming == null) return;
        for (ProcessEvent event : incoming) {
            if (event == null || !identity(event.pid, event.identityToken)) continue;
            Result saved = confirmedOnsets.get(event.pid);
            if (saved == null || event.observedMonotonicNs <= saved.observedMonotonicNs
                    || (now > 0 && event.observedMonotonicNs > now + interval)) continue;
            boolean sameIdentity = saved.identityToken.equals(event.identityToken);
            boolean exited = sameIdentity && "EXITED".equals(event.type) && exitEvidence(event.evidence);
            boolean replaced = !sameIdentity && "APPEARED".equals(event.type)
                    && "new_pidfd_after_baseline".equals(event.evidence);
            if (exited || replaced) forgetOnset(saved);
        }
    }

    private void forgetOnset(Result saved) {
        confirmedOnsets.remove(saved.pid);
        events.remove("APPEARED:" + key(saved.pid, saved.identityToken));
    }

    private void captureBeforeExit(Record record) {
        for (Map.Entry<Integer, Slot> entry : slots.entrySet()) {
            Slot slot = entry.getValue();
            long age = record.event.observedMonotonicNs - slot.lastSample;
            if (!slot.valid || slot.rate <= 0 || age < 0 || age > record.window * 2) continue;
            if (record.busyBefore.size() < MAX_EVENT_SLOTS) record.busyBefore.put(entry.getKey(), slot.generation);
            else record.overflow = true;
            if (slot.activeRounds >= 2) {
                if (record.links.size() < MAX_EVENT_SLOTS) record.links.put(entry.getKey(), new Link(slot.generation));
                else record.overflow = true;
            }
        }
    }

    private void updateBirth(Record record, Map<Integer, RootSample> current, long now, boolean sampled) {
        if (!record.rootBound) return; // Cache the original event until caller evidence identifies this root lifecycle.
        RootSample row = current.get(record.event.pid);
        if (row == null || !record.event.identityToken.equals(row.identityToken)) return;
        for (Map.Entry<Integer, Slot> entry : slots.entrySet()) {
            Slot slot = entry.getValue();
            if (slot.birthNs <= baselineNs || !withinEventWindow(slot.birthNs,
                    record.event.observedMonotonicNs, record.window)) continue;
            Link link = record.links.get(entry.getKey());
            if (link == null) {
                if (record.links.size() >= MAX_EVENT_SLOTS) { record.overflow = true; continue; }
                link = new Link(slot.generation); record.links.put(entry.getKey(), link);
            }
            if (link.generation != slot.generation) { link.cancelled = true; link.confirmed = false; continue; }
            if (!slot.present) { link.cancelled = true; link.confirmed = false; continue; }
            if (link.cancelled) continue;
            boolean good = sampled && slot.valid && slot.rate >= MIN_RATE
                    && Double.isFinite(row.cpuPercent) && row.cpuPercent >= MIN_CPU;
            if (good) {
                link.rounds = link.lastSequence == sequence - 1 ? link.rounds + 1 : 1;
                if (link.rounds >= 2) link.confirmed = true;
            } else if (!link.confirmed) link.rounds = 0;
            link.lastSequence = sequence;
        }
        // Reset/reuse can erase a slot's original birth timestamp; invalidate such old links too.
        for (Map.Entry<Integer, Link> entry : record.links.entrySet()) {
            Slot slot = slots.get(entry.getKey());
            if (slot == null || slot.generation != entry.getValue().generation || !slot.present) {
                entry.getValue().cancelled = true; entry.getValue().confirmed = false;
            }
        }
    }

    private void updateExit(Record record, long now, boolean sampled, boolean[] disappeared) {
        for (Map.Entry<Integer, Link> entry : record.links.entrySet()) {
            Link link = entry.getValue(); Slot slot = slots.get(entry.getKey());
            if (slot == null || slot.generation != link.generation) {
                if (link.everConfirmed) record.revoked = true;
                link.cancelled = true; link.confirmed = false; continue;
            }
            if (link.cancelled) continue;
            if (slot.valid && slot.rate > 0) {
                if (link.everConfirmed) record.revoked = true;
                link.confirmed = false; link.rounds = 0; link.disappearedAt = 0;
            }
            if (now - record.event.observedMonotonicNs > EXIT_WINDOW) continue;
            if (sampled && disappeared[entry.getKey()]) {
                link.disappearedAt = now; link.rounds = 0; link.confirmed = false;
            } else if (sampled && slot.valid && slot.rate == 0) {
                link.rounds = link.lastSequence == sequence - 1 ? link.rounds + 1 : 1;
                if (link.rounds >= 3 || (link.disappearedAt > 0 && now > link.disappearedAt)) {
                    link.confirmed = true; link.everConfirmed = true;
                }
            } else if (!slot.valid) {
                link.rounds = 0; link.disappearedAt = 0; link.confirmed = false;
            }
            link.lastSequence = sequence;
        }
    }

    private boolean otherBusySlotContinues(Record record) {
        for (Map.Entry<Integer, Long> before : record.busyBefore.entrySet()) {
            Slot slot = slots.get(before.getKey());
            if (slot != null && slot.generation == before.getValue() && slot.valid && slot.rate > 0) return true;
        }
        return false;
    }

    private boolean simultaneous(Record record) {
        for (Record other : events.values()) {
            if (other == record || !other.rootBound || other.rootKey.equals(record.rootKey)
                    || !other.event.type.equals(record.event.type)) continue;
            if (withinEventWindow(other.event.observedMonotonicNs, record.event.observedMonotonicNs,
                    Math.max(record.window, other.window))) return true;
        }
        return false;
    }

    private static boolean withinEventWindow(long first, long second, long window) {
        return Math.abs(first - second) <= window + MEASUREMENT_TOLERANCE;
    }

    private void expire(long now) {
        roots.entrySet().removeIf(entry -> now - entry.getValue().lastSeen > TTL);
        events.entrySet().removeIf(entry -> now - entry.getValue().event.observedMonotonicNs > TTL);
        // Slot data is bounded by the declared range. Stale idle slots need no retained birth identity.
        slots.entrySet().removeIf(entry -> now - entry.getValue().lastSample > TTL);
    }

    private static boolean[] flags(int[] values, int first, int end) {
        boolean[] result = new boolean[end];
        if (values != null) for (int value : values) if (value >= first && value < end) result[value] = true;
        return result;
    }

    private static int[] links(Record record, boolean confirmedOnly) {
        List<Integer> ids = new ArrayList<>();
        for (Map.Entry<Integer, Link> entry : record.links.entrySet()) {
            Link link = entry.getValue();
            if (!link.cancelled && (!confirmedOnly || link.confirmed)) ids.add(entry.getKey());
        }
        int[] result = new int[ids.size()];
        for (int i = 0; i < ids.size(); i++) result[i] = ids.get(i);
        return result;
    }

    private static boolean exitEvidence(String evidence) {
        return "pidfd_readable".equals(evidence) || "pidfd_hup".equals(evidence)
                || "pidfd_poll_readable".equals(evidence) || "pidfd_poll_hup".equals(evidence);
    }

    private static boolean identity(int pid, String token) { return pid > 0 && token != null && !token.trim().isEmpty(); }
    private static String key(int pid, String token) { return pid + ":" + token; }

    private static LinkedHashMap<Integer, RootSample> selectRoots(List<RootSample> rows) {
        LinkedHashMap<Integer, RootSample> selected = new LinkedHashMap<>();
        if (rows != null) for (RootSample row : rows) {
            if (row == null) continue;
            if (selected.containsKey(row.pid)) selected.put(row.pid, new RootSample(row.pid, "", Double.NaN));
            else if (selected.size() < MAX_ROOTS) selected.put(row.pid, row);
        }
        return selected;
    }

    private static Result result(String state, String kind, int pid, String token, int[] slots, long time, String reason) {
        return new Result(state, kind, pid, token == null ? "" : token, slots, time, reason);
    }

    private Update noEvidence(Map<Integer, RootSample> roots, String reason) {
        LinkedHashMap<Integer, Result> live = new LinkedHashMap<>();
        for (RootSample root : roots.values()) {
            Result saved = confirmedOnset(root.pid, root.identityToken);
            live.put(root.pid, saved != null ? saved
                    : result("NO_EVIDENCE", "ONSET", root.pid, root.identityToken, new int[0], 0, reason));
        }
        return new Update(live, new ArrayList<>());
    }
}
