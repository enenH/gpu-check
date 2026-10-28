package com.gpucheck.app;

import android.content.Context;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.os.SystemClock;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Reads only the log records visible to this ordinary application UID. */
public final class AvcEvidence {
    static final long MAX_AGE_MS = 30000;
    private static final int MAX_LINE = 8192;
    private final Object lock = new Object();
    private final int applicationUid;
    private final Store store = new Store();
    private volatile LocalSocket logSocket;
    private volatile Thread readerThread;
    private volatile boolean running;
    private int generation;
    private String ownContext = "";
    private String status = "未启动";
    private String error = "";
    private long startedEpoch;
    private long linesRead;
    private long parsedCount;
    private long rejectedPackets;

    public AvcEvidence(Context context) {
        applicationUid = context.getApplicationInfo().uid;
    }

    /** Starts a direct, ordinary-UID logdr reader without any subprocess or permission request. */
    public void start() {
        final int token;
        synchronized (lock) {
            if (running) return;
            if (applicationUid < 10000 || android.os.Process.myUid() != applicationUid) {
                status = "不可用";
                error = "AVC 采集仅允许普通应用 UID。";
                return;
            }
            running = true;
            token = ++generation;
            startedEpoch = System.currentTimeMillis();
            store.clear();
            linesRead = parsedCount = rejectedPackets = 0;
            status = "正在连接本应用可见日志";
            error = "";
        }
        Thread thread = new Thread(() -> readLogs(token), "gpu-check-avc");
        thread.setDaemon(true);
        readerThread = thread;
        thread.start();
    }

    /** Shutting down the socket interrupts a blocked packet read; there is no child process. */
    public void stop() {
        LocalSocket socket;
        synchronized (lock) {
            running = false;
            generation++;
            socket = logSocket;
            logSocket = null;
            status = "已停止";
            store.clear();
        }
        closeSocket(socket);
        Thread thread = readerThread;
        if (thread != null) thread.interrupt();
    }

    private void readLogs(int token) {
        LocalSocket socket = null;
        try {
            // AOSP LogReader only bypasses user consent for peers WITHOUT global log credentials.
            // Fail before connecting if unexpected UID/GID/groups could enter that consent branch.
            if (!hasOrdinaryCredentials(readOwnFile("/proc/self/status", 16384), applicationUid)) {
                throw new IllegalStateException("自身 UID/GID/Groups 未确认是普通日志凭据；未连接日志服务。不会申请授权。");
            }
            String label = readOwnFile("/proc/self/attr/current", 512).replace("\0", "").trim();
            if (!label.startsWith("u:r:") || label.split(":", 4).length != 4) {
                throw new IllegalStateException("无法读取本应用 SELinux 上下文，停止 AVC 关联。");
            }
            final long since;
            synchronized (lock) {
                if (!running || token != generation) return;
                ownContext = label;
                since = startedEpoch;
            }
            // logdOpen() uses one SOCK_SEQPACKET command and one complete logger_entry per read.
            // Buffer 0 is main; peer credentials restrict records to this UID on the server.
            socket = new LocalSocket(LocalSocket.SOCKET_SEQPACKET);
            synchronized (lock) {
                if (!running || token != generation) return;
                logSocket = socket;
            }
            socket.connect(new LocalSocketAddress("/dev/socket/logdr", LocalSocketAddress.Namespace.FILESYSTEM));
            synchronized (lock) { if (!running || token != generation) return; }
            String request = String.format(Locale.US, "stream lids=0 start=%d.%09d", since/1000, (since%1000)*1000000L);
            socket.getOutputStream().write(request.getBytes(StandardCharsets.US_ASCII));
            synchronized (lock) {
                if (!running || token != generation) return;
                status = "直连自身 UID 日志 · 等待 AVC";
            }
            try (InputStream input = socket.getInputStream()) {
                byte[] packet = new byte[65536];
                int size;
                // Never read just the header: a short SEQPACKET read discards the rest of that packet.
                while (running && (size = input.read(packet)) != -1) {
                    long wall = System.currentTimeMillis();
                    long uptime = SystemClock.uptimeMillis();
                    synchronized (lock) {
                        if (!running || token != generation) break;
                        linesRead++;
                        String line = BinaryParser.toLine(packet, size, applicationUid);
                        if (line == null) { rejectedPackets++; continue; }
                        Event event = Parser.parse(line, ownContext);
                        if (event == null || event.epochMs < since || event.epochMs > wall + 1500
                                || wall - event.epochMs > MAX_AGE_MS) continue;
                        parsedCount++;
                        store.accept(event, uptime);
                        status = "已读到本应用 AVC · 按目标和采样时窗关联";
                    }
                }
            }
            synchronized (lock) {
                if (running && token == generation) {
                    status = "日志读取已结束";
                    if (error.isEmpty()) error = "自身 UID 日志连接已关闭，后续 AVC 证据不可用；不会请求全局日志授权。";
                }
            }
        } catch (Exception failure) {
            synchronized (lock) {
                if (running && token == generation) {
                    status = "AVC 不可用";
                    error = failure.getMessage() == null ? failure.toString() : failure.getMessage();
                }
            }
        } finally {
            closeSocket(socket);
            synchronized (lock) { if (logSocket == socket) logSocket = null; }
        }
    }

    private static void closeSocket(LocalSocket socket) {
        if (socket == null) return;
        try { socket.shutdownInput(); } catch (Exception ignored) { }
        try { socket.shutdownOutput(); } catch (Exception ignored) { }
        try { socket.close(); } catch (Exception ignored) { }
    }

    private static String readOwnFile(String path, int limit) throws IOException {
        try (FileInputStream input = new FileInputStream(path)) {
            byte[] bytes = new byte[limit];
            int total=0, count;
            while (total < limit && (count=input.read(bytes,total,limit-total))>0) total+=count;
            if (total == limit) throw new IOException("自身元数据超出读取上限");
            return new String(bytes,0,total,StandardCharsets.UTF_8);
        }
    }

    // Mirrors AOSP logd LogPermissions.cpp; never enter the global-log consent branch.
    static boolean hasOrdinaryCredentials(String status, int expectedUid) {
        if (expectedUid < 10000) return false;
        boolean uid=false, gid=false, groups=false, caps=false;
        try {
            for (String line : status.split("\n")) {
                if (line.startsWith("Uid:") || line.startsWith("Gid:")) {
                    String[] values=line.substring(4).trim().split("\\s+");
                    if (values.length!=4) return false;
                    for (String value:values) {
                        int id=Integer.parseInt(value);
                        if (id==0 || id==1000 || id==1007 || line.startsWith("Uid:") && id!=expectedUid) return false;
                    }
                    if (line.startsWith("Uid:")) uid=true; else gid=true;
                } else if (line.startsWith("Groups:")) {
                    String values=line.substring(7).trim();
                    if (!values.isEmpty()) for (String value:values.split("\\s+")) {
                        int id=Integer.parseInt(value);
                        if (id==0 || id==1000 || id==1007) return false;
                    }
                    groups=true;
                } else if (line.startsWith("CapEff:")) {
                    if (!line.substring(7).trim().matches("0+")) return false;
                    caps=true;
                }
            }
        } catch (NumberFormatException malformed) { return false; }
        return uid && gid && groups && caps;
    }

    /** Adds domain hints; deliberately never writes uid, gpuActive or gpuDeviceOpen. */
    public void enrich(JSONObject report) throws JSONException {
        synchronized (lock) {
            long now = SystemClock.uptimeMillis();
            long wall = System.currentTimeMillis();
            JSONArray rows = report.optJSONArray("processes");
            JSONArray cpuRows = report.optJSONArray("cpuSamples");
            // Continuous idle CPU samples also need the current lifecycle and fresh AVC evidence.
            for (int i = 0; cpuRows != null && i < cpuRows.length(); i++) {
                JSONObject p = cpuRows.optJSONObject(i);
                if (p != null) store.identity(p.optInt("pid", -1),
                        p.optBoolean("identityVerified") ? p.optString("identityToken", "") : "", now);
            }
            for (int i = 0; rows != null && i < rows.length(); i++) {
                JSONObject p = rows.optJSONObject(i);
                if (p == null) continue;
                String identity = p.optString("identityToken", "");
                if (!p.optBoolean("identityVerified", false)) identity = "";
                int pid = p.optInt("pid", -1);
                store.identity(pid, identity, now);
                long begin = p.optLong("probeEpochMs", 0), end = p.optLong("probeEndEpochMs", 0);
                int source = p.optInt("probeSourcePid", report.optInt("collectorPid", -1));
                if (p.optBoolean("metadataProbeAttempted", begin > 0)) {
                    store.probe(pid, identity, source, begin, end, now);
                }
            }
            store.reconcile(now);
            int rootHints = 0;
            JSONArray enriched = new JSONArray();
            for (int i = 0; rows != null && i < rows.length(); i++) enriched.put(rows.opt(i));
            for (int i = 0; cpuRows != null && i < cpuRows.length(); i++) enriched.put(cpuRows.opt(i));
            for (int i = 0; i < enriched.length(); i++) {
                JSONObject p = enriched.optJSONObject(i);
                if (p == null) continue;
                Match match = store.lookup(p.optInt("pid", -1), p.optString("identityToken", ""), now);
                if (match != null && (wall-match.event.epochMs > MAX_AGE_MS || match.event.epochMs > wall+1500)) match = null;
                boolean rootHint = match != null && match.event.rootDomain;
                p.put("avcRootDomainHint", rootHint);
                if (rootHint && rows != null && i < rows.length()) rootHints++;
                if (match == null) continue;
                Event event = match.event;
                p.put("avcTargetContext", event.targetContext).put("avcTargetDomain", event.domain)
                        .put("avcSourcePid", event.sourcePid).put("avcTargetPid", event.targetPid)
                        .put("avcEpochMs", event.epochMs).put("avcEvidenceAgeMs", Math.max(0, now - match.receivedUptime))
                        .put("avcIdentityToken", match.identity)
                        .put("avcIdentitySource", "own_context_proc_getattr_denial_and_probe_window")
                        .put("avcUidConfirmed", false)
                        .put("avcEvidence", event.raw)
                        .put("avcNote", "目标域由本应用访问 /proc/PID 的拒绝日志关联；root 域是身份线索，不等于读取 effective UID。");
            }
            JSONArray recent = new JSONArray();
            int skip = Math.max(0, store.pending.size()-8);
            for (Pending item : store.pending.values()) {
                if (skip-- > 0) continue;
                Event event=item.event;
                recent.put(new JSONObject().put("sourcePid",event.sourcePid).put("targetPid",event.targetPid)
                        .put("epochMs",event.epochMs).put("targetContext",event.targetContext)
                        .put("rootDomainHint",event.rootDomain).put("raw",event.raw));
            }
            report.put("avcStatus", status).put("avcError", error).put("avcOwnContext", ownContext)
                    .put("avcReaderRunning", running && logSocket != null)
                    .put("avcLinesRead", linesRead).put("avcParsedCount", parsedCount)
                    .put("avcMatchedCount", store.boundCount).put("avcRootHintCount", rootHints)
                    .put("avcRejectedPackets", rejectedPackets).put("avcRecentEvents", recent)
                    .put("avcTransport", "direct_logdr_seqpacket_self_uid")
                    .put("avcProbeEarlyToleranceMs",100).put("avcProbeDeliveryToleranceMs",1500)
                    .put("avcEvidenceTtlMs", MAX_AGE_MS)
                    .put("avcVisibility", "ordinary_uid_visible_main_log_only")
                    .put("avcCoverageNote", "无匹配不等于无 root；审计限速、权限、日志丢失或过期均会造成缺口。");
        }
    }

    /** logger_entry v4: little-endian 28-byte header followed by priority, tag NUL, message NUL. */
    static final class BinaryParser {
        static String toLine(byte[] packet, int count, int expectedUid) {
            if (packet==null || count<28 || count>packet.length) return null;
            int length=u16(packet,0), header=u16(packet,2);
            if (header<28 || header>256 || length<3 || length>5120 || header+length>count) return null;
            long pid=u32(packet,4), tid=u32(packet,8), seconds=u32(packet,12), nanos=u32(packet,16);
            if (u32(packet,20)!=0 || u32(packet,24)!=expectedUid || nanos>=1000000000L
                    || pid<=0 || pid>Integer.MAX_VALUE || tid<=0 || tid>Integer.MAX_VALUE) return null;
            int priority=packet[header]&255;
            if (priority<2 || priority>7) return null;
            int end=header+length, tagEnd=zero(packet,header+1,end);
            if (tagEnd<0) return null;
            int messageStart=tagEnd+1, messageEnd=zero(packet,messageStart,end);
            if (messageEnd<0) return null;
            String tag=new String(packet,header+1,tagEnd-header-1,StandardCharsets.UTF_8);
            String message=new String(packet,messageStart,messageEnd-messageStart,StandardCharsets.UTF_8);
            if (tag.length()>128 || tag.indexOf('\n')>=0 || tag.indexOf('\r')>=0
                    || message.indexOf('\n')>=0 || message.indexOf('\r')>=0) return null;
            return String.format(Locale.US,"%d.%09d %d %d %c %s: %s",seconds,nanos,pid,tid,
                    "VDIWEF".charAt(priority-2),tag.replace(':','_'),message);
        }
        private static int zero(byte[] bytes,int start,int end) {
            for(int i=start;i<end;i++) if(bytes[i]==0) return i;
            return -1;
        }
        private static int u16(byte[] bytes,int at) { return (bytes[at]&255)|((bytes[at+1]&255)<<8); }
        private static long u32(byte[] bytes,int at) {
            return (bytes[at]&255L)|((bytes[at+1]&255L)<<8)|((bytes[at+2]&255L)<<16)|((bytes[at+3]&255L)<<24);
        }
    }

    static final class Event {
        final long epochMs;
        final int sourcePid, targetPid;
        final String targetContext, domain, raw, dedupKey;
        final boolean rootDomain;
        Event(long time, int source, int target, String context, String text, String audit) {
            epochMs = time; sourcePid = source; targetPid = target; targetContext = context; raw = text;
            domain = context.split(":", 4)[2];
            rootDomain = "su".equals(domain) || "magisk".equals(domain) || "zygisk".equals(domain) || "ksu".equals(domain);
            dedupKey = time + ":" + source + ":" + target + ":" + context + ":" + audit;
        }
    }

    /** Pure parser for normalized logdr records; no Android calls in this class. */
    static final class Parser {
        private static final Pattern HEADER = Pattern.compile("^\\s*(\\d{9,12})\\.(\\d{3,9})\\s+(\\d+)\\s+(\\d+)\\s+[VDIWEFA]\\s+[^:]+:\\s*(.*)$");
        private static final Pattern DENIAL = Pattern.compile("(?:^|\\s)avc:\\s*denied\\s*\\{([^}]+)\\}");
        private static final Pattern GETATTR = Pattern.compile("(?:^|\\s)getattr(?:\\s|$)");
        private static final Pattern FIELD = Pattern.compile("(?:^|\\s)([a-zA-Z_][a-zA-Z_0-9]*)=(?:\"([^\"\\r\\n]*)\"|'([^'\\r\\n]*)'|([^\\s]+))");
        private static final Pattern PATH = Pattern.compile("/proc/([1-9][0-9]*)/?");
        private static final Pattern AUDIT = Pattern.compile("audit\\(([^)]+)\\)");

        static Event parse(String line, String ownContext) {
            if (line == null || line.length() > MAX_LINE || ownContext == null || ownContext.isEmpty()) return null;
            Matcher header = HEADER.matcher(line);
            if (!header.matches()) return null;
            long epoch;
            try { epoch = Long.parseLong(header.group(1)) * 1000L + Integer.parseInt(header.group(2).substring(0, 3)); }
            catch (NumberFormatException bad) { return null; }
            String body = header.group(5);
            Matcher denied = DENIAL.matcher(body);
            if (!denied.find() || !GETATTR.matcher(denied.group(1).trim()).find()) return null;
            Map<String, String> fields = new HashMap<>();
            Matcher field = FIELD.matcher(body);
            while (field.find()) {
                String value = field.group(2) != null ? field.group(2) : field.group(3) != null ? field.group(3) : field.group(4);
                if (fields.put(field.group(1), value) != null) return null;
            }
            if (!"1400".equals(fields.get("type")) || !"proc".equals(fields.get("dev"))
                    || !"dir".equals(fields.get("tclass")) || !ownContext.equals(fields.get("scontext"))
                    || "1".equals(fields.get("permissive"))) return null;
            String targetContext = fields.get("tcontext");
            if (targetContext == null || !targetContext.startsWith("u:r:") || targetContext.split(":", 4).length != 4) return null;
            int target = -1;
            String path = fields.get("path");
            if (path != null) {
                Matcher candidate = PATH.matcher(path);
                if (!candidate.matches()) return null;
                target = positive(candidate.group(1));
            }
            String name = fields.get("name");
            if (name != null) {
                int named = positive(name);
                if (named <= 0 || target > 0 && named != target) return null;
                target = named;
            }
            int source = positive(fields.containsKey("pid") ? fields.get("pid") : header.group(3));
            if (source <= 0 || target <= 0 || source == target) return null;
            Matcher audit = AUDIT.matcher(body);
            if (!audit.find()) return null;
            return new Event(epoch, source, target, targetContext, line, audit.group(1));
        }
        private static int positive(String value) {
            if (value == null || !value.matches("[1-9][0-9]{0,9}")) return -1;
            try { return Integer.parseInt(value); } catch (NumberFormatException bad) { return -1; }
        }
    }

    static final class Probe {
        final int pid, source;
        final String identity;
        final long begin, end, received;
        Probe(int p, String token, int s, long b, long e, long r) { pid=p; identity=token; source=s; begin=b; end=e; received=r; }
    }
    static final class Match {
        final Event event;
        final String identity;
        final long receivedUptime;
        Match(Event e, String token, long received) { event=e; identity=token; receivedUptime=received; }
    }
    static final class Pending {
        final Event event;
        final long received;
        Pending(Event e, long r) { event=e; received=r; }
    }

    /** Bounded, single-lock store. Old probe windows are retained to reject ambiguous PID reuse. */
    static final class Store {
        final LinkedHashMap<Integer, String> identities = new LinkedHashMap<>();
        final ArrayDeque<Probe> probes = new ArrayDeque<>();
        final LinkedHashMap<String, Pending> pending = new LinkedHashMap<>();
        final Map<Integer, Match> matches = new HashMap<>();
        long boundCount;
        void clear() { identities.clear(); probes.clear(); pending.clear(); matches.clear(); boundCount=0; }
        void identity(int pid, String token, long now) {
            if (pid <= 0) return;
            String old = identities.put(pid, token);
            if (!token.equals(old)) matches.remove(pid);
            while (identities.size() > 2048) {
                Integer first = identities.keySet().iterator().next(); identities.remove(first); matches.remove(first);
            }
        }
        void probe(int pid, String token, int source, long begin, long end, long now) {
            if (pid <= 0 || source <= 0 || token.isEmpty() || begin <= 0 || end < begin || end-begin > 10000) return;
            probes.addLast(new Probe(pid, token, source, begin, end, now));
            while (probes.size() > 512) probes.removeFirst();
        }
        void accept(Event event, long now) {
            if (!pending.containsKey(event.dedupKey)) pending.put(event.dedupKey, new Pending(event, now));
            while (pending.size() > 256) pending.remove(pending.keySet().iterator().next());
            reconcile(now);
        }
        void reconcile(long now) {
            while (!probes.isEmpty() && now-probes.peekFirst().received > MAX_AGE_MS) probes.removeFirst();
            Iterator<Pending> iterator = pending.values().iterator();
            while (iterator.hasNext()) {
                Pending item = iterator.next();
                if (now-item.received > MAX_AGE_MS) { iterator.remove(); continue; }
                String identity = null;
                boolean ambiguous = false;
                for (Probe probe : probes) {
                    if (probe.pid != item.event.targetPid || probe.source != item.event.sourcePid
                            || item.event.epochMs < probe.begin-100 || item.event.epochMs > probe.end+1500) continue;
                    if (identity != null && !identity.equals(probe.identity)) { ambiguous=true; break; }
                    identity = probe.identity;
                }
                if (ambiguous || identity == null || !identity.equals(identities.get(item.event.targetPid))) continue;
                Match previous = matches.get(item.event.targetPid);
                if (previous == null || item.event.epochMs > previous.event.epochMs) {
                    matches.put(item.event.targetPid, new Match(item.event, identity, item.received));
                    boundCount++;
                }
            }
            matches.entrySet().removeIf(e -> now-e.getValue().receivedUptime > MAX_AGE_MS);
        }
        Match lookup(int pid, String token, long now) {
            Match match = matches.get(pid);
            return match != null && !token.isEmpty() && token.equals(identities.get(pid)) && token.equals(match.identity)
                    && now-match.receivedUptime <= MAX_AGE_MS ? match : null;
        }
    }
}
