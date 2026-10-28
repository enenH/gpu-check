package com.gpucheck.app;

import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Paths;

/** Parser and identity association tests; no Android calls or device required. */
public final class AvcEvidenceTest {
    private static final String OWN = "u:r:untrusted_app:s0:c56,c256,c512,c768";
    private static final long TIME = 1793203044155L;
    private static int passed;
    private static String line() {
        return "1793203044.155000 23247 23247 W libgpu_probe.so: type=1400 audit(0.0:15081): avc:  denied  { getattr } for "
                + "path=\"/proc/22501\" dev=\"proc\" ino=339333 scontext=" + OWN
                + " tcontext=u:r:ksu:s0 tclass=dir permissive=0 app=com.gpucheck.app";
    }
    private static AvcEvidence.Event parse(String text) { return AvcEvidence.Parser.parse(text, OWN); }
    private static byte[] packet(String message, int uid) {
        byte[] payload=("\u0005libgpu_probe.so\0"+message+"\0").getBytes(StandardCharsets.UTF_8);
        ByteBuffer buffer=ByteBuffer.allocate(28+payload.length).order(ByteOrder.LITTLE_ENDIAN);
        buffer.putShort((short)payload.length).putShort((short)28).putInt(23247).putInt(23247)
                .putInt((int)(TIME/1000)).putInt((int)((TIME%1000)*1000000)).putInt(0).putInt(uid).put(payload);
        return buffer.array();
    }
    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        passed++;
    }
    private static void rejected(String text, String message) { check(parse(text) == null, message); }
    private static AvcEvidence.Store store(String token, long begin, long end) {
        AvcEvidence.Store store = new AvcEvidence.Store();
        store.identity(22501, token, 1000);
        store.probe(22501, token, 23247, begin, end, 1000);
        return store;
    }
    public static void main(String[] args) throws Exception {
        String credentials="Name:\tGPUCheck\nUid:\t10056 10056 10056 10056\nGid:\t10056 10056 10056 10056\n"
                +"Groups:\t10056 3003 9997\nCapEff:\t0000000000000000\n";
        check(AvcEvidence.hasOrdinaryCredentials(credentials,10056),"ordinary App credentials permit self-only connection");
        for(String privileged:new String[]{"0","1000","1007"}) {
            check(!AvcEvidence.hasOrdinaryCredentials(credentials.replace("3003",privileged),10056),"privileged group blocked before connection "+privileged);
        }
        check(!AvcEvidence.hasOrdinaryCredentials(credentials.replace("Gid:\t10056 10056 10056 10056","Gid:\t1007 1007 1007 1007"),10056),"LOG primary gid rejected");
        check(!AvcEvidence.hasOrdinaryCredentials(credentials,10057),"unexpected actual UID rejected");
        check(!AvcEvidence.hasOrdinaryCredentials(credentials.replace("CapEff:\t0000000000000000","CapEff:\t0000000000000001"),10056),"capabilities rejected");
        check(!AvcEvidence.hasOrdinaryCredentials(credentials.replace("Groups:\t10056 3003 9997\n",""),10056),"unreadable group metadata fails closed");
        byte[] packet=packet(line().substring(line().indexOf("type=1400")),10056);
        String binaryLine=AvcEvidence.BinaryParser.toLine(packet,packet.length,10056);
        check(binaryLine!=null && parse(binaryLine).targetPid==22501,"real logger_entry v4 packet decoded and parsed");
        check(AvcEvidence.BinaryParser.toLine(packet,packet.length,10057)==null,"foreign UID packet rejected locally");
        check(AvcEvidence.BinaryParser.toLine(packet,packet.length-1,10056)==null,"truncated seqpacket rejected");
        byte[] changed=packet.clone(); changed[2]=20;
        check(AvcEvidence.BinaryParser.toLine(changed,changed.length,10056)==null,"legacy header without UID rejected");
        changed=packet.clone(); ByteBuffer.wrap(changed).order(ByteOrder.LITTLE_ENDIAN).putInt(16,1000000000);
        check(AvcEvidence.BinaryParser.toLine(changed,changed.length,10056)==null,"invalid nanoseconds rejected");
        changed=packet.clone(); ByteBuffer.wrap(changed).order(ByteOrder.LITTLE_ENDIAN).putInt(20,2);
        check(AvcEvidence.BinaryParser.toLine(changed,changed.length,10056)==null,"non-main binary buffer rejected");
        changed=packet.clone(); changed[changed.length-1]=65;
        check(AvcEvidence.BinaryParser.toLine(changed,changed.length,10056)==null,"unterminated binary message rejected");
        changed=packet.clone(); ByteBuffer.wrap(changed).order(ByteOrder.LITTLE_ENDIAN).putInt(4,-1);
        check(AvcEvidence.BinaryParser.toLine(changed,changed.length,10056)==null,"invalid packet source PID rejected");
        AvcEvidence.Event event = parse(line());
        check(event != null && event.targetPid == 22501 && event.sourcePid == 23247, "header PID is source, path is target");
        check(event.rootDomain && "ksu".equals(event.domain) && event.epochMs == TIME, "domain and epoch parsed");
        event = parse(line().replace("for path=", "for pid=777 path="));
        check(event != null && event.sourcePid == 777 && event.targetPid == 22501, "body PID is source, never target");
        check(parse(line().replace("path=\"/proc/22501\"", "name=\"22501\"")) != null, "numeric proc directory name");
        check(parse(line().replace('"', '\'')) != null, "single quoted fields accepted");
        for (String domain : new String[]{"su", "magisk", "zygisk", "ksu"}) {
            check(parse(line().replace(":ksu:", ":"+domain+":")).rootDomain, "known root domain "+domain);
        }
        check(!parse(line().replace(":ksu:", ":kernel:")).rootDomain, "kernel domain not automatically root tool");
        check(!parse(line().replace(":ksu:", ":notksu:")).rootDomain, "domain substrings are not matches");
        rejected(line().replace("path=\"/proc/22501\"", "path=\"/proc/22501\" name=\"12\""), "conflicting path and name");
        rejected(line().replace("/proc/22501", "/proc/22501/fd"), "subdirectory lacks exact process-dir proof");
        rejected(line().replace("/proc/22501", "/data/local/tmp/22501"), "non-proc numeric path");
        rejected(line().replace("dev=\"proc\"", "dev=\"tmpfs\""), "wrong filesystem");
        rejected(line().replace("tclass=dir", "tclass=file"), "wrong object class");
        rejected(line().replace(OWN, "u:r:untrusted_app:s0:c57,c256,c512,c768"), "foreign app scontext");
        rejected(line().replace("path=\"/proc/22501\"", "path=\"/proc/23247\""), "self target excluded");
        rejected(line().replace("path=\"/proc/22501\"", "pid=22501"), "source pid alone never identifies target");
        rejected(line().replace("type=1400", "type=1401"), "wrong audit event type");
        rejected(line().replace("denied", "granted"), "not a denial");
        rejected(line().replace("getattr", "read"), "not the metadata probe");
        rejected(line().replace("permissive=0", "permissive=1"), "permissive audit is not a real rejection");
        rejected(line().substring(line().indexOf("type=1400")), "missing log timestamp and emitter");
        rejected(line()+" tcontext=u:r:su:s0", "duplicate identity fields");
        rejected(line().replace("22501", "99999999999"), "PID overflow");
        rejected(line()+new String(new char[9000]).replace('\0','x'), "oversized record");

        AvcEvidence.Store store = new AvcEvidence.Store();
        store.accept(parse(line()), 1000);
        check(store.lookup(22501, "a", 1000) == null, "log without lifecycle is pending only");
        store.identity(22501, "a", 1001);
        store.probe(22501, "a", 23247, TIME-2, TIME+2, 1001);
        store.reconcile(1001);
        check(store.lookup(22501, "a", 1001) != null, "pending log binds after probe report");
        store.accept(parse(line()), 1002);
        check(store.boundCount == 1 && store.pending.size() == 1, "duplicate log not recounted");
        check(store.lookup(22501, "b", 1002) == null, "different lifecycle token rejected");

        store = store("a", TIME-2, TIME+2);
        store.accept(parse(line().replace("for path=", "for pid=777 path=")), 1000);
        check(store.lookup(22501, "a", 1000) == null, "source PID must match actual probe");
        store = store("a", TIME+150, TIME+160);
        store.accept(parse(line()), 1000);
        check(store.lookup(22501, "a", 1000) == null, "older log cannot bind to later probe");
        store = store("a", TIME+10, TIME+11);
        store.accept(parse(line()),1000);
        check(store.lookup(22501,"a",1000)!=null,"coarse AVC timestamp ten ms before probe is accepted");
        store = store("a", TIME-2000, TIME-1900);
        store.accept(parse(line()), 1000);
        check(store.lookup(22501, "a", 1000) == null, "log outside delivery tolerance rejected");
        store = store("", TIME-2, TIME+2);
        store.accept(parse(line()), 1000);
        check(store.lookup(22501, "", 1000) == null, "unknown lifecycle is not accepted");

        store = store("a", TIME-2, TIME+2);
        store.accept(parse(line()), 1000);
        store.identity(22501, "b", 1001);
        check(store.lookup(22501, "b", 1001) == null, "PID reuse clears prior evidence");
        store.probe(22501, "b", 23247, TIME-1, TIME+2, 1001);
        store.reconcile(1001);
        check(store.lookup(22501, "b", 1001) == null, "ambiguous reuse windows cannot rebind old event");
        store.probe(22501, "b", 23247, TIME+3000, TIME+3001, 4000);
        store.accept(parse(line().replace("1793203044.155000", "1793203047.155000").replace(":15081)", ":15082)")), 4000);
        check(store.lookup(22501, "b", 4000) != null, "new unambiguous event binds new lifecycle");
        store.reconcile(4000+AvcEvidence.MAX_AGE_MS+1);
        check(store.lookup(22501, "b", 4000+AvcEvidence.MAX_AGE_MS+1) == null, "evidence expires");

        store = store("a", TIME-2, TIME+2);
        store.accept(parse(line()), 1000);
        store.probe(22501, "a", 23247, TIME+2000, TIME+2001, 3000);
        store.accept(parse(line().replace("1793203044.155000", "1793203046.155000").replace(":ksu:", ":shell:")), 3000);
        check(!store.lookup(22501, "a", 3000).event.rootDomain, "new non-root domain supersedes old hint");
        for (int i=0;i<600;i++) store.probe(22501,"a",23247,TIME+i,TIME+i+1,4000+i);
        check(store.probes.size() <= 512, "probe history bounded");
        for (int i=0;i<2200;i++) store.identity(i+1,"token",5000);
        check(store.identities.size() <= 2048, "identity history bounded");
        for (int i=0;i<300;i++) store.accept(parse(line().replace(":15081)", ":"+(16000+i)+")")),6000);
        check(store.pending.size() <= 256, "pending events bounded");
        store.clear();
        check(store.pending.isEmpty() && store.probes.isEmpty() && store.matches.isEmpty(), "stop resets association");

        if (args.length > 0) {
            int actual=0;
            for (String sample : Files.readAllLines(Paths.get(args[0]), StandardCharsets.UTF_8)) {
                if (!sample.matches("\\d\\d-\\d\\d \\d\\d:\\d\\d:\\d\\d\\.\\d{3}.*")) continue;
                String normalized = "1793203044.155000" + sample.substring(18);
                if (parse(normalized) != null) actual++;
            }
            check(actual > 0, "real device AVC payloads accepted after timestamp-format normalization");
            System.out.println("Real device payloads parsed: " + actual);
        }
        System.out.println("AvcEvidence: " + passed + " checks passed.");
    }
}
