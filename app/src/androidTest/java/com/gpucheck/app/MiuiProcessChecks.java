package com.gpucheck.app;

import android.os.Binder;
import android.os.Bundle;
import android.os.Parcel;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Synthetic protocol/error controls only; never presented as Xiaomi device evidence. */
final class MiuiProcessChecks {
    private static int checks;
    static JSONObject run() throws Exception {
        checks = 0;
        FakeBinder cpu = new FakeBinder(false);
        JSONArray rows = MiuiProcessProbe.queryCpu(cpu, 34);
        require(rows.length() == 2 && rows.getJSONObject(0).getInt("uid") == 0, "CPU preserves UID zero");
        require(rows.getJSONObject(1).getInt("uid") == 10054 && rows.getJSONObject(1).getString("name").equals("com.example.worker"), "CPU identity fields");
        require(!rows.getJSONObject(0).has("cpuPercent") && rows.getJSONObject(0).getJSONObject("stats").getDouble("cpuValue") == 2.5, "Vendor CPU value is not percent");
        cpu.mode = "nan";
        require(MiuiProcessProbe.queryCpu(cpu, 34).getJSONObject(0).getJSONObject("stats").isNull("cpuValue"), "Nonfinite CPU stays unknown");
        cpu.mode = "empty";
        require(MiuiProcessProbe.queryCpu(cpu, 34).length() == 0, "Empty CPU list");
        cpu.mode = "null_entry";
        require(MiuiProcessProbe.queryCpu(cpu, 34).length() == 1, "CPU null entry does not invent identity");
        for (String mode : new String[]{"count", "truncated", "bad_presence", "duplicate", "negative_uid", "tail", "denied", "unhandled"}) {
            cpu.mode = mode; fails(() -> MiuiProcessProbe.queryCpu(cpu, 34), "CPU rejects " + mode);
        }
        cpu.mode = "ok"; cpu.attachInterface(null, "wrong");
        fails(() -> MiuiProcessProbe.queryCpu(cpu, 34), "CPU descriptor check");
        FakeBinder memory = new FakeBinder(true);
        rows = MiuiProcessProbe.queryMemory(memory, 77, new int[]{71, 72});
        require(rows.length() == 2 && rows.getJSONObject(0).getInt("ppid") == 8, "Perf parent relation");
        require(rows.getJSONObject(0).getInt("uid") == -1 && !rows.getJSONObject(0).has("memory"), "Perf does not infer UID or memory bytes");
        memory.mode = "missing";
        require(MiuiProcessProbe.queryMemory(memory, 77, new int[]{71, 72}).length() == 1, "Missing Bundle fields are not defaulted");
        memory.mode = "null_entry";
        require(MiuiProcessProbe.queryMemory(memory, 77, new int[]{71, 72}).length() == 1, "Null Bundle is ignored");
        for (String mode : new String[]{"unrequested", "negative_parent", "duplicate", "count", "truncated", "bad_presence", "tail", "denied", "unhandled"}) {
            memory.mode = mode; fails(() -> MiuiProcessProbe.queryMemory(memory, 77, new int[]{71, 72}), "Perf rejects " + mode);
        }
        fails(() -> MiuiProcessProbe.queryMemory(memory, 77, new int[]{71, 71}), "Reject duplicate input PID");
        fails(() -> MiuiProcessProbe.queryMemory(memory, 77, new int[129]), "Bound Perf request batch");
        require(MiuiProcessProbe.resolveCpuCode((cls, method) -> {
            if (!cls.endsWith("ProcessManagerNative")) throw new UnsupportedOperationException("synthetic absent class");
            return 62;
        }) == 62, "CPU tries later class after missing first mappings");
        require(MiuiProcessProbe.resolveCpuCode((cls, method) -> { throw new ClassNotFoundException("synthetic absent"); }) == -1,
                "CPU never guesses fallback transaction 34");
        MiuiProcessProbe.ResolvedCode full = MiuiProcessProbe.resolveMemoryCode((cls, method) -> {
            if (method.contains("Partial") || cls.endsWith("$Stub")) throw new UnsupportedOperationException("synthetic missing mapping");
            return 88;
        });
        require(full.code == 88 && full.method.equals("updateProcessFullMemInfoByPids"), "Perf falls back partial to full and second class");
        require(MiuiProcessProbe.resolveMemoryCode((cls, method) -> -1).code == -1, "Missing Perf mapping stays unsupported");
        dexChecks();
        return new JSONObject().put("result", "PASS").put("synthetic", true).put("checks", checks);
    }

    private static void dexChecks() throws Exception {
        byte[] dex = fixtureDex(34);
        require(OemDexConstants.fromDex(dex, "Lcom/example/Stub;", "TRANSACTION_read") == 34, "DEX static int after String constant");
        require(OemDexConstants.fromDex(dex, "Lcom/example/Missing;", "TRANSACTION_read") == -1, "DEX exact declaring class");
        require(OemDexConstants.fromDex(dex, "Lcom/example/Stub;", "TRANSACTION_other") == -1, "DEX exact field name");
        require(OemDexConstants.fromDex(fixtureDex(300), "Lcom/example/Stub;", "TRANSACTION_read") == 300, "DEX multibyte int constant");
        require(OemDexConstants.fromDex(fixtureDex(-3), "Lcom/example/Stub;", "TRANSACTION_read") == -1, "DEX signed invalid code rejected");
        byte[] container = dex.clone();
        container[6] = '1'; container[5] = '4'; put32(container, 36, 120); put32(container, 112, container.length); put32(container, 116, 0);
        require(OemDexConstants.fromDex(container, "Lcom/example/Stub;", "TRANSACTION_read") == 34, "DEX 041 absolute offsets");
        byte[] malformed = dex.clone(); put32(malformed, 96, Integer.MAX_VALUE);
        fails(() -> OemDexConstants.fromDex(malformed, "Lcom/example/Stub;", "TRANSACTION_read"), "DEX oversized table");
        byte[] shortFile = Arrays.copyOf(dex, 200);
        fails(() -> OemDexConstants.fromDex(shortFile, "Lcom/example/Stub;", "TRANSACTION_read"), "DEX truncated container");
        byte[] noFinal = dex.clone(); noFinal[305] = 8; noFinal[307] = 8;
        require(OemDexConstants.fromDex(noFinal, "Lcom/example/Stub;", "TRANSACTION_read") == -1, "DEX mutable fields not accepted as constants");
        byte[] corruptLeb = dex.clone(); Arrays.fill(corruptLeb, 300, 305, (byte) 0x80);
        fails(() -> OemDexConstants.fromDex(corruptLeb, "Lcom/example/Stub;", "TRANSACTION_read"), "DEX invalid LEB128 bounded");
    }

    private static byte[] fixtureDex(int transaction) {
        byte[] data = new byte[768];
        byte[] magic = {'d', 'e', 'x', '\n', '0', '3', '9', 0}; System.arraycopy(magic, 0, data, 0, 8);
        put32(data, 32, data.length); put32(data, 36, 112); put32(data, 40, 0x12345678);
        put32(data, 56, 6); put32(data, 60, 128); put32(data, 64, 3); put32(data, 68, 152);
        put32(data, 80, 2); put32(data, 84, 164); put32(data, 96, 1); put32(data, 100, 180);
        put32(data, 152, 0); put32(data, 156, 1); put32(data, 160, 4);
        data[166] = 2; put32(data, 168, 3); data[174] = 1; put32(data, 176, 2);
        put32(data, 204, 300); put32(data, 208, 320);
        // class_data: two static fields, no instance fields/methods, both static final.
        byte[] declarations = {2, 0, 0, 0, 0, 0x18, 1, 0x18}; System.arraycopy(declarations, 0, data, 300, declarations.length);
        // encoded_array: String reference followed by four-byte signed int.
        data[320] = 2; data[321] = 0x17; data[322] = 5; data[323] = 0x64; put32(data, 324, transaction);
        String[] strings = {"Lcom/example/Stub;", "I", "TRANSACTION_read", "DESCRIPTOR", "Ljava/lang/String;", "synthetic"};
        int at = 400;
        for (int i = 0; i < strings.length; i++) {
            put32(data, 128 + i * 4, at); byte[] text = strings[i].getBytes(StandardCharsets.US_ASCII);
            data[at++] = (byte) text.length; System.arraycopy(text, 0, data, at, text.length); at += text.length + 1;
        }
        return data;
    }
    private static void put32(byte[] data, int offset, int value) { for (int i = 0; i < 4; i++) data[offset + i] = (byte) (value >>> (i * 8)); }
    private interface Throwing { void run() throws Exception; }
    private static void fails(Throwing action, String reason) throws Exception {
        try { action.run(); } catch (Exception expected) { checks++; return; }
        throw new AssertionError(reason);
    }
    private static void require(boolean value, String reason) { if (!value) throw new AssertionError(reason); checks++; }

    private static final class FakeBinder extends Binder {
        final boolean memory;
        String mode = "ok";
        FakeBinder(boolean memory) { this.memory = memory; attachInterface(null, memory ? MiuiProcessProbe.MEMORY_DESCRIPTOR : MiuiProcessProbe.CPU_DESCRIPTOR); }
        @Override protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) {
            data.enforceInterface(memory ? MiuiProcessProbe.MEMORY_DESCRIPTOR : MiuiProcessProbe.CPU_DESCRIPTOR);
            if (memory) {
                int[] input = data.createIntArray();
                if (!Arrays.equals(input, new int[]{71, 72})) throw new AssertionError("Unexpected synthetic PID query");
            }
            if (data.dataAvail() != 0) throw new AssertionError("Unexpected request tail");
            if (mode.equals("unhandled")) return false;
            if (mode.equals("denied")) { reply.writeException(new SecurityException("synthetic permission denial")); return true; }
            reply.writeNoException();
            if (mode.equals("count")) { reply.writeInt(1000000); return true; }
            if (mode.equals("truncated")) { reply.writeInt(1); return true; }
            if (mode.equals("empty")) { reply.writeInt(0); return true; }
            reply.writeInt(2);
            for (int i = 0; i < 2; i++) {
                if (mode.equals("null_entry") && i == 0) { reply.writeInt(0); continue; }
                if (mode.equals("bad_presence")) { reply.writeInt(8); continue; }
                reply.writeInt(1);
                int pid = mode.equals("unrequested") ? 99 : mode.equals("duplicate") ? 71 : 71 + i;
                if (memory) {
                    Bundle bundle = new Bundle();
                    if (!(mode.equals("missing") && i == 0)) bundle.putInt("pid", pid);
                    bundle.putInt("ppid", mode.equals("negative_parent") ? -1 : 8);
                    bundle.putInt("uid", 9999); bundle.putString("memory", "not process bytes");
                    bundle.writeToParcel(reply, 0);
                } else {
                    reply.writeInt(pid); reply.writeInt(mode.equals("negative_uid") ? -1 : i == 0 ? 0 : 10054);
                    reply.writeString(i == 0 ? "native-worker" : "com.example.worker");
                    reply.writeFloat(mode.equals("nan") ? Float.NaN : 2.5f);
                }
            }
            if (mode.equals("tail")) reply.writeInt(7);
            return true;
        }
    }
}
