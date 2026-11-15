package com.gpucheck.app;

import android.content.Context;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.os.SystemClock;
import org.json.JSONArray;
import org.json.JSONObject;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.function.BooleanSupplier;

/** Recovered r.o/r.h and r.p/r.B protocols; all calls use the application's ordinary UID. */
final class MiuiProcessProbe {
    static final String CPU_DESCRIPTOR = "miui.IProcessManager";
    static final String MEMORY_DESCRIPTOR = "com.android.internal.app.IPerfShielder";
    static final int MEMORY_BATCH = 128, MEMORY_CANDIDATES = 512;
    private static final String[] JARS = {
            "/system_ext/framework/miui-framework.jar", "/system_ext/framework/miui-services.jar",
            "/system/framework/framework.jar", "/system/framework/services.jar",
            "/system/framework/miui-framework.jar", "/system/framework/miui-services.jar"};
    interface CodeResolver { int resolve(String className, String method) throws Exception; }
    static final class ResolvedCode {
        final int code;
        final String method;
        ResolvedCode(int code, String method) { this.code = code; this.method = method; }
    }
    private final CodeResolver resolver;
    private int memoryCursor;

    MiuiProcessProbe(Context context) {
        Context app = context.getApplicationContext();
        resolver = (className, method) -> OemProcessSupport.transactionCode(app, className, method, JARS);
    }

    JSONObject cpu(int[] candidates, BooleanSupplier cancelled) throws Exception {
        JSONObject report = OemProcessSupport.empty("miui_cpu", "CHECKING", "")
                .put("scope", "service_cpu_state_entries").put("coverageLimited", true)
                .put("cpuValueUnit", "vendor_raw_value_not_verified_percent");
        long start = SystemClock.elapsedRealtime();
        try {
            if (cancelled.getAsBoolean()) return finish(report, "CANCELLED", false, start);
            IBinder binder = OemProcessSupport.service("ProcessManager", CPU_DESCRIPTOR);
            int code = resolveCpuCode(resolver);
            if (code <= 0) return finish(report.put("detail", "No verified getProcessCpuState transaction constant; no fixed-code guess sent"),
                    "UNSUPPORTED_PROTOCOL", false, start);
            report.put("transaction", code).put("descriptor", CPU_DESCRIPTOR).put("transactionSource", "current_rom_named_constant");
            JSONArray current = new JSONArray();
            // The recovered sample makes two calls separated by 500 ms. Keep the newest list only.
            for (int sample = 0; sample < 2; sample++) {
                if (sample != 0) {
                    long until = SystemClock.elapsedRealtime() + 500;
                    while (SystemClock.elapsedRealtime() < until && !cancelled.getAsBoolean()) Thread.sleep(25);
                }
                if (cancelled.getAsBoolean()) return finish(report.put("rows", new JSONArray()), "CANCELLED", false, start);
                current = queryCpu(binder, code);
                report.put("samplesCompleted", sample + 1);
            }
            report.put("rows", current).put("rowCount", current.length());
            return finish(report, current.length() == 0 ? "EMPTY" : "AVAILABLE", true, start);
        } catch (Exception | LinkageError error) {
            if (error instanceof InterruptedException) Thread.currentThread().interrupt();
            return finish(report.put("detail", OemProcessSupport.rootCause(error).toString()).put("rows", new JSONArray()),
                    cancelled.getAsBoolean() ? "CANCELLED" : OemProcessSupport.status(error), false, start);
        }
    }

    JSONObject memory(int[] candidates, BooleanSupplier cancelled) throws Exception {
        JSONObject report = OemProcessSupport.empty("miui_memory", "CHECKING", "")
                .put("scope", "candidate_pid_parent_relationships").put("coverageLimited", true)
                .put("readsProcessAddressSpace", false).put("batchSize", MEMORY_BATCH);
        long start = SystemClock.elapsedRealtime();
        try {
            if (cancelled.getAsBoolean()) return finish(report, "CANCELLED", false, start);
            IBinder binder = OemProcessSupport.service("perfshielder", MEMORY_DESCRIPTOR);
            ResolvedCode resolved = resolveMemoryCode(resolver);
            String method = resolved.method;
            int code = resolved.code;
            if (code <= 0) return finish(report.put("detail", "No verified PerfShielder transaction constant"),
                    "UNSUPPORTED_PROTOCOL", false, start);
            report.put("transaction", code).put("method", method).put("descriptor", MEMORY_DESCRIPTOR)
                    .put("transactionSource", "current_rom_named_constant");
            LinkedHashSet<Integer> unique = new LinkedHashSet<>();
            if (candidates != null) for (int pid : candidates) if (pid > 0 && pid != Integer.MAX_VALUE) unique.add(pid);
            ArrayList<Integer> all = new ArrayList<>(unique);
            int count = Math.min(all.size(), MEMORY_CANDIDATES), first = all.isEmpty() ? 0 : memoryCursor % all.size();
            int[] chosen = new int[count];
            for (int i = 0; i < count; i++) chosen[i] = all.get((first + i) % all.size());
            memoryCursor = all.isEmpty() ? 0 : (first + count) % all.size();
            report.put("candidateCount", all.size()).put("candidateOffset", first).put("candidateBudget", MEMORY_CANDIDATES)
                    .put("candidatesQueried", 0).put("candidateCoverageComplete", count == all.size());
            if (count == 0) return finish(report, "NO_CANDIDATES", false, start);
            LinkedHashMap<Integer, JSONObject> rows = new LinkedHashMap<>();
            JSONArray queriedPids = new JSONArray();
            report.put("queriedPids", queriedPids);
            int batches = 0;
            for (int offset = 0; offset < count; offset += MEMORY_BATCH) {
                if (cancelled.getAsBoolean()) return finish(report.put("rows", new JSONArray()), "CANCELLED", false, start);
                int size = Math.min(MEMORY_BATCH, count - offset);
                int[] batch = new int[size];
                System.arraycopy(chosen, offset, batch, 0, size);
                for (int pid : batch) queriedPids.put(pid);
                JSONArray result = queryMemory(binder, code, batch);
                for (int i = 0; i < result.length(); i++) {
                    JSONObject row = result.getJSONObject(i); rows.put(row.getInt("pid"), row);
                }
                report.put("candidatesQueried", offset + size).put("batchesCompleted", ++batches);
            }
            report.put("rows", new JSONArray(rows.values())).put("rowCount", rows.size());
            return finish(report, rows.isEmpty() ? "EMPTY" : "AVAILABLE", true, start);
        } catch (Exception | LinkageError error) {
            return finish(report.put("detail", OemProcessSupport.rootCause(error).toString()).put("rows", new JSONArray()),
                    cancelled.getAsBoolean() ? "CANCELLED" : OemProcessSupport.status(error), false, start);
        }
    }

    static int resolveCpuCode(CodeResolver resolver) throws Exception {
        for (String cls : new String[]{"miui.process.IProcessManager$Stub", "miui.process.IProcessManager",
                "miui.process.ProcessManagerNative"}) {
            int code = tryCode(resolver, cls, "getProcessCpuState");
            if (code > 0) return code;
        }
        return -1;
    }

    static ResolvedCode resolveMemoryCode(CodeResolver resolver) throws Exception {
        for (String method : new String[]{"updateProcessPartialMemInfoByPids", "updateProcessFullMemInfoByPids"}) {
            for (String cls : new String[]{"com.android.internal.app.IPerfShielder$Stub", "com.android.internal.app.IPerfShielder"}) {
                int code = tryCode(resolver, cls, method);
                if (code > 0) return new ResolvedCode(code, method);
            }
        }
        return new ResolvedCode(-1, "");
    }

    private static int tryCode(CodeResolver resolver, String cls, String method) throws Exception {
        try {
            int code = resolver.resolve(cls, method);
            return code > 0 && code < 0x00ffffff ? code : -1;
        } catch (ReflectiveOperationException | UnsupportedOperationException missing) { return -1; }
    }

    static JSONArray queryCpu(IBinder binder, int code) throws Exception {
        if (!CPU_DESCRIPTOR.equals(binder.getInterfaceDescriptor())) throw new UnsupportedOperationException("Unexpected MIUI CPU descriptor");
        validCode(code);
        Parcel data = Parcel.obtain(), reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(CPU_DESCRIPTOR);
            if (!binder.transact(code, data, reply, 0)) throw new UnsupportedOperationException("Unhandled MIUI CPU transaction");
            OemProcessSupport.checkReply(reply);
            reply.readException();
            requireBytes(reply, 4);
            int count = reply.readInt();
            if (count < 0 || count > OemProcessSupport.MAX_ROWS || count > reply.dataAvail() / 4)
                throw new IllegalArgumentException("Invalid MIUI CPU row count");
            LinkedHashMap<Integer, JSONObject> rows = new LinkedHashMap<>();
            for (int i = 0; i < count; i++) {
                requireBytes(reply, 4);
                int present = reply.readInt();
                if (present == 0) continue;
                if (present != 1) throw new IllegalArgumentException("Invalid MIUI CPU entry marker");
                requireBytes(reply, 12);
                int pid = reply.readInt(), uid = reply.readInt();
                String name = reply.readString();
                requireBytes(reply, 4);
                float value = reply.readFloat();
                if (pid <= 0 || uid < 0 || name == null || name.trim().isEmpty() || name.length() > 4096)
                    throw new IllegalArgumentException("Invalid MIUI CPU identity");
                if (rows.containsKey(pid)) throw new IllegalArgumentException("Duplicate MIUI CPU PID");
                rows.put(pid, OemProcessSupport.row(pid, uid, name, -1, "miui_pm")
                        .put("uidSemantics", "vendor_reported_uid")
                        .put("stats", new JSONObject().put("cpuValue", Float.isFinite(value) ? value : JSONObject.NULL)
                                .put("cpuValueUnit", "vendor_raw_value_not_verified_percent")));
            }
            if (reply.dataAvail() != 0) throw new IllegalArgumentException("Unexpected MIUI CPU reply tail");
            return new JSONArray(rows.values());
        } finally { data.recycle(); reply.recycle(); }
    }

    static JSONArray queryMemory(IBinder binder, int code, int[] pids) throws Exception {
        if (!MEMORY_DESCRIPTOR.equals(binder.getInterfaceDescriptor())) throw new UnsupportedOperationException("Unexpected PerfShielder descriptor");
        validCode(code);
        if (pids == null || pids.length == 0 || pids.length > MEMORY_BATCH) throw new IllegalArgumentException("Invalid PerfShielder batch");
        Set<Integer> requested = new LinkedHashSet<>();
        for (int pid : pids) if (pid <= 0 || !requested.add(pid)) throw new IllegalArgumentException("Invalid requested PID");
        Parcel data = Parcel.obtain(), reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(MEMORY_DESCRIPTOR); data.writeIntArray(pids);
            if (!binder.transact(code, data, reply, 0)) throw new UnsupportedOperationException("Unhandled PerfShielder transaction");
            OemProcessSupport.checkReply(reply);
            reply.readException(); requireBytes(reply, 4);
            int count = reply.readInt();
            if (count < -1 || count > pids.length || (count >= 0 && count > reply.dataAvail() / 4))
                throw new IllegalArgumentException("Invalid PerfShielder result count");
            if (count == -1) throw new IllegalArgumentException("PerfShielder returned a null list");
            LinkedHashMap<Integer, JSONObject> rows = new LinkedHashMap<>();
            for (int i = 0; i < count; i++) {
                requireBytes(reply, 4);
                int present = reply.readInt();
                if (present == 0) continue;
                if (present != 1) throw new IllegalArgumentException("Invalid PerfShielder entry marker");
                requireBytes(reply, 4);
                Bundle bundle = Bundle.CREATOR.createFromParcel(reply);
                bundle.setClassLoader(null);
                Object pidValue = bundle.get("pid"), parentValue = bundle.get("ppid");
                if (!(pidValue instanceof Integer) || !(parentValue instanceof Integer)) continue;
                int pid = (Integer) pidValue, ppid = (Integer) parentValue;
                if (!requested.contains(pid) || ppid < 0 || ppid == pid || rows.containsKey(pid))
                    throw new IllegalArgumentException("Invalid PerfShielder parent identity");
                rows.put(pid, OemProcessSupport.row(pid, -1, "", ppid, "miui_perf_ppid"));
            }
            if (reply.dataAvail() != 0) throw new IllegalArgumentException("Unexpected PerfShielder reply tail");
            return new JSONArray(rows.values());
        } finally { data.recycle(); reply.recycle(); }
    }

    private static void validCode(int code) {
        if (code <= 0 || code >= 0x00ffffff) throw new IllegalArgumentException("Invalid Binder transaction code");
    }
    private static void requireBytes(Parcel reply, int size) {
        if (reply.dataAvail() < size) throw new IllegalArgumentException("Truncated OEM reply");
    }
    private static JSONObject finish(JSONObject report, String status, boolean available, long start) throws Exception {
        return report.put("status", status).put("available", available)
                .put("observedAtMs", SystemClock.elapsedRealtime()).put("durationMs", SystemClock.elapsedRealtime() - start)
                .put("brandGateUsed", false);
    }
}
