package com.gpucheck.app;

import android.app.ActivityManager;
import android.content.Context;
import android.os.Build;
import android.os.IBinder;
import android.os.Parcel;
import android.os.SystemClock;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/** Recovered r.E/G/j/u/y and r.C/H/n protocols; no brand is used to skip either service. */
final class RedVivoProcessProbe {
    static final String MIND_DESCRIPTOR = "com.zte.performance.mindsync.IMindSyncManager";
    static final String VIVO_DESCRIPTOR = "com.vivo.rms.IRM";
    static final String NX769J_FINGERPRINT =
            "nubia/NX769J/NX769J:16/BQ2A.250705.001-BP2A.250605.031.A3/20260813.151005:user/release-keys";
    static final int MIND_MAX_ROWS = 64;
    static final int VIVO_QUERY_BUDGET = 256;
    static final long VIVO_TIME_BUDGET_MS = 1500;
    private static final int MAX_STRING = 4096;
    private static final int VIVO_MAX_REPLY = 65536;
    private final Context context;
    private final IBinder injectedMind, injectedVivo;
    private final int injectedMindCode, injectedVivoCode;
    private int vivoCursorPid;

    RedVivoProcessProbe(Context context) { this(context, null, -1, null, -1); }

    // Test-only injection uses the same production transaction and validation code.
    RedVivoProcessProbe(Context context, IBinder mind, int mindCode, IBinder vivo, int vivoCode) {
        this.context = context == null ? null : context.getApplicationContext();
        injectedMind = mind; injectedMindCode = mindCode;
        injectedVivo = vivo; injectedVivoCode = vivoCode;
    }

    JSONObject mindsync(int[] candidates, BooleanSupplier cancelled) throws JSONException {
        JSONObject result = OemProcessSupport.empty("mindsync", "CHECKING", "")
                .put("coverage", "service_top_records").put("coverageLimited", true)
                .put("perPhaseRowLimit", MIND_MAX_ROWS).put("brandGateUsed", false);
        JSONArray attempts = new JSONArray();
        result.put("attempts", attempts);
        long started = SystemClock.elapsedRealtime();
        try {
            checkCancelled(cancelled);
            IBinder binder = injectedMind == null
                    ? OemProcessSupport.service("mindsyncservice", MIND_DESCRIPTOR) : injectedMind;
            requireDescriptor(binder, MIND_DESCRIPTOR);
            int code = injectedMindCode;
            String resolution = "injected_test";
            if (injectedMind == null) {
                resolution = "named_transaction_field";
                try {
                    code = OemProcessSupport.transactionCode(context, MIND_DESCRIPTOR + "$Stub", "getProcessTopInfo",
                            "/system/framework/framework.jar", "/system/framework/services.jar");
                } catch (Exception | LinkageError unavailable) {
                    // The original payload only associates 66 with this exact build, never with a brand.
                    code = fingerprintTransaction(Build.FINGERPRINT);
                    if (code < 0) throw unavailable;
                    resolution = "exact_recovered_NX769J_fingerprint";
                }
            }
            requireTransaction(code);
            result.put("transaction", code).put("transactionResolution", resolution);
            queryMind(binder, code, "init", attempts);
            cancellableDelay(cancelled, 250);
            LinkedHashMap<Integer, JSONObject> rows = new LinkedHashMap<>();
            Set<Integer> conflicts = new HashSet<>();
            int malformed = 0, successfulPhases = 0;
            for (String phase : new String[]{"mem", "cpu"}) {
                checkCancelled(cancelled);
                try {
                    List<String> records = queryMind(binder, code, phase, attempts);
                    successfulPhases++;
                    int accepted = 0;
                    for (String record : records) {
                        JSONObject row = parseMindRecord(record, phase);
                        if (row == null) { malformed++; continue; }
                        int pid = row.getInt("pid");
                        if (conflicts.contains(pid)) { malformed++; continue; }
                        JSONObject old = rows.get(pid);
                        if (old != null && !old.getString("name").equals(row.getString("name"))) {
                            // Two sequential lists can cross a PID reuse. Do not choose either identity.
                            rows.remove(pid); conflicts.add(pid); malformed++; continue;
                        }
                        if (old == null) rows.put(pid, row);
                        else old.getJSONObject("stats").put(phase, row.getJSONObject("stats").getJSONObject(phase));
                        accepted++;
                    }
                    result.put(phase + "Rows", records.size()).put(phase + "Accepted", accepted);
                } catch (SecurityException denied) { throw denied; }
                catch (Exception | LinkageError unavailable) {
                    result.put(phase + "Error", concise(unavailable));
                }
            }
            checkCancelled(cancelled);
            boolean truncated = false;
            for (int i = 0; i < attempts.length(); i++) truncated |= attempts.getJSONObject(i).optBoolean("truncated");
            boolean available = successfulPhases > 0 && (malformed == 0 || !rows.isEmpty());
            result.put("rows", new JSONArray(rows.values())).put("malformedRows", malformed)
                    .put("truncated", truncated)
                    .put("conflictingPids", new JSONArray(conflicts)).put("available", available)
                    .put("status", !available ? (successfulPhases == 0 ? "FAILED" : "MALFORMED")
                            : successfulPhases < 2 || malformed > 0 || truncated ? "PARTIAL" : rows.isEmpty() ? "EMPTY" : "AVAILABLE");
        } catch (Exception | LinkageError error) {
            result.put("available", false).put("rows", new JSONArray())
                    .put("status", failureStatus(error)).put("detail", concise(error));
        }
        return result.put("observedAtMs", SystemClock.elapsedRealtime())
                .put("durationMs", SystemClock.elapsedRealtime() - started);
    }

    JSONObject vivo(int[] candidates, BooleanSupplier cancelled) throws JSONException {
        JSONObject result = OemProcessSupport.empty("vivo_rms", "CHECKING", "")
                .put("coverage", "queried_candidate_pids").put("coverageLimited", true)
                .put("queryBudget", VIVO_QUERY_BUDGET).put("brandGateUsed", false);
        JSONArray rows = new JSONArray(), errors = new JSONArray(), queriedPids = new JSONArray();
        result.put("queriedPids", queriedPids);
        long started = SystemClock.elapsedRealtime();
        int queried = 0, controlQueries = 0, successful = 0, misses = 0, malformed = 0;
        TreeSet<Integer> unique = new TreeSet<>();
        if (candidates != null) for (int pid : candidates) if (pid > 1) unique.add(pid);
        // Self is an explicit positive control, not an externally supplied target or a detected row.
        unique.remove(android.os.Process.myPid());
        result.put("candidateCount", unique.size()).put("candidateCursorBefore", vivoCursorPid);
        try {
            checkCancelled(cancelled);
            IBinder binder = injectedVivo == null
                    ? OemProcessSupport.service("rms", VIVO_DESCRIPTOR) : injectedVivo;
            requireDescriptor(binder, VIVO_DESCRIPTOR);
            int code = injectedVivo == null
                    ? OemProcessSupport.transactionCode(context, "com.vivo.services.rms.sdk.IRM",
                            "GET_RUNNING_APP_PROCESSES", "/system/framework/vivo-services.jar") : injectedVivoCode;
            requireTransaction(code);
            result.put("transaction", code).put("transactionResolution", injectedVivo == null
                    ? "named_IRM_constant" : "injected_test");
            controlQueries++;
            ActivityManager.RunningAppProcessInfo control = queryVivo(binder, code, android.os.Process.myPid());
            boolean selfVerified = control != null && control.uid == android.os.Process.myUid();
            result.put("selfControl", new JSONObject().put("pid", android.os.Process.myPid())
                    .put("matched", selfVerified).put("reportedUid", control == null ? -1 : control.uid)
                    .put("expectedUid", android.os.Process.myUid()));
            if (control != null && !selfVerified) throw new IllegalArgumentException("RMS self UID mismatch");
            successful++;
            ArrayList<Integer> ordered = new ArrayList<>(unique.size());
            ordered.addAll(unique.tailSet(vivoCursorPid, false));
            ordered.addAll(unique.headSet(vivoCursorPid, true));
            long queryStarted = SystemClock.elapsedRealtime();
            for (int pid : ordered) {
                checkCancelled(cancelled);
                if (queried >= VIVO_QUERY_BUDGET - 1 || SystemClock.elapsedRealtime() - queryStarted >= VIVO_TIME_BUDGET_MS) break;
                queried++; vivoCursorPid = pid; queriedPids.put(pid);
                try {
                    ActivityManager.RunningAppProcessInfo info = queryVivo(binder, code, pid);
                    successful++;
                    if (info == null) { misses++; continue; }
                    rows.put(OemProcessSupport.row(info.pid, info.uid, info.processName, -1, "vivo_rms")
                            .put("uidSemantics", "service_reported_uid")
                            .put("requestedPid", pid));
                } catch (SecurityException | UnsupportedOperationException failure) { throw failure; }
                catch (Exception failure) {
                    malformed++;
                    if (errors.length() < 8) errors.put(new JSONObject().put("pid", pid).put("detail", concise(failure)));
                    if (malformed >= 8) break;
                }
            }
            checkCancelled(cancelled);
            boolean complete = queried == unique.size();
            result.put("available", successful > 0).put("rows", rows)
                    .put("status", malformed > 0 || !complete ? "PARTIAL" : rows.length() == 0 ? "EMPTY" : "AVAILABLE");
        } catch (Exception | LinkageError failure) {
            result.put("available", false).put("rows", new JSONArray())
                    .put("status", failureStatus(failure)).put("detail", concise(failure));
        }
        return result.put("queriedCandidates", queried).put("queryCount", queried + controlQueries)
                .put("unqueriedCandidates", unique.size() - queried)
                .put("allCandidatesQueried", queried == unique.size()).put("candidateCursorAfter", vivoCursorPid)
                .put("misses", misses).put("malformedRows", malformed).put("errors", errors)
                .put("observedAtMs", SystemClock.elapsedRealtime())
                .put("durationMs", SystemClock.elapsedRealtime() - started);
    }

    static int fingerprintTransaction(String fingerprint) {
        return NX769J_FINGERPRINT.equals(fingerprint) ? 66 : -1;
    }

    static JSONObject parseMindRecord(String record, String phase) throws JSONException {
        if (record == null || record.length() > MAX_STRING || !(phase.equals("mem") || phase.equals("cpu"))) return null;
        String[] fields = record.trim().split("\\s+", 5);
        if (fields.length != 5 || !validName(fields[4])) return null;
        try {
            int pid = Integer.parseInt(fields[0]);
            float value = Float.parseFloat(fields[1]);
            long counter2 = Long.parseLong(fields[2]);
            int counter3 = Integer.parseInt(fields[3]);
            if (pid <= 0 || !Float.isFinite(value) || value < 0 || counter2 < 0 || counter3 < 0) return null;
            // Only PID/name are identified. The three numeric statistics are NOT UID or PPID.
            JSONObject stats = new JSONObject().put("value", (double) value).put("counter2", counter2)
                    .put("counter3", counter3).put("units", "vendor_defined_unverified");
            return OemProcessSupport.row(pid, -1, fields[4], -1, "mindsync")
                    .put("stats", new JSONObject().put(phase, stats));
        } catch (NumberFormatException ignored) { return null; }
    }

    static List<String> queryMind(IBinder binder, int code, String phase, JSONArray evidence) throws Exception {
        requireTransaction(code);
        if (!(phase.equals("init") || phase.equals("mem") || phase.equals("cpu")))
            throw new IllegalArgumentException("Unsupported MindSync command");
        Parcel data = Parcel.obtain(), reply = Parcel.obtain();
        JSONObject attempt = new JSONObject().put("command", phase).put("transaction", code).put("handled", false);
        evidence.put(attempt);
        try {
            data.writeInterfaceToken(MIND_DESCRIPTOR); data.writeString(phase);
            boolean handled = binder.transact(code, data, reply, 0);
            attempt.put("handled", handled).put("replyBytes", reply.dataSize());
            if (!handled) throw new UnsupportedOperationException("MindSync transaction not handled");
            requireReply(reply, OemProcessSupport.MAX_REPLY_BYTES);
            reply.readException();
            if (reply.dataAvail() < 4) throw new IllegalArgumentException("Missing MindSync list length");
            int count = reply.readInt();
            if (count < -1 || count > OemProcessSupport.MAX_ROWS)
                throw new IllegalArgumentException("MindSync list exceeds validation budget");
            ArrayList<String> records = new ArrayList<>(Math.min(Math.max(count, 0), MIND_MAX_ROWS));
            for (int i = 0; i < count; i++) {
                String record = readBoundedString(reply);
                if (i < MIND_MAX_ROWS) records.add(record);
            }
            if (reply.dataAvail() != 0) throw new IllegalArgumentException("Trailing MindSync reply data");
            attempt.put("status", count > MIND_MAX_ROWS ? "PARTIAL" : "AVAILABLE")
                    .put("reportedRows", Math.max(count, 0)).put("rows", records.size())
                    .put("truncated", count > MIND_MAX_ROWS);
            return records;
        } catch (Exception failure) {
            attempt.put("status", failureStatus(failure)).put("detail", concise(failure)); throw failure;
        } finally { data.recycle(); reply.recycle(); }
    }

    static ActivityManager.RunningAppProcessInfo queryVivo(IBinder binder, int code, int pid) throws Exception {
        requireTransaction(code);
        if (pid <= 0) throw new IllegalArgumentException("Invalid RMS requested PID");
        Parcel data = Parcel.obtain(), reply = Parcel.obtain();
        try {
            // r.C deliberately writes no interface token. RMS uses an ordinary int PID payload.
            data.writeInt(pid);
            if (!binder.transact(code, data, reply, 0)) throw new UnsupportedOperationException("RMS transaction not handled");
            requireReply(reply, VIVO_MAX_REPLY);
            try {
                // Bound string/array allocations before the platform's Parcelable decoder runs.
                preflightVivoPrefix(reply);
                reply.setDataPosition(0);
                ActivityManager.RunningAppProcessInfo info = new ActivityManager.RunningAppProcessInfo();
                info.readFromParcel(reply);
                if (reply.dataAvail() < 4) throw new IllegalArgumentException("Missing RMS exception trailer");
                reply.readException();
                if (reply.dataAvail() != 0) throw new IllegalArgumentException("Trailing RMS reply data");
                if (info.pid == 0 && (info.processName == null || info.processName.isEmpty())) return null;
                if (info.pid != pid || info.uid < 0 || !validName(info.processName))
                    throw new IllegalArgumentException("RMS returned a mismatched PID or invalid identity");
                return info;
            } catch (SecurityException denied) { throw denied; }
            catch (RuntimeException malformed) {
                // A Binder-level denial can be an exception-only reply instead of RMS's normal layout.
                reply.setDataPosition(0);
                try { reply.readException(); }
                catch (SecurityException denied) { throw denied; }
                catch (RuntimeException ignored) { /* Preserve original validation failure. */ }
                throw malformed;
            }
        } finally { data.recycle(); reply.recycle(); }
    }

    private static void preflightVivoPrefix(Parcel reply) {
        readBoundedString(reply);
        if (reply.dataAvail() < 8) throw new IllegalArgumentException("Truncated RMS PID/UID");
        reply.readInt(); reply.readInt();
        // pkgDeps was absent in older Android releases. Calibrate against this platform's
        // public Parcelable writer; using a fixed SDK-35 layout would misread old flags.
        for (int array = 0; array < VivoLayout.STRING_ARRAYS; array++) {
            if (reply.dataAvail() < 4) throw new IllegalArgumentException("Truncated RMS package array");
            int count = reply.readInt();
            if (count < -1 || count > 1024) throw new IllegalArgumentException("Oversized RMS package array");
            for (int i = 0; i < count; i++) readBoundedString(reply);
        }
    }

    private static final class VivoLayout {
        static final int STRING_ARRAYS = countStringArrays();
        private static int countStringArrays() {
            Parcel model = Parcel.obtain();
            try {
                ActivityManager.RunningAppProcessInfo empty =
                        new ActivityManager.RunningAppProcessInfo("layout", 1, new String[0]);
                empty.writeToParcel(model, 0);
                model.setDataPosition(0);
                readBoundedString(model); model.readInt(); model.readInt();
                if (model.readInt() != 0) throw new IllegalArgumentException("Unexpected RMS package layout");
                int next = model.readInt();
                if (next == -1) return 2; // null pkgDeps, then flags
                if (next == 0) return 1; // default flags directly after empty pkgList
                throw new IllegalArgumentException("Unsupported RunningAppProcessInfo layout");
            } finally { model.recycle(); }
        }
    }

    private static String readBoundedString(Parcel parcel) {
        if (parcel.dataAvail() < 4) throw new IllegalArgumentException("Truncated String16 length");
        int start = parcel.dataPosition(), length = parcel.readInt();
        if (length < -1 || length > MAX_STRING) throw new IllegalArgumentException("Invalid String16 length");
        long bytes = length < 0 ? 0 : (((long) length + 1) * 2 + 3) & ~3L;
        if (bytes > parcel.dataAvail()) throw new IllegalArgumentException("Truncated String16 data");
        parcel.setDataPosition(start);
        String value = parcel.readString();
        if (length >= 0 && (value == null || value.length() != length)) throw new IllegalArgumentException("Invalid String16");
        return value;
    }

    private static void requireReply(Parcel reply, int limit) {
        if (reply.dataSize() < 4 || reply.dataSize() > limit || reply.hasFileDescriptors())
            throw new IllegalArgumentException("Invalid OEM reply size or file descriptors");
        reply.setDataPosition(0);
    }

    private static boolean validName(String name) {
        if (name == null || name.isEmpty() || name.length() > MAX_STRING) return false;
        for (int i = 0; i < name.length(); i++) if (Character.isISOControl(name.charAt(i))) return false;
        return true;
    }

    private static void requireDescriptor(IBinder binder, String expected) throws Exception {
        if (binder == null || !expected.equals(binder.getInterfaceDescriptor()))
            throw new UnsupportedOperationException("Unexpected OEM service descriptor");
    }

    private static void requireTransaction(int code) {
        if (code < IBinder.FIRST_CALL_TRANSACTION || code > IBinder.LAST_CALL_TRANSACTION)
            throw new UnsupportedOperationException("OEM transaction could not be resolved");
    }

    private static void checkCancelled(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean() || Thread.currentThread().isInterrupted()) throw new CancellationException("OEM probe stopped");
    }

    private static void cancellableDelay(BooleanSupplier cancelled, long millis) throws InterruptedException {
        long end = SystemClock.elapsedRealtime() + millis;
        while (SystemClock.elapsedRealtime() < end) {
            checkCancelled(cancelled);
            Thread.sleep(Math.min(25, Math.max(1, end - SystemClock.elapsedRealtime())));
        }
    }

    private static String failureStatus(Throwable failure) {
        Throwable cause = OemProcessSupport.rootCause(failure);
        if (cause instanceof CancellationException || cause instanceof InterruptedException) return "CANCELLED";
        if (cause instanceof IllegalArgumentException) return "MALFORMED";
        return OemProcessSupport.status(failure);
    }

    private static String concise(Throwable failure) {
        String text = OemProcessSupport.rootCause(failure).toString();
        return text.length() > 512 ? text.substring(0, 512) : text;
    }
}
