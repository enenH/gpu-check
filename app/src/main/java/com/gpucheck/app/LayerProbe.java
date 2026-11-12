package com.gpucheck.app;

import android.os.IBinder;
import android.os.Parcel;
import android.os.SystemClock;
import android.util.Base64;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import java.util.ArrayDeque;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.BooleanSupplier;

/** Both recovered Binder routes are attempted on every ROM. Build properties never gate calls. */
final class LayerProbe {
    static final String DESCRIPTOR = "android.ui.ISurfaceComposer";
    static final int OPLUS_STATUS = 0x6f696665;
    static final int QUERY_BUDGET = 256;
    private static final String ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .#/[]()-_:@+";
    private static final String[] SEEDS = {"[BBQ]", "bbq-wrapper", "SurfaceView", "StatusBar", "NavigationBar", "Wallpaper", "Splash", "Float", "Overlay", "imgui", "dfm_plus", "ESP"};
    private final String packageName;
    private IBinder binder;
    private final ArrayDeque<String> frontier = new ArrayDeque<>();
    private final Set<String> expanded = new LinkedHashSet<>();
    private final Set<String> previousSuspects = new LinkedHashSet<>();
    private int mixedQueryCursor;

    LayerProbe(String packageName) { this.packageName = packageName; }
    LayerProbe(String packageName, IBinder binder) { this.packageName = packageName; this.binder = binder; }
    private static native IBinder lookupSurfaceFlinger();

    private IBinder service() throws Exception {
        if (binder == null || !binder.isBinderAlive()) {
            binder = null;
            try { System.loadLibrary("gpu_layer"); binder = lookupSurfaceFlinger(); }
            catch (LinkageError | SecurityException unavailable) { /* Try the recovered Java lookup as well. */ }
            if (binder == null) {
                // Older Android releases may lack libbinder_ndk. This ordinary reflection call
                // is also present in V.t; hidden-API/service denials remain denials, with no bypass.
                try {
                    Object found = Class.forName("android.os.ServiceManager").getDeclaredMethod("checkService", String.class)
                            .invoke(null, "SurfaceFlinger");
                    if (found instanceof IBinder) binder = (IBinder) found;
                } catch (ReflectiveOperationException | RuntimeException error) {
                    throw new UnsupportedOperationException("SurfaceFlinger NDK/Java lookup unavailable", error);
                }
            }
        }
        if (binder == null) throw new UnsupportedOperationException("SurfaceFlinger service unavailable");
        if (!DESCRIPTOR.equals(binder.getInterfaceDescriptor())) throw new UnsupportedOperationException("Unexpected Binder descriptor");
        return binder;
    }

    static final class Reply {
        final String value;
        final JSONObject evidence;
        Reply(String value, JSONObject evidence) { this.value = value; this.evidence = evidence; }
    }

    private static final class QueryFailure extends Exception {
        final JSONObject evidence;
        QueryFailure(Exception cause, JSONObject evidence) { super(cause); this.evidence = evidence; }
    }

    static Reply query(IBinder binder, int code, String target, boolean string8) throws Exception {
        Parcel data = Parcel.obtain(), reply = Parcel.obtain();
        long start = SystemClock.elapsedRealtimeNanos();
        JSONObject evidence = new JSONObject().put("transaction", code).put("query", target)
                .put("handled", false).put("decoded", false);
        try {
            data.writeInterfaceToken(DESCRIPTOR);
            if (string8) {
                byte[] bytes = LayerReplyDecoder.string8(target);
                Parcel encoded = Parcel.obtain();
                try { encoded.unmarshall(bytes, 0, bytes.length); data.appendFrom(encoded, 0, bytes.length); }
                finally { encoded.recycle(); }
            } else data.writeString(target);
            boolean handled = binder.transact(code, data, reply, 0);
            evidence.put("handled", handled).put("replyBytes", reply.dataSize());
            if (!handled) throw new UnsupportedOperationException("Unhandled transaction " + code);
            int limit = string8 ? LayerReplyDecoder.MAX_BYTES : 65536;
            if (reply.dataSize() < 4 || reply.dataSize() > limit) throw new IllegalArgumentException("Invalid reply size");
            byte[] bytes = reply.marshall();
            evidence.put("replyBase64", Base64.encodeToString(bytes, Base64.NO_WRAP));
            LayerReplyDecoder.Decoded decoded;
            try { decoded = LayerReplyDecoder.decode(bytes, string8); }
            catch (IllegalArgumentException error) {
                evidence.put("decodeError", error.toString());
                reply.setDataPosition(0);
                try { reply.readException(); }
                catch (SecurityException denied) { throw denied; }
                catch (RuntimeException invalidHeader) { evidence.put("exceptionDecodeError", invalidHeader.toString()); }
                throw error;
            }
            evidence.put("decoded", true).put("decodeMode", decoded.mode);
            return new Reply(decoded.value, evidence);
        } catch (Exception error) { throw new QueryFailure(error, evidence); }
        finally { data.recycle(); reply.recycle(); evidence.put("durationNs", SystemClock.elapsedRealtimeNanos() - start); }
    }

    JSONObject oplus(BooleanSupplier cancelled) throws JSONException {
        JSONObject report = empty("oplus", "CHECKING", "");
        LinkedHashMap<String, JSONObject> rows = new LinkedHashMap<>();
        int count = 0;
        long started = SystemClock.elapsedRealtime();
        try {
            IBinder sf = service();
            report.put("descriptor", sf.getInterfaceDescriptor());
            String negative = "gpucheck_absent_" + android.os.Process.myPid() + "_" + SystemClock.elapsedRealtimeNanos();
            Reply control = query(sf, OPLUS_STATUS, negative, false); count++;
            requireEmptyControl(control);
            report.put("negativeControl", control.evidence);
            LinkedHashSet<String> queries = new LinkedHashSet<>(previousSuspects);
            queries.add(packageName);
            java.util.Collections.addAll(queries, SEEDS);
            for (int i = 0; i < ALPHABET.length(); i++) queries.add(ALPHABET.substring(i, i + 1));
            // Single characters can all be masked by earlier normal layers. Reserve a rotating
            // slice for mixed alphanumeric substrings outside hex WM prefixes. This is a generic
            // alphabet, not a target name: 0g..9z then 0G..9Z, revisited independently of the BFS.
            for (int i = 0; i < 96; i++) {
                int index = mixedQueryCursor++ % 400;
                char digit = (char) ('0' + (index % 200) / 20);
                char letter = (char) ((index < 200 ? 'g' : 'G') + index % 20);
                queries.add("" + digit + letter);
            }
            mixedQueryCursor %= 400;
            ArrayDeque<String> refresh = new ArrayDeque<>(queries);
            Set<String> sent = new LinkedHashSet<>();
            while (count < QUERY_BUDGET - 1 && SystemClock.elapsedRealtime() - started < 1500 && !cancelled.getAsBoolean()) {
                String target = !refresh.isEmpty() ? refresh.removeFirst() : frontier.pollFirst();
                if (target == null) break;
                if (!sent.add(target)) continue;
                Reply response = query(sf, OPLUS_STATUS, target, false); count++;
                if (response.value == null || response.value.isEmpty()) continue;
                if (!response.value.contains(target)) throw new IllegalArgumentException("Reply does not contain query");
                rows.putIfAbsent(response.value, row(response.value, "oplus", response.evidence, -1, -1));
                if (target.length() < 4 && expanded.size() < 4096 && frontier.size() < 8192 - ALPHABET.length() && expanded.add(target)) {
                    for (int i = 0; i < ALPHABET.length(); i++) frontier.addLast(target + ALPHABET.charAt(i));
                }
            }
            if (cancelled.getAsBoolean()) return empty("oplus", "CANCELLED", "Session stopped");
            Reply after = query(sf, OPLUS_STATUS, negative + "_end", false); count++;
            requireEmptyControl(after);
            report.put("negativeControlAfter", after.evidence);
            previousSuspects.clear();
            for (JSONObject value : rows.values()) {
                if (value.optBoolean("suspicious") && previousSuspects.size() < 64) previousSuspects.add(value.optString("name"));
            }
            if (frontier.isEmpty()) expanded.clear();
            report.put("status", rows.isEmpty() ? "NO_DATA" : "AVAILABLE").put("available", !rows.isEmpty())
                    .put("rows", new JSONArray(rows.values())).put("remainingQueries", frontier.size())
                    .put("negativeControlValid", true);
        } catch (Exception | LinkageError error) { fail(report, error); }
        return report.put("queryCount", count).put("queryBudget", QUERY_BUDGET)
                .put("durationMs", SystemClock.elapsedRealtime() - started).put("observedAtMs", SystemClock.elapsedRealtime());
    }

    private static void requireEmptyControl(Reply reply) {
        if (reply.value != null && !reply.value.isEmpty()) throw new IllegalArgumentException("Negative control returned a name");
    }

    JSONObject nubia(BooleanSupplier cancelled) throws JSONException {
        JSONObject report = empty("nubia", "CHECKING", "");
        JSONArray attempts = new JSONArray();
        LinkedHashMap<String, JSONObject> rows = new LinkedHashMap<>();
        long start = SystemClock.elapsedRealtime();
        try {
            IBinder sf = service();
            // These are the two recovered list_layer commands, not a transaction-number scan.
            for (int code : new int[]{77, 73}) {
                if (cancelled.getAsBoolean()) return empty("nubia", "CANCELLED", "Session stopped");
                JSONObject attempt = new JSONObject().put("transaction", code).put("query", "list_layer");
                try {
                    Reply reply = query(sf, code, "list_layer", true);
                    List<LayerTextParser.Row> parsed = LayerTextParser.nubiaList(reply.value == null ? "" : reply.value);
                    attempt = reply.evidence.put("status", parsed.isEmpty() ? "NO_DATA" : "AVAILABLE");
                    // Keep the list reply once; rows refer to its transaction rather than duplicate a large Parcel.
                    for (LayerTextParser.Row entry : parsed) rows.putIfAbsent(entry.name, row(entry.name, "nubia",
                            new JSONObject().put("transaction", code).put("query", "list_layer"), -1, -1));
                } catch (Exception error) { fail(attempt, error); }
                attempts.put(attempt);
            }
            String status = "UNSUPPORTED";
            for (int i = 0; i < attempts.length(); i++) {
                String state = attempts.getJSONObject(i).optString("status");
                if (!"UNSUPPORTED".equals(state)) status = state;
            }
            report.put("available", !rows.isEmpty()).put("status", rows.isEmpty() ? status : "AVAILABLE")
                    .put("rows", new JSONArray(rows.values()));
            if (rows.isEmpty()) {
                StringBuilder errors = new StringBuilder();
                for (int i = 0; i < attempts.length(); i++) {
                    JSONObject attempt = attempts.getJSONObject(i);
                    if (errors.length() > 0) errors.append("; ");
                    errors.append(attempt.optInt("transaction")).append(": ").append(attempt.optString("status"));
                }
                report.put("error", errors.toString());
            }
        } catch (Exception | LinkageError error) { fail(report, error); }
        return report.put("attempts", attempts).put("durationMs", SystemClock.elapsedRealtime() - start)
                .put("observedAtMs", SystemClock.elapsedRealtime());
    }

    static JSONObject row(String name, String route, JSONObject evidence, int pid, int uid) throws JSONException {
        LayerNamePolicy.Decision decision = LayerNamePolicy.classify(name);
        return new JSONObject().put("name", name).put("normalizedName", decision.name).put("route", route)
                .put("suspicious", decision.suspicious).put("reason", decision.reason)
                .put("ownerPid", pid < 0 ? JSONObject.NULL : pid).put("ownerUid", uid < 0 ? JSONObject.NULL : uid)
                .put("ownershipSource", pid < 0 ? "unknown" : "same_dump_exact_name")
                .put("evidence", evidence);
    }

    static JSONObject empty(String route, String status, String error) throws JSONException {
        return new JSONObject().put("route", route).put("status", status).put("available", false)
                .put("error", error).put("coverageLimited", true).put("rows", new JSONArray())
                .put("appUid", android.os.Process.myUid()).put("appPid", android.os.Process.myPid());
    }

    static void fail(JSONObject report, Throwable error) throws JSONException {
        if (error instanceof QueryFailure) {
            report.put("queryEvidence", ((QueryFailure) error).evidence);
            error = error.getCause();
        }
        String state = error instanceof SecurityException ? "BLOCKED"
                : error instanceof UnsupportedOperationException || error instanceof LinkageError ? "UNSUPPORTED" : "FAILED";
        report.put("available", false).put("status", state).put("error", error.getClass().getSimpleName() + ": " + error.getMessage())
                .put("rows", new JSONArray());
    }
}
