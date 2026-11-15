package com.gpucheck.app;

import org.json.JSONArray;
import org.json.JSONObject;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/** Synthetic CPU-protocol checks, only packaged in the instrumentation APK. */
final class OplusProcessChecks {
    private static int checks;

    static JSONObject run() throws Exception {
        checks = 0;
        JSONObject parsed = OplusProcessProbe.parseRecord("  com.example.worker=1234=5.5=42  ");
        require(parsed != null && parsed.getInt("pid") == 1234, "Recover PID delimiter");
        require(parsed.getString("name").equals("com.example.worker"), "Trim name without including values");
        require(parsed.getInt("uid") == -1 && parsed.getInt("ppid") == -1, "Do not infer UID or PPID from statistics");
        require(parsed.getJSONObject("stats").getString("raw").contains("5.5"), "Keep raw statistics evidence");
        require(OplusProcessProbe.parseRecord("worker=2147483647=x").getInt("pid") == Integer.MAX_VALUE, "Maximum integer PID");
        for (String value : new String[]{"", "worker", "worker=1234", "=1234=x", "worker=-1=x", "worker=0=x",
                "worker=2147483648=x", "worker=999999999999999999999999=x", "worker=１２３=x", "worker=1.5=x",
                "worker\nspoof=123=x", "worker\u0000=123=x"}) {
            require(OplusProcessProbe.parseRecord(value) == null, "Reject malformed record " + value.replace('\n', '_'));
        }
        require(OplusProcessProbe.parseRecord(null) == null, "Reject null record");
        require(OplusProcessProbe.parseRecord(String.join("", Collections.nCopies(4097, "a"))) == null, "Bound record length");

        JSONObject mixed = new JSONObject();
        OplusProcessProbe.parseRecords(Arrays.asList("one=11=x", "one=11=y", "two=12=x", "other=12=y",
                "two=12=z", "three=13=x", "bad", 99, null), mixed, () -> false);
        require(mixed.getJSONArray("rows").length() == 2, "Deduplicate equal PID/name and discard conflicting PID");
        require(mixed.getInt("conflictingPidCount") == 1, "Expose conflicting PID count");
        require(mixed.getString("status").equals("PARTIAL"), "Mixed malformed response is partial");
        JSONObject invalid = new JSONObject();
        OplusProcessProbe.parseRecords(Arrays.asList("bad", null, 5), invalid, () -> false);
        require(!invalid.getBoolean("available") && invalid.getString("status").equals("INCOMPATIBLE"), "All malformed is unavailable");
        JSONObject empty = new JSONObject();
        OplusProcessProbe.parseRecords(Collections.emptyList(), empty, () -> false);
        require(empty.getBoolean("available") && empty.getString("status").equals("EMPTY"), "Distinguish a valid empty list");
        List<String> many = new ArrayList<>();
        for (int i = 1; i <= OemProcessSupport.MAX_ROWS + 1; i++) many.add("worker=" + i + "=x");
        JSONObject bounded = new JSONObject();
        OplusProcessProbe.parseRecords(many, bounded, () -> false);
        require(bounded.getBoolean("truncated") && bounded.getJSONArray("rows").length() == OemProcessSupport.MAX_ROWS,
                "Bound decoded row count and expose incomplete coverage");

        FakeTracker tracker = new FakeTracker();
        JSONObject observed = new OplusProcessProbe(tracker, 0).collect(new int[]{99}, () -> false);
        require(observed.getBoolean("available") && observed.getJSONArray("rows").length() == 1, "Recovered call sequence produces rows");
        require(tracker.times.size() == 2 && tracker.times.get(0).equals(tracker.times.get(1)), "Both updates use the same initial uptime");
        require(tracker.statsCalls == 1 && observed.getInt("updateCalls") == 2, "Exactly two updates followed by one read");
        require(!observed.getBoolean("uidProvided") && !observed.getBoolean("candidateFilterUsed"), "Expose identity and discovery limits");

        tracker = new FakeTracker();
        tracker.fail = new SecurityException("Synthetic permission denial");
        JSONObject denied = new OplusProcessProbe(tracker, 0).collect(new int[0], () -> false);
        require(!denied.getBoolean("available") && denied.getJSONArray("rows").length() == 0, "Permission denial never returns process evidence");
        require(denied.getString("status").equals(OemProcessSupport.status(tracker.fail)), "Retain denied status");
        require(tracker.statsCalls == 0, "Do not query statistics after an update denial");

        tracker = new FakeTracker();
        tracker.value = "not_a_list";
        JSONObject incompatible = new OplusProcessProbe(tracker, 0).collect(new int[0], () -> false);
        require(!incompatible.getBoolean("available") && incompatible.getJSONArray("rows").length() == 0, "Reject wrong return type");

        tracker = new FakeTracker();
        AtomicInteger cancellationChecks = new AtomicInteger();
        try {
            JSONObject cancelled = new OplusProcessProbe(tracker, 0).collect(new int[0],
                    () -> cancellationChecks.incrementAndGet() > 2);
            require(cancelled.getString("status").equals("CANCELLED") && cancelled.getJSONArray("rows").length() == 0,
                    "Cancellation drops results");
            require(tracker.times.size() == 1 && tracker.statsCalls == 0, "Cancellation stops before second update");
        } finally { Thread.interrupted(); }
        return new JSONObject().put("result", "PASS").put("synthetic", true).put("checks", checks);
    }

    private static final class FakeTracker implements OplusProcessProbe.Tracker {
        final List<Long> times = new ArrayList<>();
        Object value = Arrays.asList("worker=1234=opaque");
        RuntimeException fail;
        int statsCalls;
        @Override public Object update(long lastUpdateTime) {
            times.add(lastUpdateTime);
            if (fail != null) throw fail;
            return 1.0f;
        }
        @Override public Object stats() {
            if (times.size() != 2) throw new AssertionError("Statistics queried before two updates");
            statsCalls++;
            return value;
        }
    }

    private static void require(boolean condition, String reason) {
        if (!condition) throw new AssertionError(reason);
        checks++;
    }
}
