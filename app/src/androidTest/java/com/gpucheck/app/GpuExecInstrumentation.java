package com.gpucheck.app;

import android.app.Activity;
import android.app.Instrumentation;
import android.os.Bundle;
import android.os.SystemClock;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/** Actual App UID, real KGSL mapping and two independent EGL contexts; no supplied external PID. */
public final class GpuExecInstrumentation extends Instrumentation {
    private final JSONObject evidence = new JSONObject();
    @Override public void onCreate(Bundle args) { super.onCreate(args); start(); }
    @Override public void onStart() {
        Bundle result = new Bundle();
        int code = Activity.RESULT_CANCELED;
        try {
            verify(getTargetContext(), evidence); evidence.put("result", "PASS"); result.putString("result", "PASS"); code = Activity.RESULT_OK;
        } catch (Throwable error) {
            result.putString("result", "FAIL"); result.putString("error", android.util.Log.getStackTraceString(error));
            try { evidence.put("result", "FAIL").put("error", android.util.Log.getStackTraceString(error)); } catch (Exception ignored) { }
        } finally {
            try {
                File output = new File(getTargetContext().getFilesDir(), "gpuexec-device.json");
                Files.write(output.toPath(), evidence.toString(2).getBytes(StandardCharsets.UTF_8));
                result.putString("evidence", output.getAbsolutePath());
            } catch (Exception error) { result.putString("evidenceError", error.toString()); code = Activity.RESULT_CANCELED; }
            finish(code, result);
        }
    }
    static void verify(android.content.Context context, JSONObject evidence) throws Exception {
        check(android.os.Process.myUid() >= 10000, "not ordinary App UID");
        String domain = new String(Files.readAllBytes(new File("/proc/self/attr/current").toPath()), StandardCharsets.UTF_8).trim();
        check(domain.contains("untrusted_app"), "test outside ordinary App SELinux domain: " + domain);
        evidence.put("uid", android.os.Process.myUid()).put("pid", android.os.Process.myPid()).put("selinux", domain)
                .put("syntheticGpuData", false).put("fixture", "two_test_only_app_owned_egl_contexts");
        List<SelfGpuInstrumentation.EglWorkload> loads = new ArrayList<>();
        try {
            for (int i = 0; i < 2; i++) {
                SelfGpuInstrumentation.EglWorkload load = new SelfGpuInstrumentation.EglWorkload();
                loads.add(load); load.start();
                check(load.ready.await(5, TimeUnit.SECONDS) && load.error == null, "EGL fixture failed");
            }
            SystemClock.sleep(1200);
            File binary = new File(context.getApplicationInfo().nativeLibraryDir, "libgpu_probe.so");
            Process process = new ProcessBuilder(binary.getAbsolutePath(), "--capabilities").start();
            JSONObject raw;
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                String line = reader.readLine(); check(line != null, "collector empty"); raw = new JSONObject(line);
                check(process.waitFor(10, TimeUnit.SECONDS) && process.exitValue() == 0, "collector failed");
            } finally { process.destroy(); }
            JSONObject gpu = raw.getJSONObject("globalGpu");
            check(gpu.optBoolean("supported"), "KGSL mapping unsupported");
            int count = gpu.getJSONArray("slotDeltas").length();
            JSONObject owners = SelfGpuSlots.inspect(1, count - 7);
            check(owners.optBoolean("complete"), "owner query incomplete: " + owners);
            JSONArray owned = owners.getJSONArray("ownershipEvidence");
            List<Integer> chosen = new ArrayList<>();
            for (int i = 0; i < owned.length(); i++) {
                JSONObject owner = owned.getJSONObject(i);
                if (owner.getInt("slot") < 256 && owner.getLong("timestamp") >= 100) chosen.add(owner.getInt("slot"));
            }
            check(chosen.size() >= 2, "two real EGL slots were not found");
            int[] slots = {chosen.get(0), chosen.get(1)};
            evidence.put("slotCount", count).put("owners", owners).put("explicitFixtureSlots", new JSONArray(slots));
            JSONArray runs = new JSONArray();
            evidence.put("realRuns", runs);
            try (GpuExecSampler sampler = new GpuExecSampler()) {
                for (int round = 0; round < 3; round++) {
                    long start = SystemClock.elapsedRealtime();
                    JSONObject measured = sampler.measure(slots, 30, 500, count);
                    runs.put(measured);
                    check(SystemClock.elapsedRealtime() - start < 1500, "short window exceeded budget");
                    check("complete".equals(measured.optString("status")), "native sampling failed: " + measured);
                    check(measured.getInt("workerCount") == 2 && measured.getInt("uid") == android.os.Process.myUid(), "wrong workers or UID");
                    JSONArray rows = measured.getJSONArray("slots");
                    long latestStart = 0, earliestEnd = Long.MAX_VALUE;
                    for (int i = 0; i < rows.length(); i++) {
                        JSONObject row = rows.getJSONObject(i); validateStatistics(row);
                        check(row.optBoolean("valid") && row.getInt("completedSamples") >= 5, "real slot did not complete observations: " + row);
                        latestStart = Math.max(latestStart, row.getLong("startedMonotonicNs"));
                        earliestEnd = Math.min(earliestEnd, row.getLong("finishedMonotonicNs"));
                    }
                    check(latestStart < earliestEnd, "slot workers did not overlap");
                }
                evidence.put("realRuns", runs);
                int[] sixteen = new int[16]; for (int i = 0; i < 16; i++) sixteen[i] = i + 1;
                JSONObject full = sampler.measure(sixteen, 30, 500, count);
                check(full.optInt("workerCount") == 16 && full.getJSONArray("slots").length() == 16, "16-slot capacity failed");
                check(full.getLong("finishedMonotonicNs") - full.getLong("startedMonotonicNs") < 1500000000L, "16-slot sampling was serial");
                evidence.put("sixteenSlotRun", full);
                int[][] bad = {new int[0], {0}, {-1}, {256}, {slots[0], slots[0]}, new int[17]};
                for (int[] input : bad) check("unavailable".equals(sampler.measure(input, 30, 500, count).optString("status")), "invalid slot accepted");
                check("unavailable".equals(sampler.measure(slots, 0, 500, count).optString("status")), "zero samples accepted");
                check("unavailable".equals(sampler.measure(slots, 1025, 500, count).optString("status")), "sample overflow accepted");
                check("unavailable".equals(sampler.measure(slots, 30, 99, count).optString("status")), "small window accepted");
                check("unavailable".equals(sampler.measure(slots, 30, 10001, count).optString("status")), "large window accepted");
                check("layout_mismatch".equals(sampler.measure(slots, 30, 500, count + 1).optString("reason")), "layout mismatch accepted");
                evidence.put("argumentAndLayoutRejections", 11);
            }
            try (GpuExecSampler sampler = new GpuExecSampler()) {
                AtomicReference<JSONObject> returned = new AtomicReference<>();
                AtomicReference<Throwable> failed = new AtomicReference<>();
                Thread caller = new Thread(() -> {
                    try { returned.set(sampler.measure(slots, 1024, 10000, count)); } catch (Throwable error) { failed.set(error); }
                });
                caller.start(); SystemClock.sleep(120);
                long stoppedAt = SystemClock.elapsedRealtime(); sampler.close(); caller.join(1000);
                check(!caller.isAlive() && failed.get() == null && returned.get() != null, "cancellation failed");
                check("cancelled".equals(returned.get().optString("status")), "cancelled sampling reported success");
                evidence.put("cancellationMs", SystemClock.elapsedRealtime() - stoppedAt).put("cancelledRun", returned.get());
            }
            try (GpuExecSampler sampler = new GpuExecSampler()) {
                JSONObject restarted = sampler.measure(slots, 5, 500, count);
                check("complete".equals(restarted.optString("status")), "new session failed after cancellation");
                evidence.put("restartedRun", restarted);
            }
            for (File task : new File("/proc/self/task").listFiles()) {
                try {
                    String name = new String(Files.readAllBytes(new File(task, "comm").toPath()), StandardCharsets.UTF_8).trim();
                    check(!"gpu-exec-slot".equals(name), "native worker remained after join");
                } catch (java.io.IOException ignored) { /* thread exited during enumeration */ }
            }
            evidence.put("nativeWorkersCleaned", true);
        } finally {
            for (SelfGpuInstrumentation.EglWorkload load : loads) load.running = false;
            for (SelfGpuInstrumentation.EglWorkload load : loads) { load.join(5000); check(!load.isAlive(), "EGL fixture leaked"); }
        }
    }
    static void validateStatistics(JSONObject row) throws Exception {
        JSONArray values = row.getJSONArray("durationsUs"), done = row.getJSONArray("sampleCompleted");
        check(values.length() == row.getInt("measuredSamples") && done.length() == values.length(), "sample array mismatch");
        int positive = 0, completed = 0, timedOut = 0, min = Integer.MAX_VALUE, max = 0;
        long sum = 0;
        for (int i = 0; i < values.length(); i++) {
            int us = values.getInt(i); check(us >= 0 && us < 50000, "invalid duration");
            if (done.getBoolean(i)) {
                completed++;
                if (us > 0) { positive++; sum += us; min = Math.min(min, us); max = Math.max(max, us); }
            } else { check(us == 0, "timeout should carry zero duration"); timedOut++; }
        }
        check(completed == row.getInt("completedSamples") && positive == row.getInt("nonzeroSamples")
                && timedOut == row.getInt("timedOutSamples"), "sample totals mismatch");
        if (positive > 0) check(Math.abs(row.getDouble("meanWaitUs") - (double) sum / positive) <= 0.001
                && min == row.getInt("minWaitUs") && max == row.getInt("maxWaitUs"), "statistics mismatch");
        else check(row.isNull("meanWaitUs") && row.isNull("minWaitUs") && row.isNull("maxWaitUs"), "missing duration fabricated");
    }
    private static void check(boolean condition, String message) { if (!condition) throw new AssertionError(message); }
}
