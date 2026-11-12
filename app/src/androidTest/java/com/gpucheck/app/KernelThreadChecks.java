package com.gpucheck.app;

import android.app.Instrumentation;
import android.content.Context;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import org.json.JSONArray;
import org.json.JSONObject;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/** Explicitly synthetic controls for interpretation/UI; real collector checks are separate. */
final class KernelThreadChecks {
    private static final int PID = 900071;
    private static int checked;

    static JSONObject collector(Context context) throws Exception {
        File output = new File(context.getFilesDir(), "kernel-native.jsonl");
        File errors = new File(context.getFilesDir(), "kernel-native-errors.txt");
        Process collector = new ProcessBuilder(new File(context.getApplicationInfo().nativeLibraryDir,
                "libgpu_probe.so").getAbsolutePath(), "--samples", "3", "--interval-ms", "500")
                .redirectOutput(output).redirectError(errors).start();
        try {
            require(collector.waitFor(25, TimeUnit.SECONDS), "headless native collector completes");
            require(collector.exitValue() == 0 && errors.length() == 0, "headless native collector exits cleanly");
            RiskEngine engine = new RiskEngine(20, 3, 500);
            StringBuilder processed = new StringBuilder();
            int frames = 0, excluded = 0;
            for (String line : Files.readAllLines(output.toPath(), StandardCharsets.UTF_8)) {
                JSONObject raw = new JSONObject(line);
                require(raw.getInt("collectorUid") == android.os.Process.myUid() && !raw.getBoolean("root"),
                        "native collector remains ordinary App");
                JSONObject report = engine.process(raw);
                real(report); frames++; excluded += report.getInt("kernelThreadExcludedCount");
                processed.append(report).append('\n');
            }
            Files.write(new File(context.getFilesDir(), "kernel-processed.jsonl").toPath(),
                    processed.toString().getBytes(StandardCharsets.UTF_8));
            require(frames == 3 && excluded > 0, "real frames exclude kernel threads");
            return new JSONObject().put("synthetic", false).put("frames", frames).put("excludedObservations", excluded);
        } finally {
            if (collector.isAlive()) collector.destroyForcibly();
        }
    }

    static JSONObject engine() throws Exception {
        checked = 0;
        JSONObject source = row(1, true), output = evaluate(frame(source));
        require(output.getJSONArray("processes").length() == 0, "kernel removed from processes");
        require(output.getJSONArray("cpuSamples").length() == 0, "kernel removed from CPU samples");
        require(output.getInt("kernelThreadExcludedCount") == 1 && output.getInt("monitoredProcessCount") == 0,
                "kernel excluded from count");
        require(!output.getBoolean("environmentAnomaly"), "actual kernel is not kernel-domain mismatch");
        require(output.getInt("rootProcessCount") == 0 && output.getInt("highRiskCount") == 0,
                "kernel cannot become root risk");
        source = row(1, false).put("uid", 0);
        require(evaluate(frame(source)).getInt("kernelThreadExcludedCount") == 1,
                "kernel excluded even without AVC and with UID 0");

        output = evaluate(frame(row(11, true)));
        require(output.getInt("monitoredProcessCount") == 1 && output.getInt("cpuSampleCount") == 1,
                "mismatched user stays in CPU list");
        require(output.getBoolean("environmentAnomaly") && output.getInt("kernelDomainMismatchCount") == 1,
                "kernel domain plus user result immediately flags environment");
        require(output.getInt("rootProcessCount") == 0 && output.getInt("highRiskCount") == 0,
                "mismatch does not fabricate root or high-risk count");
        require(output.getJSONArray("environmentChecks").getJSONObject(0).getString("type")
                .equals("avc_kernel_userspace"), "distinct evidence type");

        output = evaluate(frame(row(11, false)));
        require(!output.getBoolean("environmentAnomaly") && output.getInt("monitoredProcessCount") == 1,
                "ordinary user without kernel AVC is retained normally");
        for (int error : new int[]{3, 13, 22, 35, 38, 12, 0}) {
            output = evaluate(frame(row(error, true)));
            require(!output.getBoolean("environmentAnomaly") && output.getInt("monitoredProcessCount") == 1
                    && "UNKNOWN".equals(output.getJSONArray("processes").getJSONObject(0).getString("threadType")),
                    "unknown errno stays visible without anomaly: " + error);
        }
        for (int error : new int[]{1, 11}) {
            for (String bad : new String[]{"calibration", "peer", "zeroUnlock", "calibrationSample", "sample",
                    "identity", "verified", "before", "after", "tid", "method", "ret", "stringBoolean"}) {
                source = row(error, true);
                JSONObject input = frame(source);
                JSONObject check = source.getJSONObject("threadTypeCheck");
                switch (bad) {
                    case "calibration": input.getJSONObject("futexPi").put("available", false); break;
                    case "peer": input.getJSONObject("futexPi").getJSONObject("controls")
                            .getJSONObject("peer").put("errno", 1); break;
                    case "zeroUnlock": input.getJSONObject("futexPi").getJSONObject("controls")
                            .getJSONObject("zero").put("unlockRet", -1); break;
                    case "calibrationSample": input.getJSONObject("futexPi").put("sampleIndex", 1); break;
                    case "sample": check.put("sampleIndex", 1); break;
                    case "identity": check.put("identityToken", "previous_pid_identity"); break;
                    case "verified": source.put("identityVerified", false); break;
                    case "before": check.put("pidfdLiveBefore", false); break;
                    case "after": check.put("pidfdLiveAfter", false); break;
                    case "tid": check.put("tid", PID + 1); break;
                    case "method": check.put("method", "unrelated_syscall"); break;
                    case "ret": check.getJSONObject("result").put("ret", 0); break;
                    case "stringBoolean": check.put("calibrated", "true"); break;
                    default: throw new AssertionError(bad);
                }
                output = evaluate(input);
                require(!output.getBoolean("environmentAnomaly") && output.getInt("kernelThreadExcludedCount") == 0
                        && output.getInt("monitoredProcessCount") == 1, "invalid evidence rejected: " + error + " " + bad);
            }
        }
        for (String bad : new String[]{"expired", "identity", "pid", "domain", "substring", "malformed", "missingAge"}) {
            source = row(11, true);
            switch (bad) {
                case "expired": source.put("avcEvidenceAgeMs", AvcEvidence.MAX_AGE_MS + 1); break;
                case "identity": source.put("avcIdentityToken", "old"); break;
                case "pid": source.put("avcTargetPid", PID + 1); break;
                case "domain": source.put("avcTargetDomain", "su"); break;
                case "substring": source.put("avcTargetContext", "u:r:kernel_helper:s0"); break;
                case "malformed": source.put("avcTargetContext", "u:r:kernel:s0 injected"); break;
                case "missingAge": source.remove("avcEvidenceAgeMs"); break;
                default: throw new AssertionError(bad);
            }
            require(!evaluate(frame(source)).getBoolean("environmentAnomaly"), "invalid AVC rejected: " + bad);
        }
        JSONObject input = frame(row(11, false)).put("environmentAnomaly", true)
                .put("environmentChecks", new JSONArray().put(new JSONObject().put("status", "ANOMALY").put("pid", 900072)));
        output = evaluate(input);
        require(output.getBoolean("environmentAnomaly") && output.getJSONArray("environmentChecks").length() == 1,
                "existing pidfd/proc environment check preserved");
        input = frame(row(1, true)); input.put("processes", new JSONArray());
        require(evaluate(input).getInt("monitoredProcessCount") == 0, "CPU-only merge cannot resurrect kernel");
        input = frame(row(11, true)); input.put("processes", new JSONArray());
        require(evaluate(input).getInt("kernelDomainMismatchCount") == 1, "CPU-only merge retains fresh mismatch evidence");
        RiskEngine engine = new RiskEngine(20, 3, 2000);
        engine.process(frame(row(11, true)));
        output = engine.process(frame(row(11, false)).put("elapsedMs", 4000));
        require(!output.getBoolean("environmentAnomaly"), "removed AVC clears prior mismatch");
        input = frame(row(1, true));
        input.put("processes", new JSONArray().put(row(1, true)).put(row(11, true)));
        require(evaluate(input).getInt("kernelDomainMismatchCount") == 0, "duplicate identity cannot flag mismatch");
        return new JSONObject().put("synthetic", true).put("checks", checked);
    }

    static void ui(Instrumentation instrumentation, MainActivity activity) throws Exception {
        AtomicReference<Throwable> failure = new AtomicReference<>();
        instrumentation.runOnMainSync(() -> {
            try {
                JSONObject mismatch = evaluate(frame(row(11, true)));
                bind(activity, mismatch);
                View card = (View) field(activity, "environmentCard");
                require(card.getVisibility() == View.VISIBLE, "environment card visible for mismatch");
                require(((TextView) field(activity, "environmentSummary")).getText().toString().contains("用户态线程"),
                        "environment summary explains AVC mismatch");
                int red = (Integer) field(activity, "RED");
                require(hasRedText(card, "环境异常", red), "environment title is red");
                View list = (View) field(activity, "processList");
                require(hasRedText(list, "环境异常", red), "process row anomaly is red");
                require(hasRedText(list, "AVC 域", red), "conflicting AVC is red");
                bind(activity, evaluate(frame(row(11, false))));
                require(((View) field(activity, "environmentCard")).getVisibility() == View.GONE,
                        "anomaly card clears on recovery");
                require(!hasRedText((View) field(activity, "processList"), "环境异常", red),
                        "recycled row loses anomaly text/color");
                JSONObject kernel = evaluate(frame(row(1, true)));
                bind(activity, kernel);
                require(MainActivity.cpuLeaders(kernel.getJSONArray("processes"), -1).isEmpty(),
                        "kernel absent from UI leaders");
            } catch (Throwable error) { failure.set(error); }
            finally {
                try { bind(activity, null); } catch (Throwable error) { failure.set(error); }
            }
        });
        if (failure.get() != null) throw new AssertionError("Kernel thread UI checks", failure.get());
    }

    static void real(JSONObject report) throws Exception {
        require(KernelThreadPolicy.calibrated(report), "real App futex controls must pass");
        JSONArray rows = report.getJSONArray("processes"), excluded = report.getJSONArray("excludedKernelThreads");
        require(excluded.length() == report.getInt("kernelThreadExcludedCount"), "real excluded count");
        for (int i = 0; i < rows.length(); i++) {
            JSONObject row = rows.getJSONObject(i);
            require(!KernelThreadPolicy.KERNEL.equals(KernelThreadPolicy.classify(row, report)),
                    "real kernel not retained in process list");
            require(row.optBoolean("kernelDomainMismatch") == KernelThreadPolicy.kernelDomainMismatch(row,
                    KernelThreadPolicy.classify(row, report)), "real mismatch bound to evidence");
        }
        for (int i = 0; i < excluded.length(); i++) {
            JSONObject kernel = excluded.getJSONObject(i);
            require(KernelThreadPolicy.KERNEL.equals(KernelThreadPolicy.classify(new JSONObject(kernel.toString())
                    .put("identityVerified", true), report)), "real excluded row has calibrated kernel evidence");
            JSONArray samples = report.getJSONArray("cpuSamples");
            for (int j = 0; j < samples.length(); j++) require(samples.getJSONObject(j).getInt("pid") != kernel.getInt("pid"),
                    "real kernel not retained in CPU samples");
        }
    }

    private static JSONObject outcome(int ret, int error) throws Exception {
        return new JSONObject().put("ret", ret).put("errno", error);
    }
    private static JSONObject row(int error, boolean kernelAvc) throws Exception {
        JSONObject row = new JSONObject().put("pid", PID).put("uid", -1).put("name", "synthetic kernel-domain control")
                .put("identityToken", "held:test").put("identityVerified", true).put("cpuPercent", 99)
                .put("threadTypeCheck", new JSONObject().put("method", KernelThreadPolicy.METHOD).put("tid", PID)
                        .put("sampleIndex", 0).put("identityToken", "held:test").put("calibrated", true)
                        .put("pidfdLiveBefore", true).put("pidfdLiveAfter", true).put("result", outcome(-1, error)));
        if (kernelAvc) row.put("avcTargetContext", "u:r:kernel:s0").put("avcTargetDomain", "kernel")
                .put("avcIdentityToken", "held:test").put("avcTargetPid", PID).put("avcEvidenceAgeMs", 0);
        return row;
    }
    private static JSONObject frame(JSONObject row) throws Exception {
        return new JSONObject().put("sampleIndex", 0).put("elapsedMs", 2000).put("collectorPid", 900099)
                .put("processes", new JSONArray().put(row)).put("cpuSamples", new JSONArray().put(row))
                .put("environmentAnomaly", false).put("environmentChecks", new JSONArray())
                .put("futexPi", new JSONObject().put("method", KernelThreadPolicy.METHOD).put("available", true)
                        .put("private", true).put("sampleIndex", 0).put("controls", new JSONObject()
                                .put("zero", outcome(0, 0).put("unlockRet", 0).put("unlockErrno", 0))
                                .put("self", outcome(-1, 35)).put("peer", outcome(-1, 11)).put("missing", outcome(-1, 3))));
    }
    private static JSONObject evaluate(JSONObject input) throws Exception {
        return new RiskEngine(20, 3, 2000).process(input);
    }
    private static Object field(Object owner, String name) throws Exception {
        Field field = owner.getClass().getDeclaredField(name); field.setAccessible(true); return field.get(owner);
    }
    private static void bind(MainActivity activity, JSONObject report) throws Exception {
        Field field = MainActivity.class.getDeclaredField("currentReport"); field.setAccessible(true); field.set(activity, report);
        for (String name : new String[]{"updateEnvironmentStatus", "renderProcesses"}) {
            Method method = MainActivity.class.getDeclaredMethod(name); method.setAccessible(true); method.invoke(activity);
        }
    }
    private static boolean hasRedText(View view, String text, int color) {
        if (view.getVisibility() != View.VISIBLE) return false;
        if (view instanceof TextView && ((TextView) view).getText().toString().contains(text)
                && ((TextView) view).getCurrentTextColor() == color) return true;
        if (view instanceof ViewGroup) for (int i = 0; i < ((ViewGroup) view).getChildCount(); i++) {
            if (hasRedText(((ViewGroup) view).getChildAt(i), text, color)) return true;
        }
        return false;
    }
    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checked++;
    }
}
