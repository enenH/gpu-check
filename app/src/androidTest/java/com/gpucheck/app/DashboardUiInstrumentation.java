package com.gpucheck.app;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.Intent;
import android.graphics.Bitmap;
import android.os.Bundle;
import android.os.SystemClock;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Synthetic UI-only regression for the native dashboard, including software emulators.
 *
 * This runner never starts MonitorService or a native collector. Fixture data only
 * exercises rendering, navigation, filtering, and stale-state cleanup; it is not
 * evidence that real ARM/KGSL detection works. Screenshot names say "ui-fixture".
 *
 * Build with -PgpuCheckTestRunner=com.gpucheck.app.DashboardUiInstrumentation,
 * then run the generated test APK with am instrument. Set -e screenshots false
 * to disable optional screenshots in externalFilesDir/ui-smoke.
 */
public final class DashboardUiInstrumentation extends Instrumentation {
    private static final Pattern PID_LABEL = Pattern.compile("\\bPID (\\d+)\\b");
    private static final int ROOT_PID = 910041;
    private static final int FIRST_TIE_PID = 910051;
    private static final int SECOND_TIE_PID = 910052;
    private static final int UNKNOWN_PID = 910061;
    private static final int COLLECTOR_PID = 910091;

    private final List<String> screenshots = new ArrayList<>();
    private final List<String> screenshotErrors = new ArrayList<>();
    private Bundle arguments;
    private MainActivity activity;
    private File screenshotDirectory;
    private int assertions;

    @Override public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        this.arguments = arguments == null ? new Bundle() : new Bundle(arguments);
        start();
    }

    @Override public void onStart() {
        super.onStart();
        new Thread(this::runChecks, "dashboard-ui-fixture").start();
    }

    private void runChecks() {
        boolean previousRunning = MonitorService.running;
        String previousReport = MonitorService.latestReport;
        String previousError = MonitorService.lastError;
        Bundle result = new Bundle();
        result.putString("test", "dashboard_ui_synthetic_fixture");
        result.putBoolean("synthetic", true);
        result.putBoolean("nativeCollectorStarted", false);
        int resultCode = Activity.RESULT_CANCELED;
        try {
            check(!previousRunning, "Refusing to replace an active collector with UI fixtures");
            Activity launched = startActivitySync(new Intent(getTargetContext(), MainActivity.class)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK));
            check(launched instanceof MainActivity, "MainActivity did not launch");
            activity = (MainActivity) launched;
            waitForIdleSync();
            onMain(() -> {
                inject(null, false);
                checkCleared(false);
                check(((Integer) field("selectedPage")) == 0, "Dashboard must initially show overview");
                check(((Button[]) field("pageTabs")).length == 3, "Dashboard must expose three workspaces");
                check(((ScrollView) field("workspaceScroll")).isShown(), "Workspace is not visible");
            });
            screenshot("00-idle-ui-fixture.png");

            String fixture = fixture().toString();
            onMain(() -> {
                inject(fixture, true);
                checkFixture(fixture);
                check(text("globalGpuStatus").equals(getTargetContext().getString(R.string.global_gpu_active)),
                        "Measured global GPU state was not rendered");
                check(text("overlayStatus").equals(getTargetContext().getString(R.string.overlay_cheat)),
                        "Synthetic overlay alert was not rendered");
                check(!text("gpuExecRows").isEmpty(), "Synthetic multi-slot evidence was not rendered");
            });
            screenshot("01-overview-ui-fixture.png");

            for (int index : new int[]{1, 2, 0}) {
                final int page = index;
                onMain(() -> {
                    Button[] tabs = (Button[]) field("pageTabs");
                    check(tabs[page].performClick(), "Tab has no click handler: " + page);
                    check(((Integer) field("selectedPage")) == page, "Tab failed to select page " + page);
                    for (int i = 0; i < tabs.length; i++) {
                        check(tabs[i].isSelected() == (i == page), "Tab selection is inconsistent at " + i);
                    }
                    checkFixture(fixture);
                });
                waitForIdleSync();
                onMain(() -> ((ScrollView) field("workspaceScroll")).scrollTo(0, 0));
                if (page == 1) {
                    screenshot("02-processes-ui-fixture.png");
                    onMain(() -> {
                        LinearLayout list = (LinearLayout) field("processList");
                        check(list.getChildAt(0).performClick(), "Process evidence has no click handler");
                    });
                    screenshot("03-process-detail-ui-fixture.png");
                    sendKeyDownUpSync(KeyEvent.KEYCODE_BACK);
                    waitForIdleSync();
                    onMain(() -> checkFixture(fixture));
                }
                if (page == 2) screenshot("04-evidence-ui-fixture.png");
            }

            onMain(() -> {
                verifyCgroupCoverage();
                inject("{not-valid-json: UI fixture", true);
                checkCleared(true);
                check(text("heroStatus").contains("异常"), "Malformed report must show a readable error state");
                check(((TextView) field("errorText")).getVisibility() == View.VISIBLE,
                        "Malformed report error is hidden");
                check(!text("errorText").isEmpty(), "Malformed report has no explanation");
                check(MonitorService.running, "Rendering an invalid report unexpectedly stopped the session");
            });
            screenshot("05-malformed-ui-fixture.png");

            onMain(() -> {
                inject(null, false);
                checkCleared(false);
                check(((TextView) field("errorText")).getVisibility() == View.GONE,
                        "Error survived session cleanup");
                check(text("errorText").isEmpty(), "Error text survived session cleanup");
                check(text("startButton").equals("开始检测"), "Stopped session does not offer start");
            });
            screenshot("06-cleared-ui-fixture.png");
            result.putString("result", "PASS");
            resultCode = Activity.RESULT_OK;
        } catch (Throwable error) {
            result.putString("result", "FAIL");
            result.putString("trace", stackTrace(error));
        } finally {
            try {
                if (activity != null) {
                    onMain(() -> {
                        // Do not let Activity.onStop interpret a fixture as a real service.
                        MonitorService.running = false;
                        MonitorService.latestReport = null;
                        MonitorService.lastError = null;
                        activity.finish();
                    });
                    waitForIdleSync();
                }
            } catch (Throwable cleanupError) {
                resultCode = Activity.RESULT_CANCELED;
                result.putString("result", "FAIL");
                result.putString("cleanupTrace", stackTrace(cleanupError));
            } finally {
                MonitorService.running = previousRunning;
                MonitorService.latestReport = previousReport;
                MonitorService.lastError = previousError;
            }
            result.putInt("assertions", assertions);
            result.putString("screenshots", new JSONArray(screenshots).toString());
            result.putString("screenshotErrors", new JSONArray(screenshotErrors).toString());
            if (screenshotDirectory != null) result.putString("screenshotDirectory", screenshotDirectory.getAbsolutePath());
            finish(resultCode, result);
        }
    }

    private void checkFixture(String raw) throws Exception {
        check(MonitorService.running, "In-page navigation stopped the synthetic session");
        check(raw.equals(MonitorService.latestReport), "In-page navigation replaced the current snapshot");
        JSONObject report = (JSONObject) field("currentReport");
        check(report != null && "dashboard_ui_only".equals(report.optString("fixtureKind")),
                "Displayed report lost its explicit fixture marker");
        check(text("riskCount").equals("1"), "High-risk count does not exclude self/collector/kernel rows");
        check(text("candidateMetric").equals("4"), "Monitored count does not match eligible fixture rows");
        check(text("gpuMetric").equals("1"), "GPU metric includes excluded fixture rows");
        check(text("cpuMetric").equals("72.4%"), "Maximum CPU is not the real value from the visible fixture");
        check(text("startButton").equals("停止检测"), "Active session does not offer stop");
        check(processPids().equals(Arrays.asList(ROOT_PID, FIRST_TIE_PID, SECOND_TIE_PID, UNKNOWN_PID)),
                "CPU ranking/filtering/tie-break/unknown ordering is incorrect: " + processPids());
    }

    private void verifyCgroupCoverage() throws Exception {
        JSONObject report = fixture().put("errors", new JSONArray());
        JSONObject scan = new JSONObject().put("method", CgroupWatchPolicy.METHOD)
                .put("available", true).put("calibrationValid", true).put("complete", false)
                .put("status", "partial").put("missingDetectionAvailable", false)
                .put("freshCoverageThisSample", false);
        report.put("cgroupScan", scan);
        inject(report.toString(), true);
        check(text("sampleStatus").contains(getTargetContext().getString(R.string.cgroup_check_partial)),
                "Partial layouts must explain that missing paths cannot be confirmed");
        check(!text("errorText").contains(getTargetContext().getString(R.string.cgroup_check_unavailable)),
                "A usable partial layout must not be reported as entirely unavailable");

        scan.put("missingDetectionAvailable", true).put("freshCoverageThisSample", true)
                .put("complete", true).put("status", "complete");
        inject(report.toString(), true);
        check(text("sampleStatus").contains(getTargetContext().getString(R.string.cgroup_check_available)),
                "Complete current coverage did not restore the available state");
        check(!text("sampleStatus").contains(getTargetContext().getString(R.string.cgroup_check_partial)),
                "Partial warning survived coverage recovery");

        scan.put("available", false).put("calibrationValid", false)
                .put("missingDetectionAvailable", false).put("freshCoverageThisSample", false);
        inject(report.toString(), true);
        check(text("errorText").contains(getTargetContext().getString(R.string.cgroup_check_unavailable)),
                "No usable layouts must still report unavailable calibration");
        check(!text("sampleStatus").contains(getTargetContext().getString(R.string.cgroup_check_partial)),
                "Stale partial availability survived loss of every layout");
    }

    private void checkCleared(boolean malformed) throws Exception {
        check(field("currentReport") == null, "Previous report object survived reset");
        for (String metric : new String[]{"riskCount", "candidateMetric", "gpuMetric", "cpuMetric"}) {
            check(text(metric).equals("—"), "Stale number survived reset: " + metric + "=" + text(metric));
        }
        check(processPids().isEmpty(), "Old process rows survived reset");
        check(text("gpuExecRows").isEmpty(), "Old multi-slot rows survived reset");
        check(text("overlayNames").isEmpty(), "Old suspicious overlay names survived reset");
        check(!text("overlayStatus").equals(getTargetContext().getString(R.string.overlay_cheat)),
                "Old overlay alert survived reset");
        check(!text("globalGpuStatus").equals(getTargetContext().getString(R.string.global_gpu_active)),
                "Old global GPU activity survived reset");
        check(text("overviewGpuStatus").equals(text("globalGpuStatus")),
                "Overview and evidence GPU state disagree after reset");
        TextView frequency = (TextView) field("gpuFrequencyWarning");
        check(frequency.getVisibility() == View.GONE && frequency.getText().length() == 0,
                "Frequency warning survived reset");
        if (!malformed) check(!MonitorService.running, "Idle UI still has a running session");
    }

    private JSONObject fixture() throws Exception {
        int externalUid = android.os.Process.myUid() + 100000;
        JSONArray processes = new JSONArray()
                .put(process(UNKNOWN_PID, externalUid + 3, "", null, "UNKNOWN"))
                .put(process(SECOND_TIE_PID, externalUid + 2, "fixture.worker.beta", 12.5, "MONITORING"))
                .put(process(android.os.Process.myPid(), 0, "fixture.excluded.app-pid", 990.0, "HIGH").put("gpuActive", true))
                .put(process(ROOT_PID, 0, "fixture.render.worker", 72.4, "HIGH")
                        .put("gpuDeviceOpen", true).put("gpuActive", true))
                .put(process(FIRST_TIE_PID, externalUid + 1, "fixture.worker.alpha", 12.5, "MONITORING"))
                .put(process(910081, android.os.Process.myUid(), "fixture.excluded.same-uid", 980.0, "HIGH").put("gpuActive", true))
                .put(process(COLLECTOR_PID, 0, "fixture.excluded.collector", 970.0, "HIGH").put("gpuActive", true))
                .put(process(910071, 0, "fixture.excluded.kernel", 960.0, "HIGH")
                        .put("threadType", KernelThreadPolicy.KERNEL).put("gpuActive", true));
        JSONObject slot = new JSONObject().put("slot", 23).put("eligible", true)
                .put("measuredSamples", 30).put("completedSamples", 30)
                .put("meanWaitUs", 184.6).put("minWaitUs", 42).put("maxWaitUs", 390)
                .put("observationsPerSecond", 60).put("timedOutSamples", 0).put("unfinishedSamples", 0);
        JSONObject global = new JSONObject().put("supported", true).put("sampled", true).put("active", true)
                .put("execMulti", new JSONObject().put("status", "complete").put("ageMs", 0)
                        .put("candidateCount", 1).put("slots", new JSONArray().put(slot)));
        JSONObject overlay = new JSONObject().put("suspected", true).put("availableRoutes", 1)
                .put("routes", new JSONArray().put(new JSONObject().put("route", "oplus").put("status", "AVAILABLE")))
                .put("suspects", new JSONArray().put(new JSONObject().put("name", "UI_FIXTURE_debug_overlay")
                        .put("reason", "仅用于界面回归的合成名称，不是实际检测结果")));
        return new JSONObject().put("fixtureKind", "dashboard_ui_only").put("synthetic", true)
                .put("schema", 1).put("sampleIndex", 7).put("samplingState", "SAMPLING")
                .put("timestampEpochMs", System.currentTimeMillis()).put("collectorPid", COLLECTOR_PID)
                .put("collectorUid", android.os.Process.myUid()).put("monitoredProcessCount", 4)
                .put("scannedProcesses", 18).put("deniedProcesses", 2).put("processes", processes)
                .put("globalGpu", global).put("overlay", overlay)
                .put("errors", new JSONArray().put("UI fixture · 读取限制示例"));
    }

    private static JSONObject process(int pid, int uid, String name, Double cpu, String risk) throws Exception {
        JSONObject process = new JSONObject().put("pid", pid).put("uid", uid).put("name", name)
                .put("risk", risk).put("threadType", KernelThreadPolicy.USER)
                .put("reason", "UI fixture / 合成界面样本，不是实际检测结果")
                .put("identityVerified", true).put("identityToken", "ui-fixture:" + pid);
        if (cpu != null) process.put("cpuPercent", cpu);
        return process;
    }

    private void inject(String raw, boolean running) throws Exception {
        MonitorService.running = running;
        MonitorService.latestReport = raw;
        MonitorService.lastError = null;
        Field force = MainActivity.class.getDeclaredField("forceRefresh");
        force.setAccessible(true);
        force.setBoolean(activity, true);
        Method render = MainActivity.class.getDeclaredMethod("renderLatest");
        render.setAccessible(true);
        render.invoke(activity);
    }

    private List<Integer> processPids() throws Exception {
        LinearLayout list = (LinearLayout) field("processList");
        List<Integer> pids = new ArrayList<>();
        for (int i = 0; i < list.getChildCount(); i++) {
            Integer pid = findPid(list.getChildAt(i));
            if (pid != null) pids.add(pid);
        }
        return pids;
    }

    private static Integer findPid(View view) {
        if (view instanceof TextView) {
            Matcher matcher = PID_LABEL.matcher(((TextView) view).getText());
            if (matcher.find()) return Integer.parseInt(matcher.group(1));
        }
        if (view instanceof ViewGroup) {
            ViewGroup group = (ViewGroup) view;
            for (int i = 0; i < group.getChildCount(); i++) {
                Integer pid = findPid(group.getChildAt(i));
                if (pid != null) return pid;
            }
        }
        return null;
    }

    private String text(String name) throws Exception {
        return ((TextView) field(name)).getText().toString();
    }

    private Object field(String name) throws Exception {
        Field field = MainActivity.class.getDeclaredField(name);
        field.setAccessible(true);
        return field.get(activity);
    }

    private interface MainAction { void run() throws Exception; }

    private void onMain(MainAction action) throws Exception {
        AtomicReference<Throwable> failure = new AtomicReference<>();
        runOnMainSync(() -> {
            try { action.run(); }
            catch (Throwable error) { failure.set(error); }
        });
        if (failure.get() != null) throw new AssertionError("Dashboard UI assertion on main thread", failure.get());
    }

    private void check(boolean condition, String message) {
        assertions++;
        if (!condition) throw new AssertionError(message);
    }

    private void screenshot(String name) {
        if (!Boolean.parseBoolean(arguments.getString("screenshots", "true"))) return;
        try {
            waitForIdleSync();
            SystemClock.sleep(180);
            if (screenshotDirectory == null) screenshotDirectory = getTargetContext().getExternalFilesDir("ui-smoke");
            if (screenshotDirectory == null || (!screenshotDirectory.isDirectory() && !screenshotDirectory.mkdirs())) {
                throw new IllegalStateException("Screenshot directory is unavailable");
            }
            Bitmap bitmap = getUiAutomation().takeScreenshot();
            if (bitmap == null) throw new IllegalStateException("UiAutomation returned no screenshot");
            try (FileOutputStream output = new FileOutputStream(new File(screenshotDirectory, name))) {
                if (!bitmap.compress(Bitmap.CompressFormat.PNG, 100, output)) {
                    throw new IllegalStateException("PNG compression failed");
                }
                screenshots.add(name);
            } finally { bitmap.recycle(); }
        } catch (Exception error) {
            screenshotErrors.add(name + ": " + error);
        }
    }

    private static String stackTrace(Throwable error) {
        StringWriter text = new StringWriter();
        error.printStackTrace(new PrintWriter(text));
        return text.toString();
    }
}
