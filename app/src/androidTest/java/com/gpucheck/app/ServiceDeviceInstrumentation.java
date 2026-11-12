package com.gpucheck.app;

import android.accessibilityservice.AccessibilityService;
import android.app.Activity;
import android.app.Instrumentation;
import android.app.KeyguardManager;
import android.content.Intent;
import android.graphics.Bitmap;
import android.os.Bundle;
import android.os.PowerManager;
import android.os.SystemClock;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Exercises the real Activity -> Service -> native/AVC/self-GPU -> RiskEngine -> UI pipeline. */
public final class ServiceDeviceInstrumentation extends Instrumentation {
    private static final Pattern PID_LABEL = Pattern.compile("^PID (\\d+)\\b");
    private final JSONObject summary = new JSONObject();
    private final JSONArray frames = new JSONArray();
    private final JSONArray issues = new JSONArray();
    private final Set<String> issueKeys = new HashSet<>();
    private final Set<String> recorded = new HashSet<>();
    private Bundle arguments;
    private MainActivity activity;
    private BufferedWriter reports;
    private BufferedWriter uiReports;
    private File files;
    private boolean captureOnly;
    private boolean startingObserved;
    private boolean startingUiObserved;
    private int durationSeconds;
    private int expectedTargetPid;
    private int expectedTargetObservations;
    private int nonemptyUiSnapshots;
    private int maximumUiCandidates;
    private String installedVersion;
    private View overlayFixture;
    private String overlayFixtureName;
    private long fixtureHitAt, fixtureRemovedAt;
    private boolean fixtureGoneObserved;

    @Override public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        this.arguments = arguments == null ? new Bundle() : new Bundle(arguments);
        start();
    }

    @Override public void onStart() {
        Bundle result = new Bundle();
        int resultCode = Activity.RESULT_CANCELED;
        try {
            captureOnly = Boolean.parseBoolean(arguments.getString("capture_only", "false"));
            durationSeconds = integerArgument("duration_seconds", 25, 5, 180);
            expectedTargetPid = integerArgument("expected_target_pid", 0, 0, Integer.MAX_VALUE);
            files = getTargetContext().getFilesDir();
            installedVersion = getTargetContext().getPackageManager()
                    .getPackageInfo(getTargetContext().getPackageName(), 0).versionName;
            summary.put("test", "real_activity_service_pipeline").put("synthetic", false)
                    .put("captureOnly", captureOnly).put("durationSeconds", durationSeconds)
                    .put("expectedTargetPid", expectedTargetPid).put("appUid", android.os.Process.myUid())
                    .put("appPid", android.os.Process.myPid()).put("installedVersion", installedVersion)
                    .put("startedEpochMs", System.currentTimeMillis());
            summary.put("appSelinux", new String(Files.readAllBytes(new File("/proc/self/attr/current").toPath()), StandardCharsets.UTF_8)
                    .replace("\u0000", "").trim());
            String ownStatus = new String(Files.readAllBytes(new File("/proc/self/status").toPath()), StandardCharsets.UTF_8);
            for (String statusLine : ownStatus.split("\n")) {
                if (statusLine.startsWith("CapEff:")) summary.put("appCapEff", statusLine.substring(7).trim());
            }
            check(android.os.Process.myUid() >= 10000, "Instrumentation must run as an ordinary App UID");
            summary.put("kernelThreadRegression", KernelThreadChecks.engine());
            if (Boolean.parseBoolean(arguments.getString("kernel_checks_only", "false"))) {
                summary.put("test", "kernel_thread_headless").put("kernelThreadCollector", KernelThreadChecks.collector(getTargetContext()));
                summary.put("result", "PASS"); result.putString("result", "PASS");
                resultCode = Activity.RESULT_OK;
                return;
            }
            check(getTargetContext().getSystemService(PowerManager.class).isInteractive(), "Screen is not awake");
            check(!getTargetContext().getSystemService(KeyguardManager.class).isKeyguardLocked(), "Screen is locked");
            summary.put("overlayProtocolRegression", OverlayBinderChecks.run());
            reports = Files.newBufferedWriter(new File(files, "service-real.jsonl").toPath(), StandardCharsets.UTF_8);
            uiReports = Files.newBufferedWriter(new File(files, "service-ui.jsonl").toPath(), StandardCharsets.UTF_8);
            Activity launched = startActivitySync(new Intent(getTargetContext(), MainActivity.class)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK));
            check(launched instanceof MainActivity, "MainActivity did not launch");
            activity = (MainActivity) launched;
            waitForIdleSync();
            check(!MonitorService.running && MonitorService.latestReport == null, "Unexpected retained session before start");
            KernelThreadChecks.ui(this, activity);
            if (Boolean.parseBoolean(arguments.getString("overlay_fixture", "false"))) createOverlayFixture();
            clickStartStop();
            JSONObject first = awaitSamples("first", 2, 20000);
            int firstCollector = first.getInt("collectorPid");
            long firstSession = first.getLong("sessionStartedAt");
            summary.put("firstCollectorPid", firstCollector).put("firstSessionStartedAt", firstSession);
            Bundle ready = new Bundle();
            ready.putString("stage", "MONITOR_READY");
            ready.putInt("collectorPid", firstCollector);
            ready.putInt("appUid", android.os.Process.myUid());
            ready.putInt("sampleCount", recorded.size());
            ready.putInt("rootProcessCount", first.optInt("rootProcessCount"));
            ready.putInt("cgroupAnomalyCount", first.optInt("cgroupAnomalyCount"));
            sendStatus(0, ready);
            long deadline = SystemClock.elapsedRealtime() + durationSeconds * 1000L;
            while (SystemClock.elapsedRealtime() < deadline) {
                check(MonitorService.running, "Service stopped during real capture: " + MonitorService.lastError);
                recordLatest("first");
                advanceOverlayFixture();
                SystemClock.sleep(50);
            }
            recordLatest("first");
            if (overlayFixtureName != null) {
                check(fixtureHitAt > 0, "Real ZUI collection did not find the app-owned fixture window");
                check(fixtureGoneObserved, "A fresh ZUI collection did not confirm fixture disappearance");
                summary.put("overlayFixtureLifecyclePassed", true);
            }
            screenshot("service-ui-active.png");
            summary.put("activeUi", captureUi());
            onMain(() -> check(((View) field("overlayCard")).performClick(), "Overlay evidence card did not open"));
            waitForIdleSync();
            long dialogDeadline = SystemClock.elapsedRealtime() + 3000;
            boolean dialogVisible = false;
            while (SystemClock.elapsedRealtime() < dialogDeadline) {
                android.view.accessibility.AccessibilityNodeInfo root = getUiAutomation().getRootInActiveWindow();
                if (root != null && !root.findAccessibilityNodeInfosByText("悬浮窗检测依据").isEmpty()) {
                    dialogVisible = true;
                    break;
                }
                SystemClock.sleep(50);
            }
            check(dialogVisible, "Overlay evidence dialog is not visible");
            SystemClock.sleep(250); // Let the dialog's first rendered frame reach screenshot capture.
            screenshot("overlay-details.png");
            check(getUiAutomation().performGlobalAction(AccessibilityService.GLOBAL_ACTION_BACK), "Cannot close overlay details");
            waitForIdleSync();
            check(MonitorService.running, "Opening overlay details stopped collection");
            if (expectedTargetPid > 0) {
                validation(expectedTargetObservations > 0, "expected_target_not_observed",
                        "External validation PID did not appear in the real monitored list");
            }
            clickStartStop();
            awaitStopped(firstCollector, "buttonStop");
            summary.put("stoppedUi", captureUi());
            screenshot("service-ui-stopped.png");
            SystemClock.sleep(900);
            clickStartStop();
            JSONObject second = awaitSamples("restart", 2, 20000);
            int secondCollector = second.getInt("collectorPid");
            validation(secondCollector != firstCollector && second.getLong("sessionStartedAt") > firstSession,
                    "old_session_reused", "Restart reused the old collector/session");
            summary.put("secondCollectorPid", secondCollector)
                    .put("secondSessionStartedAt", second.getLong("sessionStartedAt"));
            check(getUiAutomation().performGlobalAction(AccessibilityService.GLOBAL_ACTION_HOME), "HOME action failed");
            awaitStopped(secondCollector, "backgroundStop");
            screenshot("service-ui-background.png");
            summary.put("result", captureOnly ? "CAPTURED" : "PASS");
            result.putString("result", captureOnly ? "CAPTURED" : "PASS");
            resultCode = Activity.RESULT_OK;
        } catch (Throwable error) {
            String detail = android.util.Log.getStackTraceString(error);
            try { summary.put("result", "FAIL").put("error", detail); } catch (Exception ignored) { }
            result.putString("result", "FAIL");
            result.putString("error", detail);
        } finally {
            try { removeOverlayFixture(); } catch (Exception ignored) { }
            if (MonitorService.running) {
                try { getTargetContext().stopService(new Intent(getTargetContext(), MonitorService.class)); }
                catch (Exception ignored) { }
            }
            try { if (reports != null) reports.close(); } catch (Exception ignored) { }
            try { if (uiReports != null) uiReports.close(); } catch (Exception ignored) { }
            try {
                summary.put("frames", frames).put("validationIssues", issues)
                        .put("realSamples", recorded.size()).put("expectedTargetObservations", expectedTargetObservations)
                        .put("startingSnapshotObserved", startingObserved).put("startingUiObserved", startingUiObserved)
                        .put("nonemptyUiSnapshots", nonemptyUiSnapshots).put("maximumUiCandidates", maximumUiCandidates)
                        .put("finishedEpochMs", System.currentTimeMillis());
                if (files != null) Files.write(new File(files, "service-device-summary.json").toPath(),
                        summary.toString(2).getBytes(StandardCharsets.UTF_8));
            } catch (Exception error) {
                result.putString("evidenceError", error.toString());
                resultCode = Activity.RESULT_CANCELED;
            }
            result.putInt("realSamples", recorded.size());
            result.putInt("validationIssues", issues.length());
            result.putString("summary", files == null ? "unavailable" : new File(files, "service-device-summary.json").getAbsolutePath());
            finish(resultCode, result);
        }
    }

    private int integerArgument(String name, int fallback, int minimum, int maximum) {
        String raw = arguments.getString(name);
        if (raw == null) return fallback;
        int value = Integer.parseInt(raw);
        if (value < minimum || value > maximum) throw new IllegalArgumentException(name + " out of range");
        return value;
    }

    private void clickStartStop() throws Exception {
        long deadline = SystemClock.elapsedRealtime() + 4000;
        while (SystemClock.elapsedRealtime() < deadline) {
            AtomicReference<Boolean> clicked = new AtomicReference<>(false);
            onMain(() -> {
                Button button = (Button) field("startButton");
                if (button.isEnabled()) clicked.set(button.performClick());
            });
            if (clicked.get()) return;
            SystemClock.sleep(50);
        }
        throw new AssertionError("Start/stop button did not accept a real click");
    }

    private JSONObject awaitSamples(String phase, int needed, long timeoutMs) throws Exception {
        int previous = recorded.size();
        JSONObject last = null;
        long deadline = SystemClock.elapsedRealtime() + timeoutMs;
        while (SystemClock.elapsedRealtime() < deadline) {
            JSONObject found = recordLatest(phase);
            if (found != null) last = found;
            if (recorded.size() - previous >= needed && last != null) return last;
            if (!MonitorService.running && MonitorService.lastError != null) {
                throw new AssertionError("Service startup failed: " + MonitorService.lastError);
            }
            SystemClock.sleep(10);
        }
        throw new AssertionError("Timed out awaiting real Service samples in " + phase);
    }

    private JSONObject recordLatest(String phase) throws Exception {
        String raw = MonitorService.latestReport;
        if (raw == null || raw.isEmpty()) return null;
        JSONObject report = new JSONObject(raw);
        if (!report.has("sampleIndex")) {
            if (!startingObserved) {
                startingObserved = true;
                summary.put("startingReport", report);
                JSONObject ui = captureUi();
                summary.put("startingUi", ui);
                if (ui.optBoolean("renderedReportPresent") && !ui.optBoolean("hasRealSample")) {
                    startingUiObserved = true;
                    validation(ui.optString("heroStatus").contains("基线")
                                    && !ui.optString("visibleErrors").contains("cgroup")
                                    && !ui.optString("listText").contains("尚未发现需要监听"),
                            "starting_ui_misclassified", "Initial baseline was rendered as unavailable or no candidates");
                }
            }
            return null;
        }
        String key = report.getInt("collectorPid") + ":" + report.getLong("sampleIndex");
        if (!recorded.add(key)) return null;
        reports.write(raw);
        reports.newLine();
        reports.flush();
        check(!report.optBoolean("root") && report.getInt("collectorUid") == android.os.Process.myUid(),
                "Real collector did not retain the ordinary App UID");
        check("direct_logdr_seqpacket_self_uid".equals(report.optString("avcTransport")), "Real AVC enrichment was bypassed");
        JSONObject global = report.optJSONObject("globalGpu");
        JSONObject ownSlots = global == null ? null : global.optJSONObject("selfGpuSlots");
        check(ownSlots != null && ownSlots.optInt("pid") == android.os.Process.myPid()
                && ownSlots.optInt("uid") == android.os.Process.myUid(), "Real App GPU-owner enrichment was bypassed");
        validation(installedVersion.equals(report.optString("appVersion")), "wrong_report_version",
                "Published appVersion differs from the installed package");
        validation("SAMPLING".equals(report.optString("samplingState")), "missing_sampling_state",
                "Real report does not state SAMPLING");
        JSONArray rows = report.getJSONArray("processes");
        JSONObject overlay = report.getJSONObject("overlay");
        observeOverlayFixture(overlay);
        validation(!overlay.optBoolean("brandGateUsed") && overlay.getJSONArray("routes").length() == 3,
                "overlay_routes_missing", "Every ROM route must be represented without a brand gate");
        for (int i = 0; i < overlay.getJSONArray("routes").length(); i++) {
            JSONObject route = overlay.getJSONArray("routes").getJSONObject(i);
            validation(route.getInt("appUid") == android.os.Process.myUid(), "overlay_uid", "Layer query changed UID");
            validation(!"STALE".equals(route.optString("status")) || "AVAILABLE".equals(route.optString("previousStatus")),
                    "overlay_unavailable_became_stale", "Unavailable protocol was misclassified as stale layer data");
        }
        CgroupWatchInstrumentation.assertSelfExcluded(report, -1);
        KernelThreadChecks.real(report);
        List<Integer> expectedOrder = validateReportOrder(rows);
        JSONObject frame = new JSONObject().put("phase", phase).put("collectorPid", report.getInt("collectorPid"))
                .put("sampleIndex", report.getLong("sampleIndex")).put("elapsedMs", report.optLong("elapsedMs"))
                .put("rootProcessCount", report.optInt("rootProcessCount"))
                .put("cgroupAnomalyCount", report.optInt("cgroupAnomalyCount"))
                .put("monitoredProcessCount", report.optInt("monitoredProcessCount"))
                .put("reportOrder", new JSONArray(expectedOrder)).put("avcStatus", report.optString("avcStatus"));
        for (int i = 0; i < rows.length(); i++) {
            JSONObject row = rows.getJSONObject(i);
            if (expectedTargetPid > 0 && row.optInt("pid") == expectedTargetPid) {
                expectedTargetObservations++;
                frame.put("expectedTarget", row);
            }
        }
        JSONObject ui = captureUi();
        ui.put("phase", phase).put("capturedReportSampleIndex", report.getLong("sampleIndex"))
                .put("capturedReportCollectorPid", report.getInt("collectorPid"))
                .put("renderedMatchesReport", ui.optLong("sampleIndex", -1) == report.getLong("sampleIndex")
                        && ui.optInt("collectorPid", -1) == report.getInt("collectorPid"));
        uiReports.write(ui.toString());
        uiReports.newLine();
        uiReports.flush();
        frame.put("ui", ui);
        frames.put(frame);
        return report;
    }

    /** A real app-owned panel, not mock detector input; no SYSTEM_ALERT_WINDOW permission. */
    private void createOverlayFixture() throws Exception {
        overlayFixtureName = "gpc_fixture_" + java.util.UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        onMain(() -> {
            TextView panel = new TextView(activity);
            panel.setText("悬浮窗检测测试");
            panel.setTextColor(android.graphics.Color.BLACK);
            panel.setTextSize(16);
            panel.setBackgroundColor(android.graphics.Color.CYAN);
            panel.setGravity(android.view.Gravity.CENTER);
            float density = activity.getResources().getDisplayMetrics().density;
            android.view.WindowManager.LayoutParams params = new android.view.WindowManager.LayoutParams(
                    (int) (190 * density), (int) (52 * density), android.view.WindowManager.LayoutParams.TYPE_APPLICATION_PANEL,
                    android.view.WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE | android.view.WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE,
                    android.graphics.PixelFormat.TRANSLUCENT);
            params.token = activity.getWindow().getDecorView().getWindowToken();
            params.gravity = android.view.Gravity.TOP | android.view.Gravity.RIGHT;
            params.setTitle(overlayFixtureName);
            activity.getWindowManager().addView(panel, params);
            overlayFixture = panel;
        });
        summary.put("overlayFixture", new JSONObject().put("name", overlayFixtureName).put("syntheticReport", false)
                .put("kind", "real_app_owned_application_panel").put("expectedOwnerUid", android.os.Process.myUid())
                .put("targetNameSuppliedToDetector", false));
        Files.write(new File(files, "overlay-fixture.json").toPath(), summary.getJSONObject("overlayFixture").toString(2).getBytes(StandardCharsets.UTF_8));
        Bundle ready = new Bundle(); ready.putString("stage", "OVERLAY_FIXTURE_CREATED");
        ready.putString("fixtureName", overlayFixtureName); sendStatus(0, ready);
    }

    private void observeOverlayFixture(JSONObject overlay) throws Exception {
        if (overlayFixtureName == null) return;
        JSONArray routes = overlay.getJSONArray("routes");
        for (int i = 0; i < routes.length(); i++) {
            JSONObject route = routes.getJSONObject(i);
            if (!"zui".equals(route.optString("route")) || !route.optBoolean("available")) continue;
            boolean found = false;
            JSONArray rows = route.getJSONArray("rows");
            for (int j = 0; j < rows.length(); j++) {
                JSONObject row = rows.getJSONObject(j);
                if (!overlayFixtureName.equals(row.optString("normalizedName"))) continue;
                found = true;
                check(row.optBoolean("suspicious"), "Unexplained fixture title was not classified as suspicious");
                if (fixtureHitAt == 0) {
                    fixtureHitAt = SystemClock.elapsedRealtime();
                    summary.getJSONObject("overlayFixture").put("firstHit", row).put("firstHitAtMs", fixtureHitAt)
                            .put("firstCollectionAtMs", route.getLong("observedAtMs"));
                    Bundle hit = new Bundle(); hit.putString("stage", "OVERLAY_FIXTURE_DETECTED"); sendStatus(0, hit);
                }
            }
            if (fixtureRemovedAt > 0 && route.optLong("observedAtMs") > fixtureRemovedAt && !found && !fixtureGoneObserved) {
                fixtureGoneObserved = true;
                summary.getJSONObject("overlayFixture").put("absenceCollectionAtMs", route.getLong("observedAtMs"))
                        .put("absentFromFreshCollection", true);
                Bundle gone = new Bundle(); gone.putString("stage", "OVERLAY_FIXTURE_DISAPPEARED"); sendStatus(0, gone);
            }
        }
    }

    private void advanceOverlayFixture() throws Exception {
        if (overlayFixture == null || fixtureHitAt == 0 || SystemClock.elapsedRealtime() - fixtureHitAt < 2500) return;
        JSONObject ui = captureUi();
        check(ui.optBoolean("overlaySuspected") && "外挂悬浮窗".equals(ui.optString("overlayStatus")), "Fixture did not reach real red UI");
        check(ui.optString("overlayNames").contains(overlayFixtureName), "Real UI does not show the fixture name");
        summary.getJSONObject("overlayFixture").put("hitUi", ui);
        screenshot("overlay-fixture-hit.png");
        removeOverlayFixture();
        fixtureRemovedAt = SystemClock.elapsedRealtime();
        summary.getJSONObject("overlayFixture").put("removedAtMs", fixtureRemovedAt);
        Bundle removed = new Bundle(); removed.putString("stage", "OVERLAY_FIXTURE_REMOVED"); sendStatus(0, removed);
    }

    private void removeOverlayFixture() throws Exception {
        if (overlayFixture == null) return;
        onMain(() -> { activity.getWindowManager().removeViewImmediate(overlayFixture); overlayFixture = null; });
    }

    private List<Integer> validateReportOrder(JSONArray rows) throws Exception {
        List<Integer> pids = new ArrayList<>();
        double previousCpu = Double.POSITIVE_INFINITY;
        int previousPid = -1;
        for (int i = 0; i < rows.length(); i++) {
            JSONObject row = rows.getJSONObject(i);
            double cpu = row.optDouble("cpuPercent", -1);
            if (!Double.isFinite(cpu) || cpu < 0) cpu = -1;
            int pid = row.getInt("pid");
            validation(cpu <= previousCpu && (cpu != previousCpu || pid >= previousPid),
                    "report_cpu_order", "Real monitored list is not CPU descending with PID ties");
            previousCpu = cpu;
            previousPid = pid;
            pids.add(pid);
        }
        return pids;
    }

    private JSONObject captureUi() throws Exception {
        AtomicReference<JSONObject> result = new AtomicReference<>();
        onMain(() -> {
            JSONObject shown = (JSONObject) field("currentReport");
            LinearLayout list = (LinearLayout) field("processList");
            JSONArray order = new JSONArray();
            for (int i = 0; i < list.getChildCount(); i++) {
                Integer pid = findPid(list.getChildAt(i));
                if (pid != null) order.put(pid);
            }
            if (shown != null && shown.has("sampleIndex")) {
                JSONArray shownRows = shown.getJSONArray("processes");
                validateReportOrder(shownRows);
                List<Integer> expected = new ArrayList<>();
                for (int i = 0; i < Math.min(10, shownRows.length()); i++) {
                    JSONObject row = shownRows.getJSONObject(i);
                    expected.add(row.getInt("pid"));
                }
                validation(order.length() == expected.size(), "ui_candidate_count", "UI omitted or added a candidate");
                for (int i = 0; i < Math.min(order.length(), expected.size()); i++) {
                    validation(order.getInt(i) == expected.get(i), "ui_cpu_order", "UI order differs from the real CPU order");
                }
            }
            if (order.length() > 0) nonemptyUiSnapshots++;
            maximumUiCandidates = Math.max(maximumUiCandidates, order.length());
            TextView errors = (TextView) field("errorText");
            TextView overlayLabel = (TextView) field("overlayStatus");
            TextView overlayNames = (TextView) field("overlayNames");
            JSONObject overlay = shown == null ? null : shown.optJSONObject("overlay");
            boolean suspected = overlay != null && overlay.optBoolean("suspected");
            validation("外挂悬浮窗".contentEquals(overlayLabel.getText()) == suspected,
                    "overlay_label", "Overlay label does not match the displayed report");
            if (suspected) validation(overlayLabel.getCurrentTextColor() == android.graphics.Color.rgb(255, 119, 125)
                            && overlayNames.getVisibility() == View.VISIBLE && overlayNames.length() > 0,
                    "overlay_red", "Overlay alert is not red or lacks names");
            result.set(new JSONObject().put("renderedReportPresent", shown != null)
                    .put("hasRealSample", shown != null && shown.has("sampleIndex"))
                    .put("sampleIndex", shown == null ? -1 : shown.optLong("sampleIndex", -1))
                    .put("collectorPid", shown == null ? -1 : shown.optInt("collectorPid", -1))
                    .put("heroStatus", ((TextView) field("heroStatus")).getText().toString())
                    .put("overlayStatus", overlayLabel.getText().toString()).put("overlayColor", overlayLabel.getCurrentTextColor())
                    .put("overlayNames", overlayNames.getText().toString()).put("overlaySuspected", suspected)
                    .put("button", ((Button) field("startButton")).getText().toString())
                    .put("visibleErrors", errors.getVisibility() == View.VISIBLE ? errors.getText().toString() : "")
                    .put("listText", allText(list)).put("pidOrder", order)
                    .put("displayLimit", 10).put("minimumVisibleCpuPercent", 0));
        });
        return result.get();
    }

    private void awaitStopped(int collectorPid, String key) throws Exception {
        long deadline = SystemClock.elapsedRealtime() + 8000;
        while (SystemClock.elapsedRealtime() < deadline
                && (MonitorService.running || MonitorService.latestReport != null || processExists(collectorPid))) {
            SystemClock.sleep(50);
        }
        check(!MonitorService.running && MonitorService.latestReport == null, key + ": Service retained published results");
        check(!processExists(collectorPid), key + ": native collector remained alive");
        SystemClock.sleep(1200);
        check(!MonitorService.running && MonitorService.latestReport == null, key + ": old worker republished after stop");
        summary.put(key, new JSONObject().put("running", MonitorService.running)
                .put("reportCleared", MonitorService.latestReport == null).put("collectorExited", true));
    }

    private static boolean processExists(int pid) throws Exception {
        try { Os.kill(pid, 0); return true; }
        catch (ErrnoException error) {
            if (error.errno == OsConstants.ESRCH) return false;
            throw error;
        }
    }

    private void screenshot(String name) {
        try {
            Bitmap bitmap = getUiAutomation().takeScreenshot();
            if (bitmap == null) return;
            try (FileOutputStream stream = new FileOutputStream(new File(files, name))) {
                bitmap.compress(Bitmap.CompressFormat.PNG, 100, stream);
            } finally { bitmap.recycle(); }
        } catch (Exception error) {
            try { summary.put(name + "_error", error.toString()); } catch (Exception ignored) { }
        }
    }

    private Object field(String name) throws Exception {
        Field member = MainActivity.class.getDeclaredField(name);
        member.setAccessible(true);
        return member.get(activity);
    }

    private static Integer findPid(View view) {
        if (view instanceof TextView) {
            Matcher match = PID_LABEL.matcher(((TextView) view).getText());
            if (match.find()) return Integer.parseInt(match.group(1));
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

    private static String allText(View view) {
        StringBuilder text = new StringBuilder();
        if (view instanceof TextView) text.append(((TextView) view).getText()).append('\n');
        if (view instanceof ViewGroup) {
            ViewGroup group = (ViewGroup) view;
            for (int i = 0; i < group.getChildCount(); i++) text.append(allText(group.getChildAt(i)));
        }
        return text.toString();
    }

    private void validation(boolean valid, String key, String message) throws Exception {
        if (valid) return;
        if (issueKeys.add(key)) issues.put(new JSONObject().put("key", key).put("message", message));
        if (!captureOnly) throw new AssertionError(message);
    }

    private interface MainAction { void run() throws Exception; }

    private void onMain(MainAction action) throws Exception {
        AtomicReference<Throwable> failure = new AtomicReference<>();
        runOnMainSync(() -> {
            try { action.run(); } catch (Throwable error) { failure.set(error); }
        });
        Throwable error = failure.get();
        if (error instanceof Error) throw (Error) error;
        if (error != null) throw new Exception(error);
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
