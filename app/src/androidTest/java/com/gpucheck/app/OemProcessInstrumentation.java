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
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

/** Ordinary-UID OEM protocol/model checks followed by the real Activity -> Service -> UI path. */
public final class OemProcessInstrumentation extends Instrumentation {
    private final JSONObject summary = new JSONObject();
    private final Set<String> samples = new HashSet<>();
    private final Set<String> completedRoutes = new HashSet<>();
    private final Set<String> availableRoutes = new HashSet<>();
    private Bundle arguments;
    private MainActivity activity;
    private File files;
    private BufferedWriter reports, uiReports;
    private int uidRows, unknownUidRows, reportedUidRows, uiRows, realUiFrames;
    private volatile boolean activityStopped;

    @Override public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        this.arguments = arguments == null ? new Bundle() : new Bundle(arguments);
        start();
    }

    @Override public void callActivityOnStop(Activity target) {
        super.callActivityOnStop(target);
        if (target instanceof MainActivity) activityStopped = true;
    }

    @Override public void callActivityOnResume(Activity target) {
        super.callActivityOnResume(target);
        if (target instanceof MainActivity) activityStopped = false;
    }

    @Override public void onStart() {
        Bundle result = new Bundle();
        int resultCode = Activity.RESULT_CANCELED;
        try {
            files = getTargetContext().getFilesDir();
            summary.put("test", "oem_process_activity_service_uid").put("startedEpochMs", System.currentTimeMillis())
                    .put("appUid", android.os.Process.myUid()).put("appPid", android.os.Process.myPid())
                    .put("installedVersion", getTargetContext().getPackageManager()
                            .getPackageInfo(getTargetContext().getPackageName(), 0).versionName)
                    .put("targetPidsSuppliedToDetector", false);
            String ownStatus = new String(Files.readAllBytes(new File("/proc/self/status").toPath()), StandardCharsets.UTF_8);
            summary.put("appSelinux", new String(Files.readAllBytes(new File("/proc/self/attr/current").toPath()),
                    StandardCharsets.UTF_8).replace("\u0000", "").trim());
            for (String line : ownStatus.split("\n")) if (line.startsWith("CapEff:")) summary.put("appCapEff", line.substring(7).trim());
            require(android.os.Process.myUid() >= 10000, "Test must run under ordinary application UID");
            require("0000000000000000".equals(summary.optString("appCapEff")), "Application acquired effective capabilities");
            summary.put("syntheticModelChecks", OemProcessChecks.run());
            summary.put("syntheticMiuiProtocolChecks", MiuiProcessChecks.run());
            summary.put("syntheticOplusProtocolChecks", OplusProcessChecks.run());
            summary.put("syntheticRedVivoProtocolChecks", RedVivoProcessChecks.run());
            if (Boolean.parseBoolean(arguments.getString("checks_only", "false"))) {
                summary.put("realServiceRun", false).put("result", "PASS");
                result.putString("result", "PASS");
                resultCode = Activity.RESULT_OK;
                return;
            }
            require(getTargetContext().getSystemService(PowerManager.class).isInteractive(), "Screen is not awake");
            require(!getTargetContext().getSystemService(KeyguardManager.class).isKeyguardLocked(), "Screen is locked");
            int duration = Integer.parseInt(arguments.getString("duration_seconds", "25"));
            require(duration >= 10 && duration <= 120, "duration_seconds must be 10..120");
            reports = Files.newBufferedWriter(new File(files, "oem-process-real.jsonl").toPath(), StandardCharsets.UTF_8);
            uiReports = Files.newBufferedWriter(new File(files, "oem-process-ui.jsonl").toPath(), StandardCharsets.UTF_8);
            activity = (MainActivity) startActivitySync(new Intent(getTargetContext(), MainActivity.class)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK));
            waitForIdleSync();
            require(!MonitorService.running && MonitorService.latestReport == null, "Unexpected old monitoring session");
            summary.put("syntheticUidUiChecks", OemProcessChecks.ui(this, activity));
            clickStartStop();
            JSONObject first = awaitSamples("first", 2, 25000);
            int firstCollector = first.getInt("collectorPid");
            long firstSession = first.getLong("sessionStartedAt");
            Bundle ready = new Bundle(); ready.putString("stage", "OEM_MONITOR_READY");
            ready.putInt("collectorPid", firstCollector); sendStatus(0, ready);
            long deadline = SystemClock.elapsedRealtime() + duration * 1000L;
            while (SystemClock.elapsedRealtime() < deadline) {
                require(MonitorService.running, "Service stopped during capture: " + MonitorService.lastError);
                record("first");
                SystemClock.sleep(80);
            }
            record("first");
            require(completedRoutes.size() == 5, "Every OEM route must report an actual result or timeout: " + completedRoutes);
            require(realUiFrames > 0 && uiRows > 0, "No real process UID labels were inspected");
            if (Boolean.parseBoolean(arguments.getString("require_oplus", "false"))) {
                require(availableRoutes.contains("oplus_cpu"), "Oplus route did not become available on this firmware");
            }
            screenshot("oem-process-active.png");
            summary.put("activeUi", captureUi());
            clickPage(1);
            screenshot("oem-process-processes.png");
            summary.put("processPageUi", captureUi());
            clickPage(2);
            screenshot("oem-process-evidence.png");
            summary.put("evidencePageUi", captureUi());
            clickStartStop();
            awaitStopped("buttonStop");
            SystemClock.sleep(300);
            clickStartStop();
            JSONObject restarted = awaitSamples("restart", 2, 25000);
            require(restarted.getInt("collectorPid") != firstCollector
                    && restarted.getLong("sessionStartedAt") > firstSession, "Restart reused native collector/session");
            summary.put("firstCollectorPid", firstCollector).put("secondCollectorPid", restarted.getInt("collectorPid"));
            require(getUiAutomation().performGlobalAction(AccessibilityService.GLOBAL_ACTION_HOME), "Cannot leave Activity");
            awaitStopped("backgroundStop");
            summary.put("realServiceRun", true).put("result", "PASS");
            result.putString("result", "PASS");
            resultCode = Activity.RESULT_OK;
        } catch (Throwable error) {
            String detail = android.util.Log.getStackTraceString(error);
            try { summary.put("result", "FAIL").put("error", detail); } catch (Exception ignored) { }
            result.putString("result", "FAIL"); result.putString("error", detail);
        } finally {
            if (MonitorService.running) {
                try { getTargetContext().stopService(new Intent(getTargetContext(), MonitorService.class)); }
                catch (Exception ignored) { }
            }
            try { if (reports != null) reports.close(); } catch (Exception ignored) { }
            try { if (uiReports != null) uiReports.close(); } catch (Exception ignored) { }
            try {
                summary.put("realSamples", samples.size()).put("knownNativeUidObservations", uidRows)
                        .put("reportedUidObservations", reportedUidRows).put("unknownUidObservations", unknownUidRows)
                        .put("realUiFrames", realUiFrames).put("inspectedProcessCards", uiRows)
                        .put("completedRoutes", new JSONArray(completedRoutes)).put("availableRoutes", new JSONArray(availableRoutes))
                        .put("finishedEpochMs", System.currentTimeMillis());
                if (files != null) Files.write(new File(files, "oem-process-summary.json").toPath(),
                        summary.toString(2).getBytes(StandardCharsets.UTF_8));
            } catch (Exception error) { result.putString("evidenceError", error.toString()); resultCode = Activity.RESULT_CANCELED; }
            result.putInt("realSamples", samples.size());
            result.putString("summary", files == null ? "unavailable" : new File(files, "oem-process-summary.json").getAbsolutePath());
            finish(resultCode, result);
        }
    }

    private JSONObject awaitSamples(String phase, int count, long timeout) throws Exception {
        int previous = samples.size();
        JSONObject latest = null;
        long deadline = SystemClock.elapsedRealtime() + timeout;
        while (SystemClock.elapsedRealtime() < deadline) {
            JSONObject report = record(phase);
            if (report != null) latest = report;
            if (latest != null && samples.size() - previous >= count) return latest;
            if (!MonitorService.running && MonitorService.lastError != null) throw new AssertionError(MonitorService.lastError);
            SystemClock.sleep(50);
        }
        throw new AssertionError("Timed out awaiting " + phase + " samples");
    }

    private JSONObject record(String phase) throws Exception {
        String raw = MonitorService.latestReport;
        if (raw == null) return null;
        JSONObject report = new JSONObject(raw);
        if (!report.has("sampleIndex")) return null;
        String key = report.getInt("collectorPid") + ":" + report.getLong("sampleIndex");
        if (!samples.add(key)) return report;
        reports.write(raw); reports.newLine(); reports.flush();
        require(!report.optBoolean("root") && report.getInt("collectorUid") == android.os.Process.myUid(), "Collector UID changed");
        JSONObject oem = report.getJSONObject("oemProcesses");
        JSONArray routes = oem.getJSONArray("routes");
        require(routes.length() == 5 && !oem.optBoolean("brandGateUsed"), "Missing OEM routes or brand gate used");
        Set<String> routeNames = new HashSet<>();
        for (int i = 0; i < routes.length(); i++) {
            JSONObject route = routes.getJSONObject(i);
            String name = route.getString("route"), status = route.getString("status");
            require(routeNames.add(name), "Duplicate OEM route " + name);
            require(!route.optBoolean("brandGateUsed"), "A route was brand-gated");
            require(!status.equals("SKIPPED_BRAND"), "OEM route skipped by brand");
            if (!status.equals("CHECKING") && !status.equals("WAITING")) completedRoutes.add(name);
            if (route.optBoolean("available")) availableRoutes.add(name);
        }
        require(routeNames.contains("miui_cpu") && routeNames.contains("miui_memory") && routeNames.contains("oplus_cpu")
                && routeNames.contains("mindsync") && routeNames.contains("vivo_rms"), "Unexpected route names " + routeNames);
        JSONArray rows = report.getJSONArray("processes");
        Set<Integer> pids = new HashSet<>();
        JSONArray excluded = report.getJSONArray("cpuExcludedPidTids");
        require(excluded.length() == report.getInt("cpuExcludedPidTidCount"), "Native excluded PID/TID list differs from its count");
        Set<Integer> excludedPids = new HashSet<>();
        for (int i = 0; i < excluded.length(); i++) require(excludedPids.add(excluded.getInt(i)), "Duplicate excluded PID/TID");
        for (int i = 0; i < rows.length(); i++) {
            JSONObject row = rows.getJSONObject(i);
            int pid = row.getInt("pid"), uid = row.optInt("uid", -1), reportedUid = row.optInt("reportedUid", -1);
            require(pids.add(pid), "Duplicate process PID");
            require(!excludedPids.contains(pid), "OEM merge restored an excluded own process/thread");
            require(pid != android.os.Process.myPid() && pid != report.getInt("collectorPid"), "App/collector retained");
            require(uid != android.os.Process.myUid(), "Own UID process retained");
            require(row.has("uid"), "Process lacks explicit native UID/unknown marker");
            if (uid >= 0) uidRows++;
            else if (reportedUid >= 0 && !row.optBoolean("reportedUidConflict")) reportedUidRows++;
            else unknownUidRows++;
            if (!row.optBoolean("identityVerified") && uid < 0 && reportedUid == 0) {
                require(!row.optBoolean("rootCandidate") && !"HIGH".equals(row.optString("risk")), "OEM-reported UID fabricated root risk");
            }
        }
        JSONObject ui = captureUi();
        ui.put("phase", phase).put("capturedReportSampleIndex", report.getLong("sampleIndex"));
        uiReports.write(ui.toString()); uiReports.newLine(); uiReports.flush();
        return report;
    }

    private JSONObject captureUi() throws Exception {
        AtomicReference<JSONObject> result = new AtomicReference<>();
        onMain(() -> {
            JSONObject rendered = (JSONObject) field("currentReport");
            LinearLayout list = (LinearLayout) field("processList");
            JSONArray cards = new JSONArray();
            if (rendered != null && rendered.has("sampleIndex")) {
                java.util.List<JSONObject> expected = MainActivity.cpuLeaders(rendered.getJSONArray("processes"),
                        rendered.optInt("collectorPid", -1));
                if (!expected.isEmpty()) require(list.getChildCount() == expected.size(), "Real UI process card count differs from CPU leaders");
                for (int i = 0; i < expected.size(); i++) {
                    JSONObject row = expected.get(i);
                    String text = texts(list.getChildAt(i));
                    String uidLabel = MainActivity.processUidLabel(row);
                    require(text.contains("PID " + row.getInt("pid")), "Card PID differs from rendered report");
                    require(text.contains(uidLabel), "Missing/wrong UID label: " + uidLabel + " in " + text);
                    cards.put(new JSONObject().put("pid", row.getInt("pid")).put("uidLabel", uidLabel).put("text", text));
                    uiRows++;
                }
                realUiFrames++;
            }
            result.set(new JSONObject().put("synthetic", false).put("cards", cards)
                    .put("collectorPid", rendered == null ? -1 : rendered.optInt("collectorPid", -1))
                    .put("sampleIndex", rendered == null ? -1 : rendered.optLong("sampleIndex", -1))
                    .put("oemProcessStatus", ((TextView) field("oemProcessStatus")).getText().toString()));
        });
        return result.get();
    }

    private void clickStartStop() throws Exception {
        long deadline = SystemClock.elapsedRealtime() + 4000;
        while (SystemClock.elapsedRealtime() < deadline) {
            AtomicReference<Boolean> accepted = new AtomicReference<>(false);
            onMain(() -> { Button button = (Button) field("startButton"); if (button.isEnabled()) accepted.set(button.performClick()); });
            if (accepted.get()) return;
            SystemClock.sleep(50);
        }
        throw new AssertionError("Start/stop control did not accept click");
    }

    private void awaitStopped(String key) throws Exception {
        long deadline = SystemClock.elapsedRealtime() + 8000;
        boolean background = "backgroundStop".equals(key);
        while ((MonitorService.running || MonitorService.latestReport != null || (background && !activityStopped))
                && SystemClock.elapsedRealtime() < deadline) SystemClock.sleep(50);
        require(!MonitorService.running && MonitorService.latestReport == null, "Session retained data after " + key
                + "; running=" + MonitorService.running + "; reportPresent=" + (MonitorService.latestReport != null));
        if (background) onMain(() -> {
            boolean focused = activity.hasWindowFocus(), refreshActive = (Boolean) field("refreshActive");
            boolean activityReportPresent = field("currentReport") != null;
            summary.put("backgroundActivity", new JSONObject().put("stopCallbackObserved", activityStopped)
                    .put("hasWindowFocus", focused).put("refreshActive", refreshActive)
                    .put("reportPresent", activityReportPresent).put("isFinishing", activity.isFinishing()));
            require(activityStopped && !focused && !refreshActive && !activityReportPresent,
                    "HOME did not leave/clear the real Activity: " + summary.getJSONObject("backgroundActivity"));
        });
        summary.put(key, true);
    }

    private void clickPage(int index) throws Exception {
        onMain(() -> {
            Button[] tabs = (Button[]) field("pageTabs");
            require(tabs[index].performClick(), "Page navigation did not accept real click: " + index);
            require((Integer) field("selectedPage") == index, "Wrong selected page after click");
        });
        waitForIdleSync();
        SystemClock.sleep(350);
        require(MonitorService.running, "Page navigation stopped collection");
    }

    private void screenshot(String name) throws Exception {
        Bitmap bitmap = getUiAutomation().takeScreenshot();
        require(bitmap != null, "Screenshot unavailable");
        try (FileOutputStream out = new FileOutputStream(new File(files, name))) {
            require(bitmap.compress(Bitmap.CompressFormat.PNG, 100, out), "Screenshot encoding failed");
        } finally { bitmap.recycle(); }
    }

    private Object field(String name) throws Exception {
        Field field = MainActivity.class.getDeclaredField(name); field.setAccessible(true); return field.get(activity);
    }

    interface Checked { void run() throws Exception; }
    private void onMain(Checked work) throws Exception {
        AtomicReference<Throwable> failure = new AtomicReference<>();
        runOnMainSync(() -> { try { work.run(); } catch (Throwable error) { failure.set(error); } });
        if (failure.get() != null) throw new AssertionError("Main thread UI check", failure.get());
    }

    static String texts(View view) {
        StringBuilder result = new StringBuilder();
        if (view instanceof TextView) result.append(((TextView) view).getText()).append('\n');
        if (view instanceof ViewGroup) {
            ViewGroup group = (ViewGroup) view;
            for (int i = 0; i < group.getChildCount(); i++) result.append(texts(group.getChildAt(i)));
        }
        return result.toString();
    }

    private static void require(boolean value, String message) { if (!value) throw new AssertionError(message); }
}
