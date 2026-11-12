package com.gpucheck.app;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.SpannableString;
import android.text.Spanned;
import android.text.style.ForegroundColorSpan;
import android.view.Gravity;
import android.view.View;
import android.view.WindowInsets;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/** A local-only dashboard. Every risk label comes from the monitor's measured report. */
public final class MainActivity extends Activity {
    static final int MAX_DISPLAYED_PROCESSES = 10;
    private static final int BG = Color.rgb(10, 20, 25);
    private static final int SURFACE = Color.rgb(18, 35, 43);
    private static final int BORDER = Color.rgb(38, 65, 74);
    private static final int TEXT = Color.rgb(238, 248, 245);
    private static final int MUTED = Color.rgb(150, 174, 180);
    private static final int ACCENT = Color.rgb(98, 227, 187);
    private static final int RED = Color.rgb(255, 119, 125);
    private static final int AMBER = Color.rgb(255, 202, 121);

    private TextView stateBadge;
    private TextView riskCount;
    private TextView heroStatus;
    private TextView heroDescription;
    private TextView candidateMetric;
    private TextView gpuMetric;
    private TextView cpuMetric;
    private TextView sampleStatus;
    private TextView errorText;
    private TextView listTitle;
    private TextView watchSummary;
    private TextView permissionStatus;
    private TextView globalGpuStatus;
    private TextView environmentSummary;
    private TextView recentLifecycleSignals;
    private Button startButton;
    private LinearLayout processList;
    private final List<ProcessRow> processRows = new ArrayList<>();
    private LinearLayout emptyProcessCard;
    private TextView emptyProcessTitle;
    private TextView emptyProcessDescription;
    private LinearLayout hero;
    private LinearLayout environmentCard;
    private boolean refreshActive;
    private String renderedReport;
    private String lastRenderedSnapshot;
    private String lastRenderedError;
    private boolean lastRenderedRunning;
    private boolean forceRefresh = true;
    private JSONObject currentReport;

    private final Handler refreshHandler = new Handler(Looper.getMainLooper());
    private final Runnable refreshLoop = new Runnable() {
        @Override public void run() {
            if (!refreshActive) return;
            renderLatest();
            refreshHandler.postDelayed(this, 1000);
        }
    };

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().setStatusBarColor(BG);
        getWindow().setNavigationBarColor(BG);
        MonitorService.clearPreviousResults(this);
        buildUi();
        renderLatest();
    }

    @Override protected void onResume() {
        super.onResume();
        forceRefresh = true;
        refreshActive = true;
        refreshHandler.removeCallbacks(refreshLoop);
        refreshHandler.post(refreshLoop);
    }

    @Override protected void onPause() {
        getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        refreshActive = false;
        refreshHandler.removeCallbacks(refreshLoop);
        super.onPause();
    }

    @Override protected void onStop() {
        // Leaving this screen stops collection and clears results; rotation keeps the session.
        if (!isChangingConfigurations()) {
            if (MonitorService.running) stopService(new Intent(this, MonitorService.class));
            currentReport = null;
            renderedReport = null;
            lastRenderedSnapshot = null;
            clearProcessRows();
        }
        super.onStop();
    }

    private void buildUi() {
        LinearLayout frame = new LinearLayout(this);
        frame.setOrientation(LinearLayout.VERTICAL);
        frame.setBackgroundColor(BG);
        frame.setOnApplyWindowInsetsListener((v, insets) -> {
            if (Build.VERSION.SDK_INT >= 30) {
                android.graphics.Insets bars = insets.getInsets(WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
                v.setPadding(bars.left, bars.top, bars.right, bars.bottom);
            } else {
                v.setPadding(insets.getSystemWindowInsetLeft(), insets.getSystemWindowInsetTop(),
                        insets.getSystemWindowInsetRight(), insets.getSystemWindowInsetBottom());
            }
            return insets;
        });
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setClipToPadding(false);
        LinearLayout page = vertical();
        page.setPadding(dp(20), dp(18), dp(20), dp(30));
        scroll.addView(page, new ScrollView.LayoutParams(-1, -2));
        frame.addView(scroll, new LinearLayout.LayoutParams(-1, -1));
        setContentView(frame);

        LinearLayout heading = row();
        TextView brand = label("GPU CHECK", 12, ACCENT, true);
        brand.setLetterSpacing(0.15f);
        heading.addView(brand, new LinearLayout.LayoutParams(0, -2, 1));
        stateBadge = badge("未运行", MUTED);
        heading.addView(stateBadge);
        page.addView(heading);
        TextView title = label("全进程 CPU 监听", 27, TEXT, true);
        marginAdd(page, title, 12);
        TextView subtitle = label("排除自身进程与线程 · 显示 CPU 前 10", 13, MUTED, false);
        marginAdd(page, subtitle, 6);

        hero = card();
        marginAdd(page, hero, 22);
        TextView eyebrow = label("当前高风险", 13, MUTED, false);
        hero.addView(eyebrow);
        LinearLayout summary = row();
        summary.setGravity(Gravity.CENTER_VERTICAL);
        riskCount = label("—", 54, TEXT, true);
        summary.addView(riskCount, new LinearLayout.LayoutParams(-2, -2));
        heroStatus = label("等待开始检测", 17, TEXT, true);
        LinearLayout.LayoutParams statusParams = new LinearLayout.LayoutParams(0, -2, 1);
        statusParams.leftMargin = dp(18);
        summary.addView(heroStatus, statusParams);
        marginAdd(hero, summary, 3);
        heroDescription = label("检测界面可见期间采样，无需任何授权。", 13, MUTED, false);
        heroDescription.setLineSpacing(dp(3), 1f);
        marginAdd(hero, heroDescription, 3);
        watchSummary = label(getString(R.string.monitoring_summary, 0, 0, 0), 13, AMBER, true);
        marginAdd(hero, watchSummary, 10);
        permissionStatus = label("无需任何授权", 11, MUTED, false);
        marginAdd(hero, permissionStatus, 8);
        globalGpuStatus = label(getString(R.string.global_gpu_waiting), 11, MUTED, false);
        globalGpuStatus.setLineSpacing(dp(2), 1f);
        globalGpuStatus.setOnClickListener(v -> showGlobalGpuEvidence());
        marginAdd(hero, globalGpuStatus, 4);
        View line = new View(this);
        line.setBackgroundColor(BORDER);
        LinearLayout.LayoutParams divider = new LinearLayout.LayoutParams(-1, dp(1));
        divider.topMargin = dp(18);
        divider.bottomMargin = dp(16);
        hero.addView(line, divider);
        LinearLayout metrics = row();
        candidateMetric = metric(metrics, getString(R.string.monitored_processes_metric));
        gpuMetric = metric(metrics, "按进程 GPU 证据");
        cpuMetric = metric(metrics, "最高 CPU");
        hero.addView(metrics);
        sampleStatus = label("采样尚未启动", 11, MUTED, false);
        marginAdd(hero, sampleStatus, 15);

        recentLifecycleSignals = label("", 12, AMBER, false);
        recentLifecycleSignals.setLineSpacing(dp(3), 1f);
        recentLifecycleSignals.setVisibility(View.GONE);
        marginAdd(page, recentLifecycleSignals, 10);

        environmentCard = card();
        environmentCard.setBackground(shape(Color.rgb(43, 30, 35), RED, 16));
        environmentCard.addView(label(getString(R.string.environment_anomaly), 17, RED, true));
        environmentSummary = label("", 13, TEXT, false);
        environmentSummary.setLineSpacing(dp(3), 1f);
        marginAdd(environmentCard, environmentSummary, 8);
        marginAdd(environmentCard, label(getString(R.string.environment_conflict_details), 11, MUTED, false), 8);
        environmentCard.setOnClickListener(v -> showEnvironmentEvidence());
        environmentCard.setFocusable(true);
        environmentCard.setVisibility(View.GONE);
        marginAdd(page, environmentCard, 14);

        startButton = button("开始检测", true);
        startButton.setOnClickListener(v -> toggleMonitor());
        LinearLayout.LayoutParams startParams = new LinearLayout.LayoutParams(-1, dp(48));
        startParams.topMargin = dp(14);
        page.addView(startButton, startParams);
        errorText = label("", 12, AMBER, false);
        errorText.setLineSpacing(dp(3), 1f);
        errorText.setVisibility(View.GONE);
        marginAdd(page, errorText, 12);

        LinearLayout sectionHeading = row();
        listTitle = label(getString(R.string.candidates_title), 18, TEXT, true);
        sectionHeading.addView(listTitle, new LinearLayout.LayoutParams(0, -2, 1));
        TextView detailHint = label("点击查看证据", 11, MUTED, false);
        sectionHeading.addView(detailHint);
        marginAdd(page, sectionHeading, 24);
        processList = vertical();
        marginAdd(page, processList, 6);

        TextView local = label("实时检测  /  停止清空  /  无需任何授权", 10, MUTED, false);
        local.setGravity(Gravity.CENTER);
        marginAdd(page, local, 20);
    }

    private void toggleMonitor() {
        if (MonitorService.running) {
            startService(new Intent(this, MonitorService.class).setAction(MonitorService.ACTION_STOP));
            startButton.setEnabled(false);
            startButton.postDelayed(() -> { startButton.setEnabled(true); renderLatest(); }, 500);
            return;
        }
        Intent intent = new Intent(this, MonitorService.class).setAction(MonitorService.ACTION_START);
        try {
            startService(intent);
            startButton.setEnabled(false);
            startButton.postDelayed(() -> { startButton.setEnabled(true); renderLatest(); }, 800);
            heroStatus.setText("正在启动采集");
            heroDescription.setText(R.string.collector_starting);
        } catch (RuntimeException e) {
            errorText.setVisibility(View.VISIBLE);
            errorText.setText(getString(R.string.start_failed, e.getMessage()));
        }
    }

    private void renderLatest() {
        boolean running = MonitorService.running;
        if (running) getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        else getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        String raw = MonitorService.latestReport;
        String currentError = MonitorService.lastError;
        if (!forceRefresh && running == lastRenderedRunning && Objects.equals(raw, lastRenderedSnapshot)
                && Objects.equals(currentError, lastRenderedError)) return;
        forceRefresh = false;
        lastRenderedRunning = running;
        lastRenderedSnapshot = raw;
        lastRenderedError = currentError;
        heroDescription.setVisibility(View.VISIBLE);
        startButton.setText(running ? "停止检测" : "开始检测");
        stateBadge.setText(running ? "●  监测中" : "●  已停止");
        stateBadge.setTextColor(running ? ACCENT : MUTED);
        stateBadge.setBackground(shape(running ? Color.rgb(20, 58, 49) : SURFACE, BORDER, 18));
        if (raw == null || raw.isEmpty()) {
            currentReport = null;
            renderedReport = null;
            updateEnvironmentStatus();
            updateRecentLifecycleSignals();
            watchSummary.setText(getString(R.string.monitoring_summary, 0, 0, 0));
            candidateMetric.setText("—");
            gpuMetric.setText("—");
            cpuMetric.setText("—");
            sampleStatus.setText(R.string.no_retained_results);
            permissionStatus.setText(getString(R.string.ordinary_mode, uidText(android.os.Process.myUid())));
            updateGlobalGpuStatus();
            hero.setBackground(shape(SURFACE, BORDER, 18));
            riskCount.setText("—");
            riskCount.setTextColor(TEXT);
            String error = currentError;
            errorText.setText(error == null ? "" : error);
            errorText.setVisibility(error == null ? View.GONE : View.VISIBLE);
            heroStatus.setText(error != null ? "采集已停止" : running ? "等待首次采样" : "等待开始检测");
            heroDescription.setText(running ? "正在以普通应用身份建立采样基线，无需任何授权。" : "检测界面可见期间采样，无需任何授权。");
            renderProcesses();
            return;
        }
        try {
            currentReport = new JSONObject(raw);
            updateEnvironmentStatus();
            updateRecentLifecycleSignals();
            if (running && isStartingReport()) {
                watchSummary.setText(getString(R.string.monitoring_summary, 0, 0, 0));
                permissionStatus.setText(getString(R.string.ordinary_mode, uidText(currentReport.optInt("collectorUid", -1))));
                riskCount.setText("—");
                riskCount.setTextColor(TEXT);
                hero.setBackground(shape(SURFACE, BORDER, 18));
                heroStatus.setText("正在建立采样基线");
                heroDescription.setText(R.string.collector_starting);
                candidateMetric.setText("—");
                gpuMetric.setText("—");
                cpuMetric.setText("—");
                sampleStatus.setText("等待首份进程快照");
                globalGpuStatus.setText(R.string.global_gpu_waiting);
                globalGpuStatus.setTextColor(MUTED);
                errorText.setText("");
                errorText.setVisibility(View.GONE);
                renderedReport = raw;
                renderProcesses();
                return;
            }
            JSONArray processes = currentReport.optJSONArray("processes");
            int high = 0;
            int rootWatch = 0;
            int rootCount = 0;
            int monitoredCount = 0;
            int anomalyCount = 0;
            JSONArray errors = currentReport.optJSONArray("errors");
            int denied = currentReport.optInt("deniedProcesses", 0);
            int gpuCount = 0;
            double maxCpu = -1;
            boolean baseline = true;
            if (processes != null) {
                for (int i = 0; i < processes.length(); i++) {
                    JSONObject p = processes.optJSONObject(i);
                    if (p == null || !isVisibleProcess(p, currentReport.optInt("collectorPid", -1))) continue;
                    monitoredCount++;
                    boolean rootCandidate = isRootCandidate(p);
                    if (rootCandidate) rootCount++;
                    if (p.optBoolean("cgroupAnomaly")) anomalyCount++;
                    if (rootCandidate && "HIGH".equals(p.optString("risk"))) high++;
                    String risk = p.optString("risk", "UNKNOWN");
                    if (rootCandidate && ("WATCH".equals(risk) || "UNKNOWN".equals(risk))) rootWatch++;
                    if (p.optBoolean("gpuDeviceOpen") || p.optBoolean("gpuActive")) gpuCount++;
                    double cpu = cpuSortValue(p);
                    if (cpu >= 0) baseline = false;
                    maxCpu = Math.max(maxCpu, cpu);
                }
            }
            watchSummary.setText(getString(R.string.monitoring_summary, monitoredCount, rootCount, anomalyCount));
            permissionStatus.setText(getString(R.string.ordinary_mode, uidText(currentReport.optInt("collectorUid", -1))));
            updateGlobalGpuStatus();
            boolean cgroupUnavailable = isCgroupCheckUnavailable();
            boolean incomplete = denied > 0 || cgroupUnavailable || (errors != null && errors.length() > 0);
            riskCount.setText(String.format(Locale.getDefault(), "%d", high));
            int riskColor = high > 0 ? RED : rootWatch > 0 || anomalyCount > 0 || incomplete ? AMBER : TEXT;
            riskCount.setTextColor(riskColor);
            hero.setBackground(shape(SURFACE, high > 0 ? RED : BORDER, 18));
            if (!running) {
                heroStatus.setText("检测已停止");
                heroDescription.setText(R.string.no_retained_results);
            } else if (currentReport.optBoolean("environmentAnomaly")) {
                heroStatus.setText(R.string.environment_anomaly);
                heroDescription.setText(R.string.environment_anomaly_description);
            } else if (high > 0) {
                heroStatus.setText("发现高风险 · 需核查");
                heroDescription.setText("");
                heroDescription.setVisibility(View.GONE);
            } else if (anomalyCount > 0) {
                heroStatus.setText(R.string.cgroup_anomaly_title);
                heroDescription.setText(R.string.cgroup_anomaly_description);
            } else if (rootWatch > 0) {
                heroStatus.setText(R.string.root_watch_title);
                heroDescription.setText(R.string.root_watch_description);
            } else if (monitoredCount == 0) {
                heroStatus.setText(R.string.no_monitored_candidates);
                heroDescription.setText(R.string.monitored_candidates_description);
            } else if (baseline) {
                heroStatus.setText(R.string.cpu_unavailable_title);
                heroDescription.setText("正在建立基线或当前数据不可读取，采集限制会在下方列出。");
            } else if (incomplete) {
                heroStatus.setText("正在采样 · 部分证据受限");
                heroDescription.setText("普通应用无法读取部分进程信息；这些字段保持未知，继续观察可用指标。");
            } else {
                heroStatus.setText("当前未命中高风险规则");
                heroDescription.setText("继续观察连续采样；未命中规则不代表设备没有风险。");
            }
            candidateMetric.setText(String.format(Locale.getDefault(), "%d", monitoredCount));
            gpuMetric.setText(String.format(Locale.getDefault(), "%d", gpuCount));
            cpuMetric.setText(cpu(maxCpu));
            long timestamp = currentReport.optLong("timestampEpochMs", 0);
            String time = timestamp > 0 ? new SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(new Date(timestamp)) : "—";
            String samplingStatus = getString(R.string.sampling_status, time,
                    currentReport.optInt("scannedProcesses", 0), denied);
            if (isCgroupPathProbeAvailable()) samplingStatus += "\n" + getString(R.string.cgroup_check_available);
            sampleStatus.setText(samplingStatus);
            StringBuilder error = new StringBuilder();
            if (errors != null) {
                for (int i = 0; i < errors.length(); i++) {
                    if (error.length() > 0) error.append('\n');
                    error.append(errors.optString(i));
                }
            }
            if (cgroupUnavailable) {
                if (error.length() > 0) error.append('\n');
                error.append(getString(R.string.cgroup_check_unavailable));
            }
            errorText.setText(error.toString());
            errorText.setVisibility(error.length() == 0 ? View.GONE : View.VISIBLE);
            if (!raw.equals(renderedReport)) {
                renderedReport = raw;
                renderProcesses();
            }
        } catch (JSONException e) {
            environmentCard.setVisibility(View.GONE);
            environmentSummary.setText("");
            recentLifecycleSignals.setVisibility(View.GONE);
            recentLifecycleSignals.setText("");
            errorText.setText(getString(R.string.parse_failed, e.getMessage()));
            errorText.setVisibility(View.VISIBLE);
            heroStatus.setText("采集结果异常");
            riskCount.setText("—");
        }
    }

    private boolean isCgroupCheckUnavailable() {
        JSONObject scan = cgroupPathScan();
        return !isStartingReport() && scan != null
                && (!scan.optBoolean("available") || !scan.optBoolean("calibrationValid"));
    }

    private boolean isCgroupPathProbeAvailable() {
        JSONObject scan = cgroupPathScan();
        return !isStartingReport() && scan != null && scan.optBoolean("available")
                && scan.optBoolean("calibrationValid");
    }

    private JSONObject cgroupPathScan() {
        JSONObject scan = currentReport == null ? null : currentReport.optJSONObject("cgroupScan");
        return scan != null && "stat_uid_pid_paths".equals(scan.optString("method")) ? scan : null;
    }

    private boolean isStartingReport() {
        return currentReport != null && ("STARTING".equals(currentReport.optString("samplingState"))
                || !currentReport.has("sampleIndex"));
    }

    private void updateGlobalGpuStatus() {
        JSONObject global = currentReport == null ? null : currentReport.optJSONObject("globalGpu");
        if (global == null || !global.optBoolean("supported")) {
            globalGpuStatus.setText(R.string.global_gpu_unknown);
            globalGpuStatus.setTextColor(MUTED);
        } else if (!global.optBoolean("sampled")) {
            globalGpuStatus.setText(R.string.global_gpu_baseline);
            globalGpuStatus.setTextColor(MUTED);
        } else {
            globalGpuStatus.setText(global.optBoolean("active") ? R.string.global_gpu_active : R.string.global_gpu_quiet);
            globalGpuStatus.setTextColor(global.optBoolean("active") ? AMBER : MUTED);
        }
    }

    private void updateEnvironmentStatus() {
        if (currentReport == null || !currentReport.optBoolean("environmentAnomaly")) {
            environmentCard.setVisibility(View.GONE);
            environmentSummary.setText("");
            return;
        }
        JSONArray checks = currentReport.optJSONArray("environmentChecks");
        List<Integer> pids = new ArrayList<>();
        for (int i = 0; checks != null && i < checks.length(); i++) {
            JSONObject check = checks.optJSONObject(i);
            if (check == null || !"ANOMALY".equals(check.optString("status"))) continue;
            int pid = check.optInt("pid", -1);
            if (pid > 0 && !pids.contains(pid)) pids.add(pid);
        }
        Collections.sort(pids);
        StringBuilder names = new StringBuilder();
        for (int pid : pids) {
            if (names.length() > 0) names.append("、");
            names.append(pid);
        }
        environmentSummary.setText(getString(R.string.environment_conflict_summary,
                names.length() == 0 ? "详见原始依据" : names.toString()));
        environmentCard.setVisibility(View.VISIBLE);
    }

    private void updateRecentLifecycleSignals() {
        JSONArray signals = currentReport == null ? null : currentReport.optJSONArray("recentLifecycleSignals");
        StringBuilder lines = new StringBuilder();
        for (int i = 0; signals != null && i < signals.length(); i++) {
            JSONObject signal = signals.optJSONObject(i);
            if (signal == null || !"EXIT".equals(signal.optString("kind"))) continue;
            String state = signal.optString("state");
            String line;
            if ("EXIT_MATCH".equals(state)) {
                line = getString(R.string.lifecycle_exit_match, signal.optInt("pid"), lifecycleSlots(signal));
            } else if ("AMBIGUOUS".equals(state)) {
                line = getString(R.string.lifecycle_exit_ambiguous, signal.optInt("pid"));
                String reason = signal.optString("reason", "");
                if (!reason.isEmpty()) line += "：" + reason;
            } else {
                continue;
            }
            if (lines.length() > 0) lines.append('\n');
            lines.append(line);
        }
        recentLifecycleSignals.setText(highlightGpuConfirmation(lines.toString()));
        recentLifecycleSignals.setVisibility(lines.length() == 0 ? View.GONE : View.VISIBLE);
    }

    private void showEnvironmentEvidence() {
        if (currentReport == null || !currentReport.optBoolean("environmentAnomaly")) return;
        StringBuilder detail = new StringBuilder("同一进程的 pidfd 仍指示存活，但其 /proc/PID 的 stat 连续复查为 ENOENT，产生环境一致性异常。权限拒绝或正常退出不等同于此异常；此检查独立于 root 候选筛选，不证明进程身份或 GPU 使用。\n\n");
        JSONObject raw = new JSONObject();
        try {
            raw.put("environmentAnomaly", currentReport.optBoolean("environmentAnomaly"));
            raw.put("environmentCheckCoverage", currentReport.opt("environmentCheckCoverage"));
            raw.put("environmentChecks", currentReport.optJSONArray("environmentChecks"));
            detail.append(raw.toString(2));
        } catch (JSONException e) {
            detail.append("原始依据无法解析：").append(e.getMessage());
        }
        TextView text = label(detail.toString(), 12, TEXT, false);
        text.setTextIsSelectable(true);
        text.setPadding(dp(20), dp(16), dp(20), dp(16));
        text.setLineSpacing(dp(3), 1f);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(text);
        new AlertDialog.Builder(this).setTitle("环境异常 · 原始依据")
                .setView(scroll).setPositiveButton("关闭", null).show();
    }

    private void showGlobalGpuEvidence() {
        JSONObject global = currentReport == null ? null : currentReport.optJSONObject("globalGpu");
        String raw = "尚未取得全局 GPU 采样";
        if (global != null) {
            try {
                JSONObject summary = new JSONObject(global.toString());
                summary.remove("slotDeltas");
                summary.remove("slotRetired");
                raw = summary.toString(2);
            } catch (JSONException e) { raw = "全局 GPU 摘要无法解析"; }
        }
        String description = "这些计数仅反映整机 GPU 状态，不能确定提交方 PID、UID 或 root 身份。非零槽可能含驱动内部和保留槽，不等于进程或 GPU 上下文数量。\n"
                + "高频提示按同一用户槽的 retired 计数推进速率统计：每秒至少 "
                + compact(GpuHighFrequency.MIN_RATE_PER_SECOND) + " 次，连续至少 "
                + GpuHighFrequency.MIN_DURATION_MS / 1000 + " 秒；速率单位是计数增量/秒。\n\n" + raw;
        TextView text = label(description, 12, TEXT, false);
        text.setTextIsSelectable(true);
        text.setPadding(dp(20), dp(16), dp(20), dp(16));
        text.setLineSpacing(dp(3), 1f);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(text);
        new AlertDialog.Builder(this).setTitle("全局 GPU 证据 · 归属未知")
                .setView(scroll).setPositiveButton("关闭", null).show();
    }

    private void renderProcesses() {
        if (processList == null) return;
        JSONArray values = currentReport == null ? null : currentReport.optJSONArray("processes");
        List<JSONObject> visible = cpuLeaders(values, currentReport == null ? -1 : currentReport.optInt("collectorPid", -1));
        String title = getString(R.string.candidates_title);
        bindText(listTitle, currentReport == null ? title : getString(R.string.cpu_leaders_title,
                visible.size(), currentReport.optInt("monitoredProcessCount", values == null ? 0 : values.length())));
        if (visible.isEmpty()) {
            clearProcessRows();
            if (emptyProcessCard == null) {
                emptyProcessCard = card();
                emptyProcessTitle = label("", 15, TEXT, true);
                emptyProcessDescription = label("", 12, MUTED, false);
                emptyProcessCard.addView(emptyProcessTitle);
                marginAdd(emptyProcessCard, emptyProcessDescription, 7);
            }
            bindText(emptyProcessTitle, isStartingReport() ? "正在建立采样基线" : currentReport == null
                    ? "等待第一份进程快照" : getString(R.string.no_monitored_candidates));
            bindText(emptyProcessDescription, getString(isStartingReport() ? R.string.collector_starting
                    : R.string.monitored_candidates_description));
            if (emptyProcessCard.getParent() == null) marginAdd(processList, emptyProcessCard, 8);
            return;
        }
        if (emptyProcessCard != null && emptyProcessCard.getParent() == processList) {
            processList.removeView(emptyProcessCard);
        }
        while (processRows.size() > visible.size()) {
            ProcessRow removed = processRows.remove(processRows.size() - 1);
            removed.process = null;
            processList.removeView(removed.item);
        }
        for (int i = 0; i < visible.size(); i++) {
            if (i == processRows.size()) {
                ProcessRow added = new ProcessRow();
                processRows.add(added);
                marginAdd(processList, added.item, 10);
            }
            processRows.get(i).bind(visible.get(i));
        }
    }

    static List<JSONObject> cpuLeaders(JSONArray values, int collectorPid) {
        List<JSONObject> visible = new ArrayList<>();
        if (values != null) {
            for (int i = 0; i < values.length(); i++) {
                JSONObject p = values.optJSONObject(i);
                if (p == null || !isVisibleProcess(p, collectorPid)) continue;
                visible.add(p);
            }
        }
        Collections.sort(visible, (a, b) -> {
            int busy = Double.compare(cpuSortValue(b), cpuSortValue(a));
            if (busy != 0) return busy;
            return Integer.compare(a.optInt("pid"), b.optInt("pid"));
        });
        if (visible.size() > MAX_DISPLAYED_PROCESSES) visible.subList(MAX_DISPLAYED_PROCESSES, visible.size()).clear();
        return visible;
    }

    private void clearProcessRows() {
        for (ProcessRow row : processRows) row.process = null;
        processRows.clear();
        if (processList != null) processList.removeAllViews();
    }

    private static void bindText(TextView view, String value) {
        if (!value.contentEquals(view.getText())) view.setText(value);
    }

    private static void bindColor(TextView view, int color) {
        if (view.getCurrentTextColor() != color) view.setTextColor(color);
    }

    /** One holder per displayed index; the current sorted row replaces its previous binding. */
    private final class ProcessRow {
        final LinearLayout item = card();
        final TextView name = label("", 16, TEXT, true);
        final TextView riskTag = badge("", MUTED);
        final TextView identity = label("", 11, MUTED, false);
        final TextView avcHint = label("", 11, AMBER, false);
        final TextView cpu = label("", 18, TEXT, true);
        final TextView gpuTag = label("", 11, MUTED, false);
        final TextView lifecycleLine = label("", 12, MUTED, false);
        final TextView explanation = label("", 12, MUTED, false);
        JSONObject process;
        int backgroundKind;

        ProcessRow() {
            LinearLayout nameRow = row();
            name.setMaxLines(2);
            nameRow.addView(name, new LinearLayout.LayoutParams(0, -2, 1));
            riskTag.setMaxWidth(dp(150));
            LinearLayout.LayoutParams tagParams = new LinearLayout.LayoutParams(-2, -2);
            tagParams.leftMargin = dp(8);
            nameRow.addView(riskTag, tagParams);
            item.addView(nameRow);
            marginAdd(item, identity, 6);
            avcHint.setMaxLines(2);
            avcHint.setVisibility(View.GONE);
            marginAdd(item, avcHint, 6);
            LinearLayout stats = row();
            stats.addView(cpu, new LinearLayout.LayoutParams(0, -2, 1));
            stats.addView(gpuTag);
            marginAdd(item, stats, 13);
            marginAdd(item, lifecycleLine, 8);
            explanation.setMaxLines(3);
            explanation.setLineSpacing(dp(2), 1f);
            marginAdd(item, explanation, 8);
            item.setOnClickListener(v -> {
                JSONObject current = process;
                if (current != null) showProcess(current);
            });
            item.setFocusable(true);
        }

        void bind(JSONObject p) {
            process = p;
            String risk = p.optString("risk", "UNKNOWN");
            boolean avcRisk = "avc_root_domain_cpu_global_memstore".equals(p.optString("riskBasis"));
            boolean cgroupAnomaly = p.optBoolean("cgroupAnomaly");
            int color = "HIGH".equals(risk) ? RED : "SUSPECT".equals(risk) || "WATCH".equals(risk) ? AMBER : MUTED;
            int nextBackground = "HIGH".equals(risk) ? 1 : "SUSPECT".equals(risk) ? 2 : 0;
            if (nextBackground != backgroundKind) {
                item.setBackground(nextBackground == 1 ? shape(Color.rgb(43, 30, 35), Color.rgb(111, 54, 65), 16)
                        : nextBackground == 2 ? shape(Color.rgb(43, 37, 27), Color.rgb(98, 80, 48), 16)
                        : shape(SURFACE, BORDER, 16));
                backgroundKind = nextBackground;
            }
            String pidLabel = "PID " + p.optInt("pid");
            String processName = p.optString("name", "").trim();
            if (processName.isEmpty()) processName = pidLabel;
            bindText(name, processName);
            bindText(riskTag, riskName(risk));
            bindColor(riskTag, color);
            String identityText = processName.equals(pidLabel) ? "" : pidLabel;
            int uid = p.optInt("uid", -1);
            if (uid >= 0) identityText += (identityText.isEmpty() ? "" : "  ·  ") + "UID " + uid;
            String background = backgroundName(p.optString("background"));
            if (!background.isEmpty()) identityText += (identityText.isEmpty() ? "" : "  ·  ") + background;
            bindText(identity, identityText);
            int identityVisibility = identityText.isEmpty() ? View.GONE : View.VISIBLE;
            if (identity.getVisibility() != identityVisibility) identity.setVisibility(identityVisibility);
            String avcContext = p.optString("avcTargetContext", "");
            boolean showAvcHint = !avcContext.isEmpty();
            bindText(avcHint, showAvcHint ? "AVC 域 · " + avcContext : "");
            int avcVisibility = showAvcHint ? View.VISIBLE : View.GONE;
            if (avcHint.getVisibility() != avcVisibility) avcHint.setVisibility(avcVisibility);
            bindText(cpu, "CPU  " + MainActivity.cpu(p.optDouble("cpuPercent", -1)));
            bindColor(cpu, "HIGH".equals(risk) ? RED : TEXT);
            String gpu = p.optBoolean("gpuActive") ? "该进程 GPU 有活动" : p.optBoolean("gpuDeviceOpen") ? "GPU 客户端已确认" : "";
            bindText(gpuTag, gpu);
            bindColor(gpuTag, p.optBoolean("gpuDeviceOpen") ? ACCENT : MUTED);
            int gpuVisibility = gpu.isEmpty() ? View.GONE : View.VISIBLE;
            if (gpuTag.getVisibility() != gpuVisibility) gpuTag.setVisibility(gpuVisibility);
            JSONObject lifecycle = p.optJSONObject("cpuGpuLifecycle");
            boolean onsetMatch = lifecycle != null && "ONSET_MATCH".equals(lifecycle.optString("state"));
            bindText(lifecycleLine, getString(R.string.lifecycle_association_line, lifecycleSummary(lifecycle)));
            bindColor(lifecycleLine, onsetMatch ? RED : MUTED);
            int lifecycleVisibility = isRootCandidate(p) || cgroupAnomaly ? View.VISIBLE : View.GONE;
            if (lifecycleLine.getVisibility() != lifecycleVisibility) lifecycleLine.setVisibility(lifecycleVisibility);
            String reason = avcRisk ? "AVC 指向 root 执行域、CPU 持续高占用且全局 GPU 计数推进，触发组合风险告警。"
                    : cgroupAnomaly && !isRootCandidate(p) ? getString(R.string.cgroup_anomaly_description)
                    : p.optString("reason", "等待进一步采样");
            reason = reason.replace("按进程 GPU 归属未确认。", "").trim();
            if (cgroupAnomaly) {
                String anomalyReason = getString(R.string.cgroup_anomaly_monitoring);
                JSONObject watch = p.optJSONObject("cgroupWatch");
                if (watch != null) {
                    anomalyReason += " · " + getString(R.string.cgroup_anomaly_stable, watch.optInt("consecutive"));
                }
                reason = anomalyReason + "\n" + reason;
            }
            bindText(explanation, reason);
            bindColor(explanation, cgroupAnomaly ? AMBER : MUTED);
            String description = p.optString("name") + "，" + riskName(risk)
                    + (cgroupAnomaly ? "，" + getString(R.string.cgroup_anomaly_monitoring) : "")
                    + "，点击查看进程证据";
            if (!description.contentEquals(item.getContentDescription() == null ? "" : item.getContentDescription()))
                item.setContentDescription(description);
        }
    }

    private void showProcess(JSONObject p) {
        StringBuilder detail = new StringBuilder();
        detail.append("风险：").append(riskName(p.optString("risk"))).append('\n');
        detail.append(p.optString("reason", "")).append("\n\n");
        if (p.has("riskBasis")) detail.append("风险依据类型：").append(p.optString("riskBasis")).append('\n');
        if (p.has("riskConfidence")) {
            String confidence = p.optString("riskConfidence");
            detail.append("风险判断性质：").append("heuristic".equals(confidence) ? "启发式告警，需进一步核查" : confidence).append('\n');
        }
        if (p.has("gpuAttribution")) {
            String attribution = p.optString("gpuAttribution");
            detail.append("GPU 归属范围：").append("global_unattributed".equals(attribution) ? "全局活动，尚未归属此 PID" : attribution).append('\n');
        }
        detail.append('\n');
        detail.append("PID：").append(p.optInt("pid")).append('\n');
        int uid = p.optInt("uid", -1);
        if (uid >= 0) detail.append("有效 UID：").append(uid).append('\n');
        String uidIdentity = uid == 0 ? "有效 UID 已确认为 0" : uid < 0 ? "" : "已知有效 UID 非 0";
        if (uid < 0 && isRootCandidate(p)
                && (p.optBoolean("avcRootDomainHint") || "avc_root_domain_cpu_global_memstore".equals(p.optString("riskBasis")))) {
            uidIdentity = "AVC 目标域为 " + avcDomain(p) + "（域证据），有效 UID 未读取";
        }
        if (!uidIdentity.isEmpty()) detail.append("进程身份依据：").append(uidIdentity).append('\n');
        detail.append("CPU（单核口径）：").append(cpu(p.optDouble("cpuPercent", -1))).append('\n');
        detail.append("连续高负载命中：").append(p.optInt("consecutiveHigh")).append(" 次\n");
        appendCgroupEvidence(detail, p);
        JSONObject lifecycle = p.optJSONObject("cpuGpuLifecycle");
        detail.append("\n进程启停关联：").append(lifecycleSummary(lifecycle)).append('\n');
        if (lifecycle != null) {
            detail.append("观察进程 PID：").append(lifecycle.optInt("pid", p.optInt("pid"))).append('\n');
            detail.append("候选槽：").append(lifecycleSlots(lifecycle)).append('\n');
            detail.append("身份标识：").append(lifecycle.optString("identityToken", "未提供")).append('\n');
            if (lifecycle.has("observedMonotonicNs")) {
                detail.append("观察时刻（单调纳秒）：").append(lifecycle.optLong("observedMonotonicNs")).append('\n');
            }
            detail.append("时序判定原因：").append(lifecycle.optString("reason", "未提供原因")).append('\n');
        }
        detail.append("生命周期时序吻合仍是间接线索，GPU 槽所有权未确认。\n\n");
        boolean metadataAvailable = p.optBoolean("metadataAccessible", true);
        detail.append("常驻内存：").append(!metadataAvailable || p.optLong("rssKb", -1) < 0 ? "未知" : compact(p.optLong("rssKb") / 1024.0) + " MiB").append('\n');
        detail.append("线程数：").append(!metadataAvailable || p.optInt("threads", -1) < 0 ? "未知" : Integer.toString(p.optInt("threads"))).append('\n');
        detail.append("启动时间标识：").append(p.optLong("startTimeTicks", 0) <= 0 ? "不可读取" : p.optLong("startTimeTicks") + " ticks").append("\n\n");
        if (p.has("identityVerified")) {
            detail.append("进程连续身份：").append(p.optBoolean("identityVerified") ? "已核验" : "尚未核验").append('\n');
            detail.append("身份核验来源：").append(p.optString("identitySource", "未知")).append('\n');
            detail.append("CPU 数据来源：").append(p.optString("cpuSource", "未知")).append("\n\n");
        }
        String background = backgroundName(p.optString("background"));
        if (!background.isEmpty()) {
            detail.append("后台状态：").append(background).append('\n');
            detail.append(p.optString("backgroundReason", "")).append("\n\n");
        }
        detail.append("AVC 目标安全上下文：").append(p.optString("avcTargetContext").isEmpty() ? "未知" : p.optString("avcTargetContext")).append('\n');
        JSONArray avcEvidence = p.optJSONArray("avcEvidence");
        if (avcEvidence != null && avcEvidence.length() > 0) {
            detail.append("原始 AVC 拒绝日志（应用自身可读取）：\n");
            for (int i = 0; i < avcEvidence.length(); i++) detail.append("• ").append(avcEvidence.optString(i)).append('\n');
        } else if (p.opt("avcEvidence") instanceof String && !p.optString("avcEvidence").isEmpty()) {
            detail.append("原始 AVC 拒绝日志（应用自身可读取）：\n").append(p.optString("avcEvidence")).append('\n');
        }
        detail.append('\n');
        detail.append("GPU 设备句柄：").append(p.optBoolean("gpuDeviceOpen") ? "已发现" : "未确认").append('\n');
        detail.append("GPU 采样期间活动：").append(p.optBoolean("gpuActive") ? "计数存在增量" : p.optBoolean("gpuCountersAvailable") ? "窗口内未观察到活动" : "未知（无可用的按进程计数）").append('\n');
        detail.append("GPU 证据扫描：").append(!p.has("gpuScanComplete") ? "未报告完整性" : p.optBoolean("gpuScanComplete") ? "已完整读取" : "读取不完整").append('\n');
        detail.append("按进程 GPU 证据：\n");
        JSONArray evidence = p.optJSONArray("gpuEvidence");
        if (evidence == null || evidence.length() == 0) detail.append("未取得\n");
        else for (int i = 0; i < evidence.length(); i++) detail.append("• ").append(evidence.optString(i)).append('\n');
        JSONArray errors = p.optJSONArray("errors");
        if (errors != null && errors.length() > 0) {
            detail.append("\n此进程的采集限制：\n");
            for (int i = 0; i < errors.length(); i++) detail.append("• ").append(errors.optString(i)).append('\n');
        }
        detail.append("\n可执行文件：\n").append(p.optString("exe").isEmpty() ? "不可读取" : p.optString("exe")).append("\n\n");
        detail.append("命令行：\n").append(p.optString("cmdline").isEmpty() ? "不可读取" : p.optString("cmdline")).append("\n\n");
        TextView text = label(detail.toString(), 13, TEXT, false);
        text.setText(highlightGpuConfirmation(detail.toString()));
        text.setTextIsSelectable(true);
        text.setLineSpacing(dp(3), 1f);
        text.setPadding(dp(22), dp(16), dp(22), dp(20));
        ScrollView scroll = new ScrollView(this);
        scroll.addView(text);
        new AlertDialog.Builder(this).setTitle(p.optString("name", "进程详情"))
                .setView(scroll).setPositiveButton("关闭", null)
                .setNeutralButton("原始记录", (dialog, which) -> showRawProcess(p)).show();
    }

    private void appendCgroupEvidence(StringBuilder detail, JSONObject process) {
        JSONObject check = process.optJSONObject("cgroupCheck");
        JSONObject watch = process.optJSONObject("cgroupWatch");
        if (check == null && watch == null) return;
        detail.append("\ncgroup 路径探测：");
        if (process.optBoolean("cgroupAnomaly")) {
            detail.append(getString(R.string.cgroup_anomaly_monitoring));
        } else if (check != null && "PRESENT".equals(check.optString("state"))) {
            detail.append("已匹配参考命名路径");
        } else if (check != null && "EXITED".equals(check.optString("state"))) {
            detail.append("进程已退出");
        } else if (watch != null && "PENDING".equals(watch.optString("status"))) {
            detail.append("连续复查中");
        } else {
            detail.append("证据不可用");
        }
        detail.append('\n');
        if (watch != null) {
            detail.append("连续路径未匹配：").append(watch.optInt("consecutive"))
                    .append(" 次（确认需 ").append(watch.optInt("required", 3)).append(" 次）\n");
            detail.append("监听判定说明：").append(watch.optString("reason", "未提供")).append('\n');
        }
        if (check != null) {
            detail.append("进程目录存在：").append(evidenceFlag(check, "procPresent")).append('\n');
            detail.append("进程身份连续：").append(evidenceFlag(check, "stableIdentity")).append('\n');
            detail.append("非僵尸进程：").append(evidenceFlag(check, "nonZombie")).append('\n');
            detail.append("路径对照校准有效：").append(evidenceFlag(check, "pathCalibrationValid")).append('\n');
            detail.append("选定路径已探测完成：").append(evidenceFlag(check, "pathCoverageComplete")).append('\n');
            detail.append("本轮 UID 范围已覆盖：").append(evidenceFlag(check, "uidCoverageComplete")).append('\n');
            detail.append("路径范围：").append("observed_uid_catalog".equals(check.optString("coverageScope"))
                    ? "已观察到的 UID 目录" : check.optString("coverageScope", "未提供")).append('\n');
            detail.append("本次探测：").append(check.optInt("testedUidCount")).append(" 个 UID，")
                    .append(check.optInt("testedPathCount")).append(" 条路径，")
                    .append(check.optInt("missingPathCount")).append(" 条未匹配\n");
            detail.append("找到路径匹配：").append(evidenceFlag(check, "pathFound")).append('\n');
            JSONObject proc = check.optJSONObject("procEvidence");
            if (proc != null) {
                if (process.optInt("pid", -1) > 0) {
                    detail.append("实际 proc 路径：/proc/").append(process.optInt("pid")).append('\n');
                }
                if (proc.has("method")) detail.append("proc 探测方式：").append(proc.optString("method")).append('\n');
                if (proc.has("beforeErrno")) detail.append("探测前 errno：").append(proc.optInt("beforeErrno")).append('\n');
                if (proc.has("afterErrno")) detail.append("探测后 errno：").append(proc.optInt("afterErrno")).append('\n');
                detail.append("探测前 / 后 pidfd 存活：").append(evidenceFlag(proc, "pidfdLiveBefore"))
                        .append(" / ").append(evidenceFlag(proc, "pidfdLiveAfter")).append('\n');
            }
            JSONArray probes = check.optJSONArray("paths");
            if (probes != null && probes.length() > 0) {
                detail.append("实际 cgroup 路径与返回值：\n");
                for (int i = 0; i < probes.length(); i++) appendPathProbe(detail, "•", probes.optJSONObject(i));
            }
            if (check.optBoolean("pathsTruncated")) detail.append("路径证据仅展开部分条目；总量见本次探测计数。\n");
            detail.append("检查说明：").append(check.optString("reason", "未提供")).append('\n');
            if (check.has("sampleIndex")) detail.append("检查采样序号：").append(check.optLong("sampleIndex")).append('\n');
        }
        JSONObject scan = cgroupPathScan();
        if (scan != null) {
            detail.append("\n路径探测校准有效：").append(evidenceFlag(scan, "calibrationValid")).append('\n');
            JSONArray procControls = scan.optJSONArray("procControls");
            for (int i = 0; procControls != null && i < procControls.length(); i++) {
                appendPathProbe(detail, "proc 路径对照", procControls.optJSONObject(i));
            }
            JSONArray layouts = scan.optJSONArray("layouts");
            for (int i = 0; layouts != null && i < layouts.length(); i++) {
                JSONObject layout = layouts.optJSONObject(i);
                if (layout == null) continue;
                detail.append("cgroup 布局：").append(layout.optString("root", "未提供"))
                        .append(" · 启用：").append(evidenceFlag(layout, "active"))
                        .append(" · 校准有效：").append(evidenceFlag(layout, "calibrated")).append('\n');
                JSONArray controls = layout.optJSONArray("controls");
                for (int n = 0; controls != null && n < controls.length(); n++) {
                    JSONObject control = controls.optJSONObject(n);
                    if (control != null) appendPathProbe(detail, "路径对照", control);
                }
            }
            JSONObject catalog = scan.optJSONObject("uidCatalog");
            if (catalog != null) {
                detail.append("UID 目录覆盖范围：").append("observed_uid_catalog".equals(catalog.optString("scope"))
                        ? "已观察到的 UID 目录" : catalog.optString("scope", "未提供")).append('\n');
                detail.append("已观察 UID 目录数：").append(catalog.optInt("uidCount"))
                        .append(" · 编目完成：").append(evidenceFlag(catalog, "complete")).append('\n');
                detail.append("已探测 UID 数字范围：").append(uidRanges(catalog.optJSONArray("ranges"))).append('\n');
                if (catalog.has("generation")) detail.append("目录编目代次：").append(catalog.optLong("generation")).append('\n');
                if (catalog.has("ageMs")) detail.append("目录编目距今：").append(catalog.optLong("ageMs")).append(" ms\n");
                if (check != null && check.has("uidCatalogGeneration")) {
                    detail.append("本进程使用的编目代次：").append(check.optLong("uidCatalogGeneration")).append('\n');
                }
            }
        }
        detail.append("这里只核对参考命名的 UID/PID 目录；已探测路径未匹配不等于没有内核 cgroup 归属。")
                .append("该线索独立于 CPU，不能据此认定 root 身份或 GPU 使用。\n");
    }

    private static void appendPathProbe(StringBuilder detail, String label, JSONObject probe) {
        if (probe == null) return;
        detail.append(label).append("：").append(probe.optString("path", "未提供路径"));
        if (probe.has("returnCode")) detail.append(" · 返回值=").append(probe.optInt("returnCode"));
        if (probe.has("errno")) detail.append(" · errno=").append(probe.optInt("errno"));
        if (probe.has("result")) detail.append(" · ").append(probe.optString("result"));
        detail.append('\n');
    }

    private static String uidRanges(JSONArray ranges) {
        StringBuilder text = new StringBuilder();
        for (int i = 0; ranges != null && i < ranges.length(); i++) {
            JSONObject range = ranges.optJSONObject(i);
            if (range == null) continue;
            String first = range.has("start") ? "start" : "first";
            String last = range.has("end") ? "end" : "last";
            if (!range.has(first) || !range.has(last)) continue;
            if (text.length() > 0) text.append("、");
            text.append(range.optLong(first)).append('–').append(range.optLong(last));
        }
        return text.length() == 0 ? "未提供" : text.toString();
    }

    private static String evidenceFlag(JSONObject evidence, String key) {
        return !evidence.has(key) || evidence.isNull(key) ? "未知" : evidence.optBoolean(key) ? "是" : "否";
    }

    private void showRawProcess(JSONObject p) {
        String content;
        try { content = p.toString(2); } catch (JSONException e) { content = p.toString(); }
        TextView text = label(content, 11, TEXT, false);
        text.setTypeface(Typeface.MONOSPACE);
        text.setTextIsSelectable(true);
        text.setPadding(dp(20), dp(16), dp(20), dp(16));
        ScrollView scroll = new ScrollView(this);
        scroll.addView(text);
        new AlertDialog.Builder(this).setTitle("进程原始记录").setView(scroll).setPositiveButton("关闭", null).show();
    }

    private static double cpuSortValue(JSONObject process) {
        double value = process.optDouble("cpuPercent", -1);
        return Double.isFinite(value) && value >= 0 ? value : -1;
    }

    private static boolean isRootCandidate(JSONObject process) {
        return RootProcessFilter.accepts(process.optInt("uid", -1),
                process.optBoolean("identityVerified"), process.optString("identityToken", ""),
                process.optBoolean("avcRootDomainHint"), process.optString("avcTargetContext", ""),
                process.optString("avcIdentityToken", ""));
    }

    private static boolean isVisibleProcess(JSONObject process, int collectorPid) {
        int pid = process.optInt("pid", -1);
        boolean self = MonitoredProcessFilter.isSelf(pid, process.optInt("uid", -1), collectorPid,
                android.os.Process.myPid(), android.os.Process.myUid());
        return MonitoredProcessFilter.acceptsCpu(pid, self);
    }

    private String lifecycleSummary(JSONObject lifecycle) {
        if (lifecycle == null) return getString(R.string.lifecycle_no_evidence);
        switch (lifecycle.optString("state", "NO_EVIDENCE")) {
            case "ONSET_MATCH": return getString(R.string.gpu_overlay_confirmed);
            case "AMBIGUOUS": return getString(R.string.lifecycle_onset_ambiguous);
            case "PENDING": return getString(R.string.lifecycle_pending);
            default: return getString(R.string.lifecycle_no_evidence);
        }
    }

    private CharSequence highlightGpuConfirmation(String value) {
        SpannableString highlighted = new SpannableString(value);
        String confirmation = getString(R.string.gpu_overlay_confirmed);
        int start = value.indexOf(confirmation);
        while (start >= 0) {
            highlighted.setSpan(new ForegroundColorSpan(RED), start, start + confirmation.length(),
                    Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            start = value.indexOf(confirmation, start + confirmation.length());
        }
        return highlighted;
    }

    private static String lifecycleSlots(JSONObject lifecycle) {
        JSONArray slots = lifecycle.optJSONArray("slots");
        List<Integer> values = new ArrayList<>();
        for (int i = 0; slots != null && i < slots.length(); i++) {
            int slot = slots.optInt(i, -1);
            if (slot >= 0 && !values.contains(slot)) values.add(slot);
        }
        Collections.sort(values);
        StringBuilder result = new StringBuilder();
        for (int slot : values) {
            if (result.length() > 0) result.append("、");
            result.append(slot);
        }
        return result.length() == 0 ? "待核实" : result.toString();
    }

    private String riskName(String risk) {
        if ("MONITORING".equals(risk)) return "CPU 监听";
        if ("HIGH".equals(risk)) return "高风险 · 需核查";
        if ("SUSPECT".equals(risk)) return "高风险线索 · 归属待核实";
        if ("WATCH".equals(risk)) return "待观察";
        if ("LOW".equals(risk)) return "未命中";
        return "证据不足";
    }

    private String backgroundName(String value) {
        if ("background".equals(value)) return "后台 / 推定后台";
        if ("foreground".equals(value)) return "前台";
        return "";
    }

    private static String uidText(int uid) { return uid < 0 ? "未知" : Integer.toString(uid); }
    private static String avcDomain(JSONObject process) {
        String domain = process.optString("avcTargetDomain", "");
        if (!domain.isEmpty()) return domain;
        String[] context = process.optString("avcTargetContext", "").split(":");
        return context.length > 2 && !context[2].isEmpty() ? context[2] : "未知";
    }

    private static String cpu(double value) {
        if (value < 0 || !Double.isFinite(value)) return "—";
        if (value > 0 && value < 0.1) return "<0.1%";
        return String.format(Locale.US, "%.1f%%", value);
    }
    private static String compact(double value) { return value == Math.rint(value) ? String.format(Locale.US, "%.0f", value) : String.format(Locale.US, "%.1f", value); }
    private int dp(float value) { return Math.round(value * getResources().getDisplayMetrics().density); }
    private LinearLayout vertical() { LinearLayout layout = new LinearLayout(this); layout.setOrientation(LinearLayout.VERTICAL); return layout; }
    private LinearLayout row() { LinearLayout layout = new LinearLayout(this); layout.setOrientation(LinearLayout.HORIZONTAL); layout.setGravity(Gravity.CENTER_VERTICAL); return layout; }
    private TextView label(String value, int size, int color, boolean bold) {
        TextView text = new TextView(this);
        text.setText(value);
        text.setTextColor(color);
        text.setTextSize(size);
        text.setFontFeatureSettings("tnum");
        if (bold) text.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        return text;
    }
    private LinearLayout card() {
        LinearLayout card = vertical();
        card.setPadding(dp(18), dp(17), dp(18), dp(17));
        card.setBackground(shape(SURFACE, BORDER, 16));
        return card;
    }
    private TextView badge(String text, int color) {
        TextView badge = label(text, 10, color, true);
        badge.setPadding(dp(9), dp(5), dp(9), dp(5));
        badge.setBackground(shape(BG, BORDER, 16));
        badge.setGravity(Gravity.CENTER);
        return badge;
    }
    private TextView metric(LinearLayout parent, String title) {
        LinearLayout column = vertical();
        TextView value = label("—", 23, TEXT, true);
        column.addView(value);
        marginAdd(column, label(title, 10, MUTED, false), 5);
        parent.addView(column, new LinearLayout.LayoutParams(0, -2, 1));
        return value;
    }
    private Button button(String text, boolean primary) {
        Button button = new Button(this);
        button.setText(text);
        button.setAllCaps(false);
        button.setTextSize(14);
        button.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        button.setTextColor(primary ? BG : TEXT);
        button.setBackground(shape(primary ? ACCENT : SURFACE, primary ? ACCENT : BORDER, 11));
        button.setPadding(dp(8), 0, dp(8), 0);
        button.setMinHeight(0);
        button.setMinimumHeight(0);
        button.setStateListAnimator(null);
        return button;
    }
    private GradientDrawable shape(int fill, int stroke, int radius) {
        GradientDrawable shape = new GradientDrawable();
        shape.setColor(fill);
        shape.setCornerRadius(dp(radius));
        shape.setStroke(dp(1), stroke);
        return shape;
    }
    private void marginAdd(LinearLayout parent, View view, int top) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(-1, -2);
        params.topMargin = dp(top);
        parent.addView(view, params);
    }
}
