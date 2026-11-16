package com.gpucheck.app;

import android.app.Activity;
import android.content.Intent;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.text.SpannableString;
import android.text.Spanned;
import android.text.TextUtils;
import android.text.style.ForegroundColorSpan;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.WindowInsets;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.ImageView;
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
    private static final int BG = Color.rgb(8, 12, 19);
    private static final int SURFACE = Color.rgb(16, 25, 36);
    private static final int BORDER = Color.rgb(38, 50, 66);
    private static final int TEXT = Color.rgb(243, 245, 247);
    private static final int MUTED = Color.rgb(155, 169, 187);
    private static final int ACCENT = Color.rgb(214, 245, 139);
    private static final int CYAN = Color.rgb(128, 216, 235);
    private static final int RED = Color.rgb(255, 119, 125);
    private static final int AMBER = Color.rgb(246, 200, 121);

    private final LinearLayout[] pages = new LinearLayout[3];
    private final Button[] pageTabs = new Button[3];
    private final int[] pageScrollPositions = new int[3];
    private ScrollView workspaceScroll;
    private TextView pageTitle;
    private TextView pageSubtitle;
    private TextView sessionCaption;
    private TextView alertRibbon;
    private TextView overviewGpuStatus;
    private TextView overviewOverlayStatus;
    private TextView evidenceSessionStatus;
    private TextView oemProcessStatus;
    private SignalRadarView signalRadar;
    private int selectedPage;
    private int controlAppearance = -1;

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
    private TextView gpuExecStatus;
    private TextView gpuExecRows;
    private TextView gpuFrequencyWarning;
    private TextView environmentSummary;
    private TextView recentLifecycleSignals;
    private TextView overlayStatus;
    private TextView overlayNames;
    private LinearLayout overlayCard;
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
    private long gpuFrequencyReceivedAtMs;
    private boolean monitorStopRequested;

    private final Handler refreshHandler = new Handler(Looper.getMainLooper());
    private final Runnable refreshLoop = new Runnable() {
        @Override public void run() {
            if (!refreshActive) return;
            renderLatest();
            refreshHandler.postDelayed(this, 250);
        }
    };

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().setStatusBarColor(BG);
        getWindow().setNavigationBarColor(BG);
        MonitorService.clearPreviousResults(this);
        if (state != null) {
            selectedPage = Math.max(0, Math.min(2, state.getInt("selectedPage", 0)));
            int[] positions = state.getIntArray("pageScrollPositions");
            if (positions != null && positions.length == 3) System.arraycopy(positions, 0, pageScrollPositions, 0, 3);
        }
        buildUi();
        renderLatest();
    }

    @Override protected void onSaveInstanceState(Bundle state) {
        pageScrollPositions[selectedPage] = workspaceScroll.getScrollY();
        state.putInt("selectedPage", selectedPage);
        state.putIntArray("pageScrollPositions", pageScrollPositions);
        super.onSaveInstanceState(state);
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
        clearGpuFrequencyWarning();
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
            updateOverlayStatus();
            updateGpuExecStatus();
            updateGpuFrequencyStatus();
        }
        super.onStop();
    }

    private void buildUi() {
        boolean compactChrome = getResources().getConfiguration().screenHeightDp < 480
                || getResources().getConfiguration().fontScale >= 1.6f;
        LinearLayout frame = vertical();
        frame.setGravity(Gravity.CENTER_HORIZONTAL);
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
        LinearLayout workspace = vertical();
        int width = getResources().getConfiguration().screenWidthDp >= 800 ? dp(760) : -1;
        frame.addView(workspace, new LinearLayout.LayoutParams(width, -1));
        setContentView(frame);

        LinearLayout heading = row();
        heading.setPadding(dp(20), dp(14), dp(20), dp(14));
        ImageView logo = new ImageView(this);
        logo.setImageResource(R.drawable.ic_observatory);
        logo.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        heading.addView(logo, new LinearLayout.LayoutParams(dp(36), dp(36)));
        LinearLayout brand = vertical();
        TextView wordmark = label("GPU CHECK", 17, TEXT, true);
        wordmark.setLetterSpacing(0.08f);
        brand.addView(wordmark);
        marginAdd(brand, mono("SIGNAL OBSERVATORY", 9, MUTED), 3);
        LinearLayout.LayoutParams brandParams = new LinearLayout.LayoutParams(0, -2, 1);
        brandParams.leftMargin = dp(10);
        heading.addView(brand, brandParams);
        stateBadge = badge("待机", MUTED);
        heading.addView(stateBadge);
        if (compactChrome) heading.setVisibility(View.GONE);
        workspace.addView(heading);

        LinearLayout navigation = row();
        navigation.setPadding(dp(4), dp(4), dp(4), dp(4));
        navigation.setBackground(shape(SURFACE, BORDER, 16));
        String[] tabs = {"01  总览", "02  进程", "03  证据"};
        for (int i = 0; i < tabs.length; i++) {
            final int index = i;
            Button tab = button(tabs[i], false);
            tab.setTextSize(12);
            tab.setMinHeight(dp(44));
            tab.setPadding(dp(4), dp(8), dp(4), dp(8));
            tab.setOnClickListener(v -> selectPage(index));
            pageTabs[i] = tab;
            navigation.addView(tab, new LinearLayout.LayoutParams(0, -2, 1));
        }
        LinearLayout.LayoutParams navigationParams = new LinearLayout.LayoutParams(-1, -2);
        navigationParams.setMargins(dp(20), compactChrome ? dp(8) : 0, dp(20), dp(2));
        workspace.addView(navigation, navigationParams);

        alertRibbon = label("", 12, RED, true);
        alertRibbon.setPadding(dp(16), dp(12), dp(16), dp(12));
        alertRibbon.setMinHeight(dp(48));
        alertRibbon.setBackground(shape(Color.rgb(42, 24, 32), Color.rgb(94, 48, 59), 12));
        alertRibbon.setVisibility(View.GONE);
        alertRibbon.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        alertRibbon.setOnClickListener(v -> openPriorityEvidence());
        alertRibbon.setFocusable(true);
        LinearLayout.LayoutParams alertParams = new LinearLayout.LayoutParams(-1, -2);
        alertParams.setMargins(dp(20), dp(8), dp(20), 0);
        if (!compactChrome) workspace.addView(alertRibbon, alertParams);

        workspaceScroll = new ScrollView(this);
        workspaceScroll.setFillViewport(true);
        workspaceScroll.setClipToPadding(false);
        workspaceScroll.setVerticalScrollBarEnabled(false);
        LinearLayout page = vertical();
        page.setPadding(dp(20), dp(24), dp(20), dp(28));
        workspaceScroll.addView(page, new ScrollView.LayoutParams(-1, -2));
        workspace.addView(workspaceScroll, new LinearLayout.LayoutParams(-1, 0, 1));

        if (compactChrome) {
            LinearLayout.LayoutParams scrollAlertParams = new LinearLayout.LayoutParams(-1, -2);
            scrollAlertParams.bottomMargin = dp(18);
            page.addView(alertRibbon, scrollAlertParams);
        }
        TextView device = mono((compactChrome ? "GPU CHECK  /  ANDROID " : "ON DEVICE  /  ANDROID ")
                + Build.VERSION.RELEASE, 10, CYAN);
        device.setLetterSpacing(0.1f);
        page.addView(device);
        pageTitle = label("信号总览", 30, TEXT, true);
        if (Build.VERSION.SDK_INT >= 28) pageTitle.setAccessibilityHeading(true);
        marginAdd(page, pageTitle, 7);
        pageSubtitle = label("从进程到图层，让异常信号浮出水面。", 12, MUTED, false);
        pageSubtitle.setLineSpacing(dp(3), 1f);
        marginAdd(page, pageSubtitle, 6);
        for (int i = 0; i < pages.length; i++) {
            pages[i] = vertical();
            marginAdd(page, pages[i], 22);
        }
        buildOverview(pages[0]);
        buildProcesses(pages[1]);
        buildEvidence(pages[2]);

        View divider = new View(this);
        divider.setBackgroundColor(BORDER);
        workspace.addView(divider, new LinearLayout.LayoutParams(-1, dp(1)));
        LinearLayout controls = vertical();
        controls.setPadding(dp(20), dp(10), dp(20), dp(10));
        controls.setBackgroundColor(BG);
        sessionCaption = mono("SESSION / 等待开始", 10, MUTED);
        sessionCaption.setGravity(Gravity.CENTER);
        if (compactChrome) sessionCaption.setVisibility(View.GONE);
        controls.addView(sessionCaption, new LinearLayout.LayoutParams(-1, -2));
        startButton = button("开始检测", true);
        startButton.setTextSize(16);
        startButton.setMinHeight(dp(52));
        startButton.setPadding(dp(20), dp(12), dp(20), dp(12));
        startButton.setOnClickListener(v -> toggleMonitor());
        marginAdd(controls, startButton, compactChrome ? 0 : 8);
        TextView local = label("界面可见时采样  ·  停止即清空", 10, MUTED, false);
        local.setGravity(Gravity.CENTER);
        if (compactChrome) local.setVisibility(View.GONE);
        marginAdd(controls, local, 7);
        workspace.addView(controls);
        applyPageSelection();
        workspaceScroll.post(() -> workspaceScroll.scrollTo(0, pageScrollPositions[selectedPage]));
    }

    private void buildOverview(LinearLayout page) {
        hero = card();
        hero.setPadding(dp(20), dp(20), dp(20), dp(20));
        hero.setBackground(heroBackground(BORDER));
        TextView eyebrow = mono("LIVE SIGNAL / 实时风险", 10, ACCENT);
        eyebrow.setLetterSpacing(0.12f);
        hero.addView(eyebrow);
        LinearLayout summary = row();
        LinearLayout number = vertical();
        riskCount = mono("—", 68, TEXT);
        riskCount.setIncludeFontPadding(false);
        riskCount.setMaxLines(1);
        riskCount.setAutoSizeTextTypeUniformWithConfiguration(22, 68, 1, TypedValue.COMPLEX_UNIT_SP);
        number.addView(riskCount, new LinearLayout.LayoutParams(-1, dp(86)));
        marginAdd(number, label("高风险进程", 12, MUTED, false), 4);
        summary.addView(number, new LinearLayout.LayoutParams(0, -2, 1));
        signalRadar = new SignalRadarView(this);
        if (getResources().getConfiguration().screenWidthDp < 350
                || getResources().getConfiguration().fontScale > 1.4f) {
            signalRadar.setVisibility(View.GONE);
        }
        summary.addView(signalRadar, new LinearLayout.LayoutParams(dp(116), dp(116)));
        marginAdd(hero, summary, 16);
        heroStatus = label("等待开始检测", 18, TEXT, true);
        marginAdd(hero, heroStatus, 16);
        heroDescription = label("检测界面可见期间采样，无需任何授权。", 12, MUTED, false);
        heroDescription.setLineSpacing(dp(3), 1f);
        marginAdd(hero, heroDescription, 8);
        View rule = new View(this);
        rule.setBackgroundColor(BORDER);
        LinearLayout.LayoutParams ruleParams = new LinearLayout.LayoutParams(-1, dp(1));
        ruleParams.topMargin = dp(18);
        ruleParams.bottomMargin = dp(12);
        hero.addView(rule, ruleParams);
        watchSummary = label(getString(R.string.monitoring_summary, 0, 0, 0), 11, MUTED, false);
        watchSummary.setLineSpacing(dp(2), 1f);
        hero.addView(watchSummary);
        page.addView(hero);

        boolean stackMetrics = getResources().getConfiguration().fontScale > 1.25f
                || getResources().getConfiguration().screenWidthDp < 340;
        LinearLayout metrics = stackMetrics ? vertical() : row();
        metrics.setGravity(Gravity.TOP);
        candidateMetric = metric(metrics, getString(R.string.monitored_processes_metric), "PROC", ACCENT);
        gpuMetric = metric(metrics, "按进程 GPU 证据", "GPU", CYAN);
        cpuMetric = metric(metrics, "最高 CPU", "CPU", TEXT);
        marginAdd(page, metrics, 12);

        marginAdd(page, sectionHeading("检测通道", "SIGNAL CHANNELS"), 26);
        gpuFrequencyWarning = label("", 16, RED, true);
        gpuFrequencyWarning.setLineSpacing(dp(3), 1f);
        gpuFrequencyWarning.setPadding(dp(18), dp(18), dp(18), dp(18));
        gpuFrequencyWarning.setBackground(shape(Color.rgb(42, 24, 32), RED, 18));
        gpuFrequencyWarning.setVisibility(View.GONE);
        gpuFrequencyWarning.setOnClickListener(v -> showGpuFrequencyEvidence());
        gpuFrequencyWarning.setFocusable(true);
        marginAdd(page, gpuFrequencyWarning, 12);

        environmentCard = card();
        environmentCard.setBackground(shape(Color.rgb(42, 24, 32), Color.rgb(94, 48, 59), 18));
        environmentCard.addView(mono("ALERT / 环境一致性", 10, RED));
        marginAdd(environmentCard, label(getString(R.string.environment_anomaly), 17, RED, true), 10);
        environmentSummary = label("", 12, TEXT, false);
        environmentSummary.setLineSpacing(dp(3), 1f);
        marginAdd(environmentCard, environmentSummary, 8);
        marginAdd(environmentCard, label(getString(R.string.environment_conflict_details) + "  ↗", 11, RED, true), 12);
        environmentCard.setOnClickListener(v -> showEnvironmentEvidence());
        environmentCard.setFocusable(true);
        environmentCard.setVisibility(View.GONE);
        marginAdd(page, environmentCard, 12);

        overlayCard = card();
        overlayCard.addView(channelHeading("01", "图层侦测", "LAYERS"));
        overlayStatus = label("悬浮窗检测 · 等待开始", 15, MUTED, true);
        marginAdd(overlayCard, overlayStatus, 14);
        overlayNames = label("", 12, TEXT, false);
        overlayNames.setLineSpacing(dp(3), 1f);
        overlayNames.setVisibility(View.GONE);
        marginAdd(overlayCard, overlayNames, 8);
        marginAdd(overlayCard, label("名称线索与探测路线  ↗", 11, CYAN, true), 14);
        overlayCard.setOnClickListener(v -> showOverlayEvidence());
        overlayCard.setFocusable(true);
        marginAdd(page, overlayCard, 12);

        LinearLayout globalPreview = card();
        globalPreview.addView(channelHeading("02", "GPU 活动", "GLOBAL"));
        overviewGpuStatus = label(getString(R.string.global_gpu_waiting), 13, MUTED, false);
        overviewGpuStatus.setLineSpacing(dp(3), 1f);
        marginAdd(globalPreview, overviewGpuStatus, 14);
        marginAdd(globalPreview, label("查看整机采样依据  ↗", 11, CYAN, true), 14);
        globalPreview.setOnClickListener(v -> showGlobalGpuEvidence());
        globalPreview.setFocusable(true);
        marginAdd(page, globalPreview, 12);

        recentLifecycleSignals = label("", 12, AMBER, false);
        recentLifecycleSignals.setLineSpacing(dp(4), 1f);
        recentLifecycleSignals.setPadding(dp(16), dp(14), dp(16), dp(14));
        recentLifecycleSignals.setBackground(shape(SURFACE, BORDER, 14));
        recentLifecycleSignals.setVisibility(View.GONE);
        marginAdd(page, recentLifecycleSignals, 12);

        Button processes = button("进入进程排行  ↗", false);
        processes.setOnClickListener(v -> selectPage(1));
        marginAdd(page, processes, 20);
    }

    private void buildProcesses(LinearLayout page) {
        LinearLayout intro = card();
        intro.addView(mono("CPU / LIVE RANKING", 10, CYAN));
        listTitle = label(getString(R.string.candidates_title), 18, TEXT, true);
        marginAdd(intro, listTitle, 10);
        TextView note = label("按 CPU 实时排序 · 点击进程查看完整证据\n每项显示 UID；厂商返回值单独标注，未取得时显示未知。\nCPU 为单核口径，负载可超过 100%。", 12, MUTED, false);
        note.setLineSpacing(dp(3), 1f);
        marginAdd(intro, note, 8);
        page.addView(intro);
        processList = vertical();
        marginAdd(page, processList, 4);
        TextView scope = label("排除自身进程与线程、已确认的内核线程。\n前 10 名之外的进程仍持续采样。", 11, MUTED, false);
        scope.setLineSpacing(dp(3), 1f);
        marginAdd(page, scope, 18);
    }

    private void buildEvidence(LinearLayout page) {
        LinearLayout session = card();
        session.addView(mono("SESSION / 本次采样", 10, ACCENT));
        evidenceSessionStatus = label("等待开始检测", 18, TEXT, true);
        marginAdd(session, evidenceSessionStatus, 10);
        permissionStatus = label("无需任何授权", 12, MUTED, false);
        marginAdd(session, permissionStatus, 10);
        sampleStatus = label("采样尚未启动", 12, MUTED, false);
        sampleStatus.setLineSpacing(dp(4), 1f);
        marginAdd(session, sampleStatus, 8);
        errorText = label("", 12, AMBER, false);
        errorText.setLineSpacing(dp(4), 1f);
        errorText.setVisibility(View.GONE);
        marginAdd(session, errorText, 12);
        page.addView(session);

        LinearLayout oem = card();
        oem.addView(channelHeading("CPU", "厂商进程探测", "PROCESS INFO"));
        oemProcessStatus = label("厂商进程探测 · 等待开始", 14, MUTED, false);
        oemProcessStatus.setLineSpacing(dp(3), 1f);
        marginAdd(oem, oemProcessStatus, 14);
        marginAdd(oem, label("五条独立路线 · 查看身份与覆盖范围  ↗", 11, CYAN, true), 14);
        oem.setOnClickListener(v -> showOemProcessEvidence());
        oem.setFocusable(true);
        marginAdd(page, oem, 12);

        LinearLayout global = card();
        global.addView(channelHeading("01", "全局 GPU", "MEMSTORE"));
        globalGpuStatus = label(getString(R.string.global_gpu_waiting), 14, MUTED, false);
        globalGpuStatus.setLineSpacing(dp(3), 1f);
        marginAdd(global, globalGpuStatus, 14);
        marginAdd(global, label("整机计数 · 未归属任何 PID  ↗", 11, CYAN, true), 14);
        global.setOnClickListener(v -> showGlobalGpuEvidence());
        global.setFocusable(true);
        marginAdd(page, global, 12);

        LinearLayout exec = card();
        exec.addView(channelHeading("02", "多槽观察", "MULTI SLOT"));
        gpuExecStatus = label("GPU 多槽采样 · 等待开始", 14, TEXT, true);
        marginAdd(exec, gpuExecStatus, 14);
        gpuExecRows = label("", 12, MUTED, false);
        gpuExecRows.setLineSpacing(dp(5), 1f);
        marginAdd(exec, gpuExecRows, 8);
        marginAdd(exec, label("观察等待间隔 · 查看全部槽位  ↗", 11, CYAN, true), 14);
        exec.setOnClickListener(v -> showGpuExecEvidence());
        exec.setFocusable(true);
        marginAdd(page, exec, 12);

        LinearLayout layers = card();
        layers.addView(channelHeading("03", "图层名称", "LAYER PROBE"));
        overviewOverlayStatus = label("悬浮窗检测 · 等待开始", 14, MUTED, false);
        overviewOverlayStatus.setLineSpacing(dp(3), 1f);
        marginAdd(layers, overviewOverlayStatus, 14);
        marginAdd(layers, label("查看探测范围与名称依据  ↗", 11, CYAN, true), 14);
        layers.setOnClickListener(v -> showOverlayEvidence());
        layers.setFocusable(true);
        marginAdd(page, layers, 12);

        TextView footnote = label("这里呈现本次检测的原始依据与读取限制。\n停止或离开界面后，本次结果会清空。", 11, MUTED, false);
        footnote.setLineSpacing(dp(3), 1f);
        marginAdd(page, footnote, 20);
    }

    private void selectPage(int index) {
        if (index < 0 || index >= pages.length || index == selectedPage) return;
        pageScrollPositions[selectedPage] = workspaceScroll.getScrollY();
        selectedPage = index;
        applyPageSelection();
        workspaceScroll.post(() -> workspaceScroll.scrollTo(0, pageScrollPositions[selectedPage]));
    }

    private void applyPageSelection() {
        String[] titles = {"信号总览", "进程脉搏", "证据透视"};
        String[] descriptions = {"从进程到图层，让异常信号浮出水面。",
                "追踪每一份负载，读懂正在发生的活动。", "每一个判断，都能回到采样依据。"};
        pageTitle.setText(titles[selectedPage]);
        pageSubtitle.setText(descriptions[selectedPage]);
        for (int i = 0; i < pages.length; i++) {
            boolean selected = i == selectedPage;
            pages[i].setVisibility(selected ? View.VISIBLE : View.GONE);
            pageTabs[i].setSelected(selected);
            pageTabs[i].setTextColor(selected ? BG : MUTED);
            pageTabs[i].setBackground(ripple(selected ? ACCENT : Color.TRANSPARENT,
                    selected ? ACCENT : Color.TRANSPARENT, 12));
            pageTabs[i].setContentDescription(new String[]{"总览", "进程", "证据"}[i]
                    + (selected ? "，已选择" : "，切换页面"));
        }
    }

    private void openPriorityEvidence() {
        JSONObject overlay = currentReport == null ? null : currentReport.optJSONObject("overlay");
        if (overlay != null && overlay.optBoolean("suspected")) showOverlayEvidence();
        else if (currentReport != null && currentReport.optBoolean("environmentAnomaly")) showEnvironmentEvidence();
        else if (gpuFrequencyWarning.getVisibility() == View.VISIBLE) showGpuFrequencyEvidence();
        else if (currentReport != null && !isStartingReport() && riskCount.getCurrentTextColor() == RED) selectPage(1);
        else selectPage(errorText.getVisibility() == View.VISIBLE ? 2 : 1);
    }

    private void toggleMonitor() {
        if (MonitorService.running) {
            monitorStopRequested = true;
            clearGpuFrequencyWarning();
            startService(new Intent(this, MonitorService.class).setAction(MonitorService.ACTION_STOP));
            startButton.setEnabled(false);
            startButton.postDelayed(() -> { startButton.setEnabled(true); renderLatest(); }, 500);
            return;
        }
        Intent intent = new Intent(this, MonitorService.class).setAction(MonitorService.ACTION_START);
        try {
            monitorStopRequested = false;
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
        renderReport();
        updateDashboardChrome();
    }

    private void renderReport() {
        boolean running = MonitorService.running;
        if (running) getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        else getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        String raw = MonitorService.latestReport;
        String currentError = MonitorService.lastError;
        // The warning expires even when a stalled collector leaves the same report in memory.
        updateGpuFrequencyStatus();
        if (!forceRefresh && running == lastRenderedRunning && Objects.equals(raw, lastRenderedSnapshot)
                && Objects.equals(currentError, lastRenderedError)) return;
        forceRefresh = false;
        if (!Objects.equals(raw, lastRenderedSnapshot)) gpuFrequencyReceivedAtMs = SystemClock.elapsedRealtime();
        lastRenderedRunning = running;
        lastRenderedSnapshot = raw;
        lastRenderedError = currentError;
        heroDescription.setVisibility(View.VISIBLE);
        startButton.setText(running ? "停止检测" : "开始检测");
        stateBadge.setText(running ? "●  监测中" : "○  待机");
        stateBadge.setTextColor(running ? ACCENT : MUTED);
        stateBadge.setBackground(shape(running ? Color.rgb(35, 48, 35) : SURFACE, BORDER, 18));
        if (raw == null || raw.isEmpty()) {
            currentReport = null;
            renderedReport = null;
            updateOverlayStatus();
            updateEnvironmentStatus();
            updateRecentLifecycleSignals();
            updateGpuExecStatus();
            updateGpuFrequencyStatus();
            watchSummary.setText(getString(R.string.monitoring_summary, 0, 0, 0));
            candidateMetric.setText("—");
            gpuMetric.setText("—");
            cpuMetric.setText("—");
            sampleStatus.setText(R.string.no_retained_results);
            permissionStatus.setText(getString(R.string.ordinary_mode, uidText(android.os.Process.myUid())));
            updateGlobalGpuStatus();
            hero.setBackground(heroBackground(BORDER));
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
            updateOverlayStatus();
            updateEnvironmentStatus();
            updateRecentLifecycleSignals();
            updateGpuExecStatus();
            updateGpuFrequencyStatus();
            if (running && isStartingReport()) {
                watchSummary.setText(getString(R.string.monitoring_summary, 0, 0, 0));
                permissionStatus.setText(getString(R.string.ordinary_mode, uidText(currentReport.optInt("collectorUid", -1))));
                riskCount.setText("—");
                riskCount.setTextColor(TEXT);
                hero.setBackground(heroBackground(BORDER));
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
                    if (p == null || !isVisibleProcess(p, currentReport.optInt("collectorPid", -1))) {
                        continue;
                    }
                    monitoredCount++;
                    boolean rootCandidate = isRootCandidate(p);
                    if (rootCandidate) { rootCount++; }
                    if (p.optBoolean("cgroupAnomaly")) { anomalyCount++; }
                    if (rootCandidate && "HIGH".equals(p.optString("risk"))) { high++; }
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
            boolean cgroupPartial = isCgroupPathProbePartial();
            boolean incomplete = denied > 0 || cgroupUnavailable || cgroupPartial
                    || (errors != null && errors.length() > 0);
            riskCount.setText(String.format(Locale.getDefault(), "%d", high));
            int riskColor = high > 0 ? RED : rootWatch > 0 || anomalyCount > 0 || incomplete ? AMBER : TEXT;
            riskCount.setTextColor(riskColor);
            hero.setBackground(heroBackground(high > 0 ? RED : BORDER));
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
            if (isCgroupPathProbeAvailable()) samplingStatus += "\n" + getString(cgroupPartial
                    ? R.string.cgroup_check_partial : R.string.cgroup_check_available);
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
            currentReport = null;
            renderedReport = null;
            updateGpuExecStatus();
            updateGpuFrequencyStatus();
            updateOverlayStatus();
            updateGlobalGpuStatus();
            environmentCard.setVisibility(View.GONE);
            environmentSummary.setText("");
            recentLifecycleSignals.setVisibility(View.GONE);
            recentLifecycleSignals.setText("");
            errorText.setText(getString(R.string.parse_failed, e.getMessage()));
            errorText.setVisibility(View.VISIBLE);
            heroStatus.setText("采集结果异常");
            heroDescription.setText("等待下一份有效采样，上一帧结果已清空。");
            heroDescription.setVisibility(View.VISIBLE);
            hero.setBackground(heroBackground(AMBER));
            riskCount.setText("—");
            riskCount.setTextColor(MUTED);
            candidateMetric.setText("—");
            gpuMetric.setText("—");
            cpuMetric.setText("—");
            watchSummary.setText(getString(R.string.monitoring_summary, 0, 0, 0));
            sampleStatus.setText("本轮数据无效 · 等待下一次采样");
            permissionStatus.setText(getString(R.string.ordinary_mode, uidText(android.os.Process.myUid())));
            renderProcesses();
        }
    }

    /** Keep navigation and persistent controls in sync, including warning expiry between reports. */
    private void updateDashboardChrome() {
        boolean running = MonitorService.running;
        boolean hasSample = currentReport != null && !isStartingReport();
        boolean environment = currentReport != null && currentReport.optBoolean("environmentAnomaly");
        JSONObject overlay = currentReport == null ? null : currentReport.optJSONObject("overlay");
        boolean suspiciousLayer = overlay != null && overlay.optBoolean("suspected");
        boolean frequency = gpuFrequencyWarning.getVisibility() == View.VISIBLE;
        boolean highRisk = hasSample && riskCount.getCurrentTextColor() == RED;
        boolean limited = errorText.getVisibility() == View.VISIBLE;
        String alert = suspiciousLayer ? "发现可疑图层 · 查看名称依据  ↗"
                : environment ? "发现环境异常 · 查看冲突依据  ↗"
                : frequency ? "检测到持续 GPU 高频活动 · 查看依据  ↗"
                : highRisk ? "发现高风险进程 · 查看进程证据  ↗"
                : limited ? "采样存在限制 · 查看本次证据  ↗" : "";
        bindText(alertRibbon, alert);
        int alertVisibility = alert.isEmpty() ? View.GONE : View.VISIBLE;
        if (alertRibbon.getVisibility() != alertVisibility) alertRibbon.setVisibility(alertVisibility);
        bindColor(alertRibbon, suspiciousLayer || environment || frequency || highRisk ? RED : AMBER);
        int signalColor = suspiciousLayer || environment || frequency || highRisk ? RED
                : limited || riskCount.getCurrentTextColor() == AMBER ? AMBER : CYAN;
        signalRadar.setSignalState(running, hasSample, signalColor);
        bindText(overviewGpuStatus, globalGpuStatus.getText().toString());
        bindColor(overviewGpuStatus, globalGpuStatus.getCurrentTextColor());
        bindText(overviewOverlayStatus, overlayStatus.getText().toString());
        bindColor(overviewOverlayStatus, overlayStatus.getCurrentTextColor());
        bindText(evidenceSessionStatus, heroStatus.getText().toString());
        updateOemProcessStatus();
        String caption = monitorStopRequested && running ? "SESSION / 正在停止并清空"
                : !running ? "SESSION / 等待开始"
                : hasSample ? "SESSION / 实时采样中" : "SESSION / 正在建立基线";
        bindText(sessionCaption, caption);
        bindColor(sessionCaption, running ? ACCENT : MUTED);
        int appearance = running ? 1 : 0;
        if (controlAppearance != appearance) {
            controlAppearance = appearance;
            startButton.setTextColor(running ? RED : BG);
            startButton.setBackground(ripple(running ? Color.rgb(42, 24, 32) : ACCENT,
                    running ? Color.rgb(94, 48, 59) : ACCENT, 16));
            startButton.setCompoundDrawablesRelativeWithIntrinsicBounds(
                    running ? R.drawable.ic_stop : R.drawable.ic_start, 0, 0, 0);
            startButton.setCompoundDrawableTintList(ColorStateList.valueOf(running ? RED : BG));
            startButton.setCompoundDrawablePadding(dp(12));
        }
        startButton.setContentDescription(running ? "停止检测并清空本次结果" : "开始本机实时检测");
    }

    private boolean isCgroupCheckUnavailable() {
        JSONObject scan = cgroupPathScan();
        return !isStartingReport() && scan != null
                && (!scan.optBoolean("available") || !scan.optBoolean("calibrationValid"));
    }

    private void updateOverlayStatus() {
        JSONObject overlay = currentReport == null ? null : currentReport.optJSONObject("overlay");
        boolean suspicious = overlay != null && overlay.optBoolean("suspected");
        overlayStatus.setTextColor(suspicious ? RED : MUTED);
        overlayCard.setBackground(shape(suspicious ? Color.rgb(42, 24, 32) : SURFACE, suspicious ? RED : BORDER, 18));
        overlayNames.setText("");
        overlayNames.setVisibility(View.GONE);
        if (suspicious) {
            overlayStatus.setText(R.string.overlay_cheat);
            JSONArray names = overlay.optJSONArray("suspects");
            StringBuilder text = new StringBuilder();
            for (int i = 0; names != null && i < Math.min(3, names.length()); i++) {
                JSONObject row = names.optJSONObject(i);
                if (row == null) continue;
                if (text.length() > 0) text.append('\n');
                text.append(displayLayerName(row.optString("name")));
            }
            if (names != null && names.length() > 3) text.append("\n另有 ").append(names.length() - 3).append(" 个可疑名称");
            text.append("\n点击查看名称与判断依据");
            overlayNames.setText(text);
            overlayNames.setVisibility(View.VISIBLE);
        } else if (!MonitorService.running) overlayStatus.setText("悬浮窗检测 · 等待开始");
        else if (overlay == null) overlayStatus.setText("悬浮窗检测 · 正在探测");
        else if (overlay.optInt("availableRoutes") > 0) overlayStatus.setText("悬浮窗检测 · 暂未发现可疑名称");
        else {
            boolean checking = false;
            JSONArray routes = overlay.optJSONArray("routes");
            for (int i = 0; routes != null && i < routes.length(); i++) {
                JSONObject route = routes.optJSONObject(i);
                if (route != null && "CHECKING".equals(route.optString("status"))) checking = true;
            }
            overlayStatus.setText(checking ? "悬浮窗检测 · 正在探测" : "悬浮窗检测 · 本轮未取得图层数据");
        }
    }

    private static String displayLayerName(String name) {
        String safe = name.replaceAll("[\\p{Cntrl}\\p{Cf}]", "�");
        return safe.length() > 180 ? safe.substring(0, 180) + "…" : safe;
    }

    private void showOverlayEvidence() {
        JSONObject overlay = currentReport == null ? null : currentReport.optJSONObject("overlay");
        if (overlay == null) {
            EvidenceSheet.show(this, "图层名称依据", "等待本次检测",
                    "开始检测后会尝试 Oplus、Nubia 与 ZUI 三条探测路线。名称线索属于启发式判断，接口不可用与未发现可疑名称会分别显示。", false, null, null);
            return;
        }
        StringBuilder detail = new StringBuilder("对可疑或无法解释的名称立即提示。名称判断属于启发式，未命中不代表没有悬浮窗。\n\n");
        JSONArray routes = overlay.optJSONArray("routes");
        for (int i = 0; routes != null && i < routes.length(); i++) {
            JSONObject route = routes.optJSONObject(i);
            if (route == null) continue;
            String id = route.optString("route");
            detail.append("oplus".equals(id) ? "Oplus / 一加 / OPPO / realme" : "nubia".equals(id) ? "红魔 / Nubia" : "联想 / ZUI")
                    .append("：").append(overlayRouteState(route.optString("status"))).append('\n');
            if (!route.optString("error").isEmpty()) detail.append(route.optString("error")).append('\n');
        }
        detail.append("\n三条路线均按实际接口响应判断，不按机型或品牌跳过。扫描有覆盖范围限制。\n");
        JSONArray suspects = overlay.optJSONArray("suspects");
        for (int i = 0; suspects != null && i < suspects.length(); i++) {
            JSONObject row = suspects.optJSONObject(i);
            if (row == null) continue;
            detail.append('\n').append(displayLayerName(row.optString("name"))).append('\n')
                    .append(row.optString("reason")).append('\n');
            if (!row.isNull("ownerPid")) detail.append("图层记录中的 PID：").append(row.optInt("ownerPid"))
                    .append(" / UID：").append(row.optInt("ownerUid")).append('\n');
            else detail.append("接口未提供 PID / UID；# 后缀为图层编号。\n");
        }
        EvidenceSheet.show(this, "图层名称依据", "三条探测路线 · 名称启发式", detail.toString(), false, null, null);
    }

    private static String overlayRouteState(String state) {
        switch (state) {
            case "AVAILABLE": return "已取得图层名称";
            case "CHECKING": return "正在探测";
            case "UNSUPPORTED": return "接口不可用";
            case "BLOCKED": return "访问被拒绝";
            case "NO_DATA": return "接口未返回图层名称";
            case "TIMEOUT": return "查询超时";
            case "STALE": return "数据已过期";
            case "CANCELLED": return "已停止";
            case "COOLDOWN": return "等待下一轮日志收集";
            default: return "回复校验失败";
        }
    }

    private void updateOemProcessStatus() {
        JSONObject oem = currentReport == null ? null : currentReport.optJSONObject("oemProcesses");
        if (oem == null || !MonitorService.running) {
            bindText(oemProcessStatus, "厂商进程探测 · " + (MonitorService.running ? "正在探测" : "等待开始"));
            return;
        }
        JSONArray routes = oem.optJSONArray("routes");
        int available = 0, checking = 0;
        for (int i = 0; routes != null && i < routes.length(); i++) {
            JSONObject route = routes.optJSONObject(i);
            if (route == null) continue;
            if (route.optBoolean("available")) available++;
            if ("CHECKING".equals(route.optString("status"))) checking++;
        }
        int nativeUids = 0, reportedUids = 0, unknownUids = 0;
        JSONArray rows = currentReport.optJSONArray("processes");
        for (int i = 0; rows != null && i < rows.length(); i++) {
            JSONObject row = rows.optJSONObject(i);
            if (row == null) continue;
            if (row.optInt("uid", -1) >= 0) nativeUids++;
            else if (row.optInt("reportedUid", -1) >= 0 && !row.optBoolean("reportedUidConflict")) reportedUids++;
            else unknownUids++;
        }
        bindText(oemProcessStatus, "厂商进程探测 · " + available + "/5 条可用"
                + (checking > 0 ? " · " + checking + " 条探测中" : "")
                + "\nUID 已读取 " + nativeUids + " · 厂商提供 " + reportedUids + " · 未知 " + unknownUids);
    }

    private void showOemProcessEvidence() {
        JSONObject oem = currentReport == null ? null : currentReport.optJSONObject("oemProcesses");
        StringBuilder detail = new StringBuilder("通过厂商服务补充进程名称、UID 和父进程关系。每条路线独立采集；不可用或没有返回记录不代表设备上没有其他进程。\n");
        JSONArray routes = oem == null ? null : oem.optJSONArray("routes");
        for (int i = 0; routes != null && i < routes.length(); i++) {
            JSONObject route = routes.optJSONObject(i);
            if (route == null) continue;
            JSONArray rows = route.optJSONArray("rows");
            detail.append('\n').append(oemRouteName(route.optString("route"))).append("：")
                    .append(oemRouteState(route.optString("status"))).append('\n')
                    .append("返回记录：").append(rows == null ? 0 : rows.length()).append('\n');
            if (!route.optString("detail").isEmpty()) detail.append(route.optString("detail")).append('\n');
            if (route.has("candidateCount")) detail.append("候选 PID：").append(route.optInt("candidateCount")).append('\n');
            if (route.has("candidateBatchCount")) detail.append("本轮候选批次：").append(route.optInt("candidateBatchCount")).append('\n');
            int queried = route.optInt("candidatesQueried", route.optInt("queriedCandidates", -1));
            if (queried >= 0) detail.append("本轮已查询：").append(queried).append('\n');
        }
        if (routes == null) detail.append("\n等待本次检测。\n");
        detail.append("\nUID 来源：优先显示本地读取的有效 UID；只有厂商返回值时标注“厂商”。未取得或返回值冲突时保持未知。厂商 UID 不单独作为有效 UID 或 root 身份证明。\n")
                .append("CPU 状态中的厂商数值不换算成本应用 CPU 百分比；进程排行继续使用原生时钟采样。\n")
                .append("Vivo 和 PerfShielder 针对候选 PID 查询，覆盖范围不等于完整枚举。父子关系也不证明 GPU 归属。\n");
        EvidenceSheet.show(this, "厂商进程探测", "五条路线 · 本次采样", detail.toString(), false,
                oem == null ? null : "原始记录", oem == null ? null : () -> {
                    try { EvidenceSheet.show(this, "厂商进程原始记录", "本次采样", oem.toString(2), true, null, null); }
                    catch (JSONException ignored) { }
                });
    }

    private static String oemRouteName(String route) {
        switch (route) {
            case "miui_cpu": return "小米 CPU 状态";
            case "miui_memory": return "小米父进程关系";
            case "oplus_cpu": return "Oplus CPU 统计";
            case "mindsync": return "红魔 MindSync";
            case "vivo_rms": return "Vivo RMS";
            default: return route;
        }
    }

    private static String oemRouteState(String state) {
        switch (state) {
            case "AVAILABLE": case "OK": return "已取得记录";
            case "PARTIAL": return "已取得部分记录";
            case "NO_DATA": case "EMPTY": return "本轮无记录";
            case "CHECKING": return "正在探测";
            case "BLOCKED": case "DENIED": return "访问被拒绝";
            case "UNSUPPORTED": case "UNSUPPORTED_PROTOCOL": return "接口不可用";
            case "TIMEOUT": return "查询超时";
            case "STALE": return "数据已过期";
            case "CANCELLED": return "已停止";
            case "NO_CANDIDATES": return "等待候选进程";
            default: return "回复不可用（" + state + "）";
        }
    }

    private boolean isCgroupPathProbeAvailable() {
        JSONObject scan = cgroupPathScan();
        return !isStartingReport() && scan != null && scan.optBoolean("available")
                && scan.optBoolean("calibrationValid");
    }

    private boolean isCgroupPathProbePartial() {
        JSONObject scan = cgroupPathScan();
        return isCgroupPathProbeAvailable() && scan != null
                && (!scan.optBoolean("missingDetectionAvailable", true)
                    || !scan.optBoolean("freshCoverageThisSample", true));
    }

    private JSONObject cgroupPathScan() {
        JSONObject scan = currentReport == null ? null : currentReport.optJSONObject("cgroupScan");
        return scan != null && "stat_uid_pid_paths".equals(scan.optString("method")) ? scan : null;
    }

    private boolean isStartingReport() {
        return currentReport != null && ("STARTING".equals(currentReport.optString("samplingState"))
                || !currentReport.has("sampleIndex"));
    }

    private JSONObject gpuFrequencyResult() {
        JSONObject global = currentReport == null ? null : currentReport.optJSONObject("globalGpu");
        return global == null ? null : global.optJSONObject("slotFrequency");
    }

    private void clearGpuFrequencyWarning() {
        if (gpuFrequencyWarning == null) return;
        gpuFrequencyWarning.setVisibility(View.GONE);
        gpuFrequencyWarning.setText("");
    }

    private void updateGpuFrequencyStatus() {
        if (gpuFrequencyWarning == null) return;
        JSONObject result = gpuFrequencyResult();
        if (!refreshActive || !MonitorService.running || monitorStopRequested || result == null
                || !"complete".equals(result.optString("status")) || !result.optBoolean("alert")) {
            clearGpuFrequencyWarning();
            return;
        }
        long ageMs = result.optLong("ageMs", -1);
        long expiryMs = result.optLong("expiryMs", 1500);
        long sinceReceipt = SystemClock.elapsedRealtime() - gpuFrequencyReceivedAtMs;
        long sampledAt = result.optLong("sampledAtUptimeMs", 0);
        long nowUptime = SystemClock.uptimeMillis();
        double fps = result.optDouble("peakFps", Double.NaN);
        if (ageMs < 0 || expiryMs <= 0 || sinceReceipt < 0 || ageMs > expiryMs
                || sinceReceipt > expiryMs - ageMs || sampledAt > nowUptime
                || (sampledAt > 0 && nowUptime - sampledAt > expiryMs)
                || !Double.isFinite(fps) || fps <= 0) {
            clearGpuFrequencyWarning();
            return;
        }
        gpuFrequencyWarning.setText(getString(R.string.gpu_frequency_warning, fps));
        gpuFrequencyWarning.setTextColor(RED);
        gpuFrequencyWarning.setVisibility(View.VISIBLE);
    }

    private void showGpuFrequencyEvidence() {
        JSONObject result = gpuFrequencyResult();
        StringBuilder detail = new StringBuilder(getString(R.string.gpu_frequency_explanation));
        if (result != null) {
            JSONArray rows = result.optJSONArray("slots");
            for (int i = 0; rows != null && i < rows.length(); i++) {
                JSONObject row = rows.optJSONObject(i);
                if (row == null || !row.optBoolean("eligible") || !row.optBoolean("alert")) continue;
                double fps = row.optDouble("observationsPerSecond", Double.NaN);
                if (!Double.isFinite(fps)) continue;
                detail.append(String.format(Locale.getDefault(), "\n\n槽 %d · 约 %.1f FPS\n持续高于阈值 %.1f 秒",
                        row.optInt("slot"), fps, row.optLong("stableForMs") / 1000.0));
            }
        }
        EvidenceSheet.show(this, getString(R.string.gpu_frequency_title), "GPU 槽活动 · 估算频率", detail.toString(), false, null, null);
    }

    private JSONObject gpuExecResult() {
        JSONObject global = currentReport == null ? null : currentReport.optJSONObject("globalGpu");
        return global == null ? null : global.optJSONObject("execMulti");
    }

    private void updateGpuExecStatus() {
        if (gpuExecStatus == null) return;
        JSONObject result = gpuExecResult();
        if (result == null) {
            gpuExecStatus.setText(MonitorService.running ? "GPU 多槽采样 · 等待采样" : "GPU 多槽采样 · 等待开始");
            gpuExecRows.setText(""); return;
        }
        JSONArray rows = result.optJSONArray("slots");
        int observed = 0;
        StringBuilder text = new StringBuilder();
        for (int i = 0; rows != null && i < rows.length(); i++) {
            JSONObject row = rows.optJSONObject(i);
            if (row == null || !row.optBoolean("eligible") || row.optInt("measuredSamples") == 0) continue;
            observed++;
            if (observed <= 3) {
                if (text.length() > 0) text.append('\n');
                text.append(gpuExecRow(row));
            }
        }
        if (observed > 0) {
            gpuExecStatus.setText(getString(R.string.gpu_exec_observed, observed));
            if (observed > 3) text.append("\n其余 ").append(observed - 3).append(" 个槽见详情");
            text.append(String.format(Locale.getDefault(), "\n%.1f 秒前的观察", result.optLong("ageMs") / 1000.0));
        } else {
            String reason = result.optString("reason");
            String state = result.optBoolean("sampling") ? "采样中"
                    : "no_active_external_slots".equals(reason) ? "未观察到可采样的外部活动槽"
                    : "waiting_self_filter".equals(reason) ? "等待自身槽确认"
                    : "complete".equals(result.optString("status")) ? "本轮无可用完成样本" : "当前不可用";
            gpuExecStatus.setText(getString(R.string.gpu_exec_state, state));
        }
        gpuExecRows.setText(text.toString());
    }

    private static String gpuExecRow(JSONObject row) {
        String mean = row.isNull("meanWaitUs") ? "—"
                : String.format(Locale.getDefault(), "%.1f μs", row.optDouble("meanWaitUs"));
        return "槽 " + row.optInt("slot") + " · " + row.optInt("measuredSamples")
                + " 次观察 · 非零均值 " + mean;
    }

    private void showGpuExecEvidence() {
        JSONObject result = gpuExecResult();
        StringBuilder detail = new StringBuilder("同时观察最多 16 个用户槽，每轮 500 毫秒。自身槽及保留槽不参与结果展示。\n"
                + "等待时间是 CPU 观察提交、完成计数之间的间隔，包含轮询和调度开销。均值仅统计已完成的非零样本。观察次数不等于帧数，也不能据此确认进程归属或外挂。\n");
        if (result != null) {
            detail.append("\n本轮候选：").append(result.optInt("candidateCount"));
            if (result.optBoolean("selectionTruncated")) detail.append("（分批轮换采样）");
            if (result.optInt("activeOutsideRange") > 0) detail.append("\n超出当前支持槽号范围：").append(result.optInt("activeOutsideRange"));
            JSONArray rows = result.optJSONArray("slots");
            for (int i = 0; rows != null && i < rows.length(); i++) {
                JSONObject row = rows.optJSONObject(i);
                if (row == null) continue;
                detail.append("\n\n");
                if (!row.optBoolean("eligible")) {
                    detail.append("槽 ").append(row.optInt("slot")).append(" · 结果不可用或已排除"); continue;
                }
                detail.append(gpuExecRow(row)).append("\n完成 ").append(row.optInt("completedSamples"))
                        .append(" 次；超时 ").append(row.optInt("timedOutSamples"))
                        .append(" 次；窗口结束未完成 ").append(row.optInt("unfinishedSamples")).append(" 次");
                if (!row.isNull("minWaitUs")) detail.append("\n非零等待范围：").append(row.optInt("minWaitUs"))
                        .append("–").append(row.optInt("maxWaitUs")).append(" μs");
                detail.append(String.format(Locale.getDefault(), "\n观察速率：%.1f 次/秒", row.optDouble("observationsPerSecond")));
            }
            if (rows == null || rows.length() == 0) detail.append("\n\n尚无可用样本。");
        } else detail.append("\n开始检测后自动采样，停止后清空。");
        EvidenceSheet.show(this, "GPU 多槽采样", "短窗口观察 · 归属未知", detail.toString(), false, null, null);
    }

    private void updateGlobalGpuStatus() {
        if (currentReport == null || isStartingReport()) {
            globalGpuStatus.setText(R.string.global_gpu_waiting);
            globalGpuStatus.setTextColor(MUTED);
            return;
        }
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
        List<Integer> kernelDomainPids = new ArrayList<>();
        for (int i = 0; checks != null && i < checks.length(); i++) {
            JSONObject check = checks.optJSONObject(i);
            if (check == null || !"ANOMALY".equals(check.optString("status"))) continue;
            int pid = check.optInt("pid", -1);
            List<Integer> target = "avc_kernel_userspace".equals(check.optString("type")) ? kernelDomainPids : pids;
            if (pid > 0 && !target.contains(pid)) target.add(pid);
        }
        Collections.sort(pids);
        StringBuilder names = new StringBuilder();
        for (int pid : pids) {
            if (names.length() > 0) names.append("、");
            names.append(pid);
        }
        String summary = pids.isEmpty() ? "" : getString(R.string.environment_conflict_summary, names.toString());
        Collections.sort(kernelDomainPids);
        names.setLength(0);
        for (int pid : kernelDomainPids) {
            if (names.length() > 0) names.append("、");
            names.append(pid);
        }
        if (!kernelDomainPids.isEmpty()) summary += (summary.isEmpty() ? "" : "\n\n")
                + getString(R.string.environment_kernel_domain_summary, names.toString());
        environmentSummary.setText(summary.isEmpty() ? "详见原始依据" : summary);
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
        StringBuilder detail = new StringBuilder("环境异常依据包含两类：同一存活身份的进程目录连续复查为不存在；或 AVC 目标域为 kernel，但经校准的 futex 检查确认是用户态线程。权限拒绝、正常退出和无法判定不作为第二类异常。确认的内核线程已从 CPU 列表排除。\n\n");
        JSONObject raw = new JSONObject();
        try {
            raw.put("environmentAnomaly", currentReport.optBoolean("environmentAnomaly"));
            raw.put("environmentCheckCoverage", currentReport.opt("environmentCheckCoverage"));
            raw.put("environmentChecks", currentReport.optJSONArray("environmentChecks"));
            raw.put("futexPi", currentReport.optJSONObject("futexPi"));
            raw.put("kernelThreadExcludedCount", currentReport.optInt("kernelThreadExcludedCount"));
            detail.append(raw.toString(2));
        } catch (JSONException e) {
            detail.append("原始依据无法解析：").append(e.getMessage());
        }
        EvidenceSheet.show(this, "环境异常", "进程存在性与线程类型 · 原始依据", detail.toString(), true, null, null);
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
        EvidenceSheet.show(this, "全局 GPU 证据", "整机活动 · 未归属任何 PID", description, true, null, null);
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
            processRows.get(i).bind(visible.get(i), i + 1);
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

    static String processUidLabel(JSONObject process) {
        int uid = process.optInt("uid", -1);
        if (uid >= 0) return "UID " + uid;
        if (process.optBoolean("reportedUidConflict")) return "UID 未知（来源冲突）";
        int reported = process.optInt("reportedUid", -1);
        return reported >= 0 ? "UID " + reported + "（厂商）" : "UID 未知";
    }

    private static void bindColor(TextView view, int color) {
        if (view.getCurrentTextColor() != color) view.setTextColor(color);
    }

    /** One holder per displayed index; the current sorted row replaces its previous binding. */
    private final class ProcessRow {
        final LinearLayout item = card();
        final TextView rank = mono("", 12, CYAN);
        final TextView name = label("", 16, TEXT, true);
        final TextView riskTag = badge("", MUTED);
        final TextView identity = label("", 11, MUTED, false);
        final TextView avcHint = label("", 11, AMBER, false);
        final TextView cpu = mono("", 24, TEXT);
        final CpuLoadView load = new CpuLoadView(MainActivity.this);
        final TextView gpuTag = label("", 11, MUTED, false);
        final TextView lifecycleLine = label("", 12, MUTED, false);
        final TextView explanation = label("", 12, MUTED, false);
        JSONObject process;
        int backgroundKind;

        ProcessRow() {
            LinearLayout rankRow = row();
            rankRow.addView(rank, new LinearLayout.LayoutParams(dp(46), -2));
            riskTag.setGravity(Gravity.END | Gravity.CENTER_VERTICAL);
            riskTag.setMaxLines(3);
            rankRow.addView(riskTag, new LinearLayout.LayoutParams(0, -2, 1));
            item.addView(rankRow);
            name.setMaxLines(2);
            name.setEllipsize(TextUtils.TruncateAt.END);
            marginAdd(item, name, 12);
            marginAdd(item, identity, 6);
            avcHint.setMaxLines(2);
            avcHint.setVisibility(View.GONE);
            marginAdd(item, avcHint, 6);
            LinearLayout stats = row();
            cpu.setMaxLines(1);
            cpu.setAutoSizeTextTypeUniformWithConfiguration(14, 24, 1, TypedValue.COMPLEX_UNIT_SP);
            stats.addView(cpu, new LinearLayout.LayoutParams(0, -2, 1));
            TextView detailLink = label("证据  ↗", 11, CYAN, true);
            LinearLayout.LayoutParams linkParams = new LinearLayout.LayoutParams(-2, -2);
            linkParams.leftMargin = dp(12);
            stats.addView(detailLink, linkParams);
            marginAdd(item, stats, 16);
            LinearLayout.LayoutParams loadParams = new LinearLayout.LayoutParams(-1, dp(8));
            loadParams.topMargin = dp(10);
            item.addView(load, loadParams);
            marginAdd(item, gpuTag, 10);
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

        void bind(JSONObject p, int position) {
            process = p;
            bindText(rank, String.format(Locale.US, "%02d /", position));
            String risk = p.optString("risk", "UNKNOWN");
            boolean avcRisk = "avc_root_domain_cpu_global_memstore".equals(p.optString("riskBasis"));
            boolean cgroupAnomaly = p.optBoolean("cgroupAnomaly");
            boolean kernelMismatch = p.optBoolean("kernelDomainMismatch");
            int color = kernelMismatch || "HIGH".equals(risk) ? RED : "SUSPECT".equals(risk) || "WATCH".equals(risk) ? AMBER : MUTED;
            int nextBackground = kernelMismatch || "HIGH".equals(risk) ? 1 : "SUSPECT".equals(risk) ? 2 : 0;
            if (nextBackground != backgroundKind) {
                item.setBackground(nextBackground == 1 ? shape(Color.rgb(42, 24, 32), Color.rgb(94, 48, 59), 18)
                        : nextBackground == 2 ? shape(Color.rgb(40, 33, 24), Color.rgb(94, 75, 45), 18)
                        : shape(SURFACE, BORDER, 18));
                backgroundKind = nextBackground;
            }
            String pidLabel = "PID " + p.optInt("pid");
            String processName = p.optString("name", "").trim();
            if (processName.isEmpty()) processName = pidLabel;
            bindText(name, processName);
            bindText(riskTag, kernelMismatch ? getString(R.string.environment_anomaly) : riskName(risk));
            bindColor(riskTag, color);
            String identityText = (processName.equals(pidLabel) ? "" : pidLabel + "  ·  ") + processUidLabel(p);
            String background = backgroundName(p.optString("background"));
            if (!background.isEmpty()) identityText += (identityText.isEmpty() ? "" : "  ·  ") + background;
            bindText(identity, identityText);
            int identityVisibility = identityText.isEmpty() ? View.GONE : View.VISIBLE;
            if (identity.getVisibility() != identityVisibility) identity.setVisibility(identityVisibility);
            String avcContext = p.optString("avcTargetContext", "");
            boolean showAvcHint = !avcContext.isEmpty();
            bindText(avcHint, showAvcHint ? "AVC 域 · " + avcContext
                    + (kernelMismatch ? "\n线程类型 · 用户态，与 kernel 域不一致" : "") : "");
            bindColor(avcHint, kernelMismatch ? RED : AMBER);
            int avcVisibility = showAvcHint ? View.VISIBLE : View.GONE;
            if (avcHint.getVisibility() != avcVisibility) avcHint.setVisibility(avcVisibility);
            bindText(cpu, "CPU  " + MainActivity.cpu(p.optDouble("cpuPercent", -1)));
            bindColor(cpu, "HIGH".equals(risk) ? RED : ACCENT);
            load.setLoad(cpuSortValue(p), "HIGH".equals(risk) ? RED : CYAN);
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
            if (kernelMismatch) reason = "环境异常：AVC 显示 kernel，但线程类型检查确认是用户态线程。\n" + reason;
            bindText(explanation, reason);
            bindColor(explanation, kernelMismatch ? RED : cgroupAnomaly ? AMBER : MUTED);
            String description = p.optString("name") + "，" + riskName(risk)
                    + "，PID " + p.optInt("pid") + "，" + processUidLabel(p)
                    + "，CPU " + MainActivity.cpu(cpuSortValue(p))
                    + (kernelMismatch ? "，环境异常" : "")
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
        detail.append("有效 UID：").append(uid >= 0 ? Integer.toString(uid) : "未知").append('\n');
        detail.append("有效 UID 来源：").append(p.optString("uidSource", "unknown")).append('\n');
        int reportedUid = p.optInt("reportedUid", -1);
        if (reportedUid >= 0) detail.append("厂商返回 UID：").append(reportedUid).append("（来源：")
                .append(p.optString("reportedUidSource", "未知")).append("）\n");
        if (p.optBoolean("reportedUidConflict")) detail.append("厂商 UID 来源冲突：保留原始依据，不据此确认身份。\n");
        if (p.optInt("reportedPpid", -1) >= 0) detail.append("厂商返回父进程 PID：").append(p.optInt("reportedPpid")).append('\n');
        if (p.optBoolean("reportedPpidConflict")) detail.append("厂商父进程记录存在冲突，未合并为一个关系。\n");
        if (p.has("oemEvidence")) detail.append("厂商进程依据：").append(p.opt("oemEvidence")).append('\n');
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
        String threadType = p.optString("threadType", KernelThreadPolicy.UNKNOWN);
        detail.append("线程类型：").append(KernelThreadPolicy.USER.equals(threadType) ? "用户态线程"
                : KernelThreadPolicy.KERNEL.equals(threadType) ? "内核线程" : "未知").append('\n');
        if (p.optBoolean("kernelDomainMismatch")) detail.append("环境异常：AVC 的 kernel 域与线程类型检查冲突。\n");
        JSONObject threadCheck = p.optJSONObject("threadTypeCheck");
        if (threadCheck != null) detail.append("线程类型检查依据：").append(threadCheck.toString()).append('\n');
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
        String title = p.optString("name", "").trim();
        if (title.isEmpty()) title = "PID " + p.optInt("pid");
        EvidenceSheet.show(this, title, "进程证据 / " + riskName(p.optString("risk")),
                highlightGpuConfirmation(detail.toString()), false, "原始记录", () -> showRawProcess(p));
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
            if (scan.has("missingDetectionAvailable")) {
                detail.append("本轮可判定路径缺失：")
                        .append(evidenceFlag(scan, "missingDetectionAvailable")).append('\n');
                detail.append("本轮 UID 范围重新探测完整：")
                        .append(evidenceFlag(scan, "freshCoverageThisSample")).append('\n');
            }
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
                if (layout.has("usableUidCount")) {
                    detail.append("本轮可观察 UID 数：").append(layout.optInt("usableUidCount"))
                            .append(" · 本轮完整覆盖：").append(evidenceFlag(layout, "freshCoverageThisSample"))
                            .append('\n');
                }
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
                        .append(" · 本轮覆盖完整：").append(evidenceFlag(catalog, "complete")).append('\n');
                if (catalog.has("scanTotal")) {
                    detail.append("UID 发现进度：").append(catalog.optLong("scanCompleted"))
                            .append(" / ").append(catalog.optLong("scanTotal")).append('\n');
                    detail.append("本轮重新验证目录：").append(evidenceFlag(catalog, "validatedThisSample"))
                            .append(" · 后台继续发现：").append(evidenceFlag(catalog, "refreshing")).append('\n');
                }
                detail.append("已探测 UID 数字范围：").append(uidRanges(catalog.optJSONArray("ranges"))).append('\n');
                if (catalog.has("generation")) detail.append("目录编目代次：").append(catalog.optLong("generation")).append('\n');
                if (catalog.optLong("ageMs", -1) >= 0) detail.append("目录发现记录年龄：")
                        .append(catalog.optLong("ageMs")).append(" ms\n");
                if (check != null && check.has("uidCatalogGeneration")) {
                    detail.append("本进程使用的编目代次：").append(check.optLong("uidCatalogGeneration")).append('\n');
                }
            }
        }
        detail.append("这里只核对参考命名的 UID/PID 目录；已探测路径未匹配不等于没有内核 cgroup 归属。")
                .append("缓存与跨轮发现仅提供候选目录，未完成本轮覆盖时不确认缺失。")
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
        EvidenceSheet.show(this, "进程原始记录", "JSON / 本次采样快照", content, true, null, null);
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
        boolean self = process.optBoolean("oemSelfProcess") || MonitoredProcessFilter.isSelf(pid, process.optInt("uid", -1), collectorPid,
                android.os.Process.myPid(), android.os.Process.myUid());
        return MonitoredProcessFilter.acceptsCpu(pid, self)
                && !KernelThreadPolicy.KERNEL.equals(process.optString("threadType"));
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
        text.setIncludeFontPadding(false);
        text.setFontFeatureSettings("tnum");
        if (bold) text.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        return text;
    }
    private TextView mono(String value, int size, int color) {
        TextView text = label(value, size, color, false);
        text.setTypeface(Typeface.MONOSPACE);
        return text;
    }
    private LinearLayout card() {
        LinearLayout card = vertical();
        card.setPadding(dp(18), dp(18), dp(18), dp(18));
        card.setBackground(shape(SURFACE, BORDER, 18));
        card.setForeground(new RippleDrawable(ColorStateList.valueOf(Color.argb(24, 128, 216, 235)),
                null, shape(Color.WHITE, Color.WHITE, 18)));
        return card;
    }
    private TextView badge(String text, int color) {
        TextView badge = label(text, 10, color, true);
        badge.setPadding(dp(10), dp(7), dp(10), dp(7));
        badge.setBackground(shape(BG, BORDER, 16));
        badge.setGravity(Gravity.CENTER);
        return badge;
    }
    private TextView metric(LinearLayout parent, String title, String code, int color) {
        boolean stacked = parent.getOrientation() == LinearLayout.VERTICAL;
        LinearLayout column = vertical();
        column.setPadding(dp(10), dp(14), dp(10), dp(14));
        column.setBackground(shape(SURFACE, BORDER, 16));
        column.addView(mono(code, 9, color));
        TextView value = mono("—", 26, color);
        value.setMaxLines(1);
        value.setAutoSizeTextTypeUniformWithConfiguration(13, 26, 1, TypedValue.COMPLEX_UNIT_SP);
        LinearLayout.LayoutParams valueParams = new LinearLayout.LayoutParams(-1, stacked ? -2 : dp(42));
        value.setMinHeight(dp(42));
        valueParams.topMargin = dp(8);
        column.addView(value, valueParams);
        TextView caption = label(title, 10, MUTED, false);
        caption.setMinLines(stacked ? 1 : 2);
        caption.setLineSpacing(dp(2), 1f);
        marginAdd(column, caption, 5);
        LinearLayout.LayoutParams params = stacked ? new LinearLayout.LayoutParams(-1, -2)
                : new LinearLayout.LayoutParams(0, -1, 1);
        if (parent.getChildCount() > 0) {
            if (stacked) params.topMargin = dp(8);
            else params.leftMargin = dp(8);
        }
        parent.addView(column, params);
        return value;
    }
    private LinearLayout sectionHeading(String title, String code) {
        LinearLayout heading = vertical();
        heading.addView(mono(code, 9, MUTED));
        TextView text = label(title, 18, TEXT, true);
        if (Build.VERSION.SDK_INT >= 28) text.setAccessibilityHeading(true);
        marginAdd(heading, text, 6);
        return heading;
    }
    private LinearLayout channelHeading(String number, String title, String code) {
        LinearLayout heading = row();
        TextView index = mono(number, 13, CYAN);
        index.setGravity(Gravity.CENTER);
        index.setBackground(shape(BG, BORDER, 10));
        heading.addView(index, new LinearLayout.LayoutParams(dp(34), dp(34)));
        LinearLayout names = vertical();
        names.addView(label(title, 15, TEXT, true));
        marginAdd(names, mono(code, 9, MUTED), 4);
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(0, -2, 1);
        params.leftMargin = dp(12);
        heading.addView(names, params);
        heading.addView(label("↗", 18, MUTED, false));
        return heading;
    }
    private Button button(String text, boolean primary) {
        Button button = new Button(this);
        button.setText(text);
        button.setAllCaps(false);
        button.setTextSize(14);
        button.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        button.setTextColor(primary ? BG : TEXT);
        button.setBackground(ripple(primary ? ACCENT : SURFACE, primary ? ACCENT : BORDER, 14));
        button.setPadding(dp(14), dp(12), dp(14), dp(12));
        button.setMinHeight(dp(48));
        button.setMinimumHeight(dp(48));
        button.setMinWidth(0);
        button.setMinimumWidth(0);
        button.setStateListAnimator(null);
        return button;
    }
    private RippleDrawable ripple(int fill, int stroke, int radius) {
        return new RippleDrawable(ColorStateList.valueOf(Color.argb(35, 128, 216, 235)),
                shape(fill, stroke, radius), shape(Color.WHITE, Color.WHITE, radius));
    }
    private GradientDrawable heroBackground(int stroke) {
        GradientDrawable background = new GradientDrawable(GradientDrawable.Orientation.TL_BR,
                new int[]{Color.rgb(29, 44, 47), Color.rgb(15, 25, 36)});
        background.setCornerRadius(dp(24));
        background.setStroke(dp(1), stroke);
        return background;
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
