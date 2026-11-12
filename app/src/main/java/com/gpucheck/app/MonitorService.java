package com.gpucheck.app;

import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.SystemClock;
import android.util.AtomicFile;
import android.util.Log;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** User-started monitor; the native helper loses stdin when the app dies. */
public final class MonitorService extends Service {
    public static final String ACTION_START = "com.gpucheck.app.START";
    public static final String ACTION_STOP = "com.gpucheck.app.STOP";
    public static final String ACTION_UPDATE = "com.gpucheck.app.UPDATE";
    public static volatile String latestReport;
    public static volatile String lastError;
    public static volatile boolean running;
    private static final Object REPORT_LOCK = new Object();
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private volatile Process process;
    private volatile AvcEvidence avcEvidence;
    private volatile OverlayMonitor overlayMonitor;
    private volatile int generation;
    private volatile long lastOutputAt;
    private volatile boolean receivedSample;
    private volatile String appVersion = "unknown";
    private Runnable watchdog;

    public static void clearPreviousResults(Context context) {
        synchronized (REPORT_LOCK) {
            // Remove the private cache written by older versions; current sessions stay in memory.
            new AtomicFile(new File(context.getFilesDir(), "latest-report.json")).delete();
            if (!running) {
                latestReport = null;
                lastError = null;
            }
        }
    }

    @Override public void onCreate() {
        super.onCreate();
        try {
            String installedVersion = getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
            if (installedVersion != null && !installedVersion.isEmpty()) appVersion = installedVersion;
        } catch (android.content.pm.PackageManager.NameNotFoundException error) {
            Log.w("GpuCheck", "Cannot read installed package version", error);
        }
        clearPreviousResults(this);
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null || ACTION_STOP.equals(intent.getAction())) {
            stopMonitoring("已停止", null);
            return START_NOT_STICKY;
        }
        if (!ACTION_START.equals(intent.getAction()) || running) return START_NOT_STICKY;
        double threshold = intent.getDoubleExtra("threshold", 20.0);
        if (!Double.isFinite(threshold)) threshold = 20.0;
        threshold = Math.max(0.1, Math.min(10000, threshold));
        int interval = Math.max(500, Math.min(10000, intent.getIntExtra("intervalMs", 2000)));
        int windows = Math.max(1, Math.min(30, intent.getIntExtra("windows", 3)));
        running = true;
        lastError = null;
        int token = ++generation;
        lastOutputAt = SystemClock.uptimeMillis();
        receivedSample = false;
        final double configuredThreshold = threshold;
        OverlayMonitor sessionOverlay = new OverlayMonitor(this);
        overlayMonitor = sessionOverlay;
        try {
            JSONObject initial = new JSONObject();
            initial.put("schema", 1).put("root", false).put("mode", "unprivileged")
                    .put("collectorUid", android.os.Process.myUid()).put("status", "正在建立用户态采样基线…")
                    .put("timestampEpochMs", System.currentTimeMillis()).put("threshold", threshold)
                    .put("windows", windows).put("intervalMs", interval).put("highRiskCount", 0)
                    .put("processes", new JSONArray())
                    .put("overlay", sessionOverlay.snapshot())
                    .put("errors", new JSONArray());
            publish(initial, token);
        } catch (Exception e) { Log.e("GpuCheck", "Initial report", e); }
        watchdog = new Runnable() {
            @Override public void run() {
                if (token != generation || !running) return;
                long deadline = receivedSample ? Math.max(20000, interval * 5L) : 60000;
                if (SystemClock.uptimeMillis() - lastOutputAt > deadline) {
                    stopMonitoring("采集超时", receivedSample ? "采集器长时间未返回快照，已结束本次监测。"
                            : "用户态采集器未返回结果，请查看本机运行限制后重试。");
                } else handler.postDelayed(this, 3000);
            }
        };
        handler.postDelayed(watchdog, 3000);
        worker.execute(() -> collect(token, configuredThreshold, windows, interval));
        return START_NOT_STICKY;
    }

    private void collect(int token, double threshold, int windows, int interval) {
        Process localProcess = null;
        AvcEvidence localEvidence = null;
        StringBuilder errorOutput = new StringBuilder();
        try {
            File binary = new File(getApplicationInfo().nativeLibraryDir, "libgpu_probe.so");
            if (!binary.isFile()) throw new IllegalStateException("缺少 arm64 原生采集器：" + binary);
            localEvidence = new AvcEvidence(this);
            localEvidence.start();
            avcEvidence = localEvidence;
            localProcess = new ProcessBuilder(binary.getAbsolutePath(), "--interval-ms",
                    Integer.toString(interval), "--watch-stdin").start();
            if (token != generation || !running) { closeProcess(localProcess); return; }
            process = localProcess;
            final Process child = localProcess;
            Thread stderr = new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(child.getErrorStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        synchronized (errorOutput) {
                            if (errorOutput.length() < 8192) errorOutput.append(line).append('\n');
                        }
                    }
                } catch (Exception ignored) { }
            }, "gpu-probe-stderr");
            stderr.setDaemon(true);
            stderr.start();
            RiskEngine engine = new RiskEngine(threshold, windows, interval);
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(localProcess.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while (token == generation && running && (line = reader.readLine()) != null) {
                    if (!line.startsWith("{")) {
                        synchronized (errorOutput) { if (errorOutput.length() < 8192) errorOutput.append(line).append('\n'); }
                        continue;
                    }
                    JSONObject raw = new JSONObject(line);
                    if (raw.optInt("schema") != 1 || !raw.has("processes")) {
                        throw new IllegalStateException("采集器返回不支持的快照格式。");
                    }
                    lastOutputAt = SystemClock.uptimeMillis();
                    receivedSample = true;
                    SelfGpuSlots.enrich(raw);
                    localEvidence.enrich(raw);
                    JSONObject report = engine.process(raw);
                    OverlayMonitor overlay = overlayMonitor;
                    if (overlay != null && token == generation) report.put("overlay", overlay.snapshot());
                    publish(report, token);
                    if (raw.optBoolean("root")) throw new IllegalStateException("采集器意外拥有 root 权限，已停止；本应用仅使用普通应用权限。");
                }
            }
            if (token == generation && running) {
                String detail;
                synchronized (errorOutput) { detail = errorOutput.toString().trim(); }
                throw new IllegalStateException("用户态采集器已退出。" + (detail.isEmpty() ? "请重试并查看采集限制。" : "\n" + detail));
            }
        } catch (Exception error) {
            String message = error.getMessage() == null ? error.toString() : error.getMessage();
            handler.post(() -> { if (token == generation && running) stopMonitoring("采集失败", message); });
        } finally {
            closeProcess(localProcess);
            if (process == localProcess) process = null;
            if (localEvidence != null) localEvidence.stop();
            if (avcEvidence == localEvidence) avcEvidence = null;
        }
    }

    private void publish(JSONObject report, int token) throws Exception {
        synchronized (REPORT_LOCK) {
        if (token != generation || !running) return;
        report.put("monitoring", true).put("deviceModel", Build.MANUFACTURER + " " + Build.MODEL)
                .put("androidVersion", Build.VERSION.RELEASE).put("appVersion", appVersion)
                .put("samplingState", report.has("sampleIndex") ? "SAMPLING" : "STARTING");
        latestReport = report.toString();
        }
    }

    private void stopMonitoring(String status, String error) {
        synchronized (REPORT_LOCK) {
        running = false;
        generation++;
        if (watchdog != null) handler.removeCallbacks(watchdog);
        closeProcess(process);
        process = null;
        AvcEvidence evidence = avcEvidence;
        avcEvidence = null;
        if (evidence != null) evidence.stop();
        OverlayMonitor overlay = overlayMonitor;
        overlayMonitor = null;
        if (overlay != null) overlay.close();
        latestReport = null;
        lastError = error == null ? null : status + "\n" + error;
        stopSelf();
        }
    }

    private static void closeProcess(Process process) {
        if (process == null) return;
        try { process.getOutputStream().close(); } catch (Exception ignored) { }
        // Native --watch-stdin also exits after app death or a closed input pipe.
        process.destroy();
    }

    @Override public void onDestroy() {
        if (running) stopMonitoring("检测已结束", null);
        handler.removeCallbacksAndMessages(null);
        worker.shutdownNow();
        super.onDestroy();
    }

    @Override public IBinder onBind(Intent intent) { return null; }
}
