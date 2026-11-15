package com.gpucheck.app;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;

/** Independent test APK UID. Supplies real EGL work without giving the detector any slot or PID. */
public final class GpuExecFixtureService extends Service {
    private SelfGpuInstrumentation.EglWorkload workload;
    private final Handler timeout = new Handler(Looper.getMainLooper());
    @Override public void onCreate() {
        super.onCreate();
        workload = new SelfGpuInstrumentation.EglWorkload(); workload.start();
        timeout.postDelayed(() -> { workload.running = false; stopSelf(); }, 60000);
    }
    @Override public IBinder onBind(Intent intent) { return new Binder(); }
    @Override public void onDestroy() {
        timeout.removeCallbacksAndMessages(null);
        if (workload != null) {
            workload.running = false;
            try { workload.join(1500); } catch (InterruptedException error) { Thread.currentThread().interrupt(); }
        }
        super.onDestroy();
    }
}
