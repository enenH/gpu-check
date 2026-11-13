package com.gpucheck.app;

import org.json.JSONException;
import org.json.JSONObject;

/** Captures the whole report, including rows outside the on-screen CPU top ten. */
final class ReportExport {
    private ReportExport() { }

    static String snapshot(JSONObject report, long capturedAtEpochMs) throws JSONException {
        if (report == null || report.optLong("sampleIndex", -1) < 0) {
            throw new IllegalArgumentException("尚无完整采样可导出");
        }
        JSONObject copy = new JSONObject(report.toString());
        copy.put("exportMetadata", new JSONObject()
                .put("format", "gpu-check-evidence-v1")
                .put("capturedAtEpochMs", capturedAtEpochMs)
                .put("scope", "full_current_snapshot")
                .put("interpretation", "候选和时序关联不是恶意行为或 GPU 所有权证明；未命中不表示完整覆盖。"));
        return copy.toString(2);
    }
}
