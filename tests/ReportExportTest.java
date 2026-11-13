package com.gpucheck.app;

import org.json.JSONArray;
import org.json.JSONObject;

public final class ReportExportTest {
    public static void main(String[] args) throws Exception {
        JSONObject report = new JSONObject().put("sampleIndex", 7);
        JSONArray processes = new JSONArray();
        for (int i = 0; i < 12; i++) processes.put(new JSONObject().put("pid", 100 + i));
        report.put("processes", processes).put("globalGpu", new JSONObject()
                .put("slotDeltas", new JSONArray().put(JSONObject.NULL).put(4)));
        report.put("overlay", new JSONObject().put("coverageLimited", true));
        String frozen = ReportExport.snapshot(report, 12345);
        JSONObject exported = new JSONObject(frozen);
        check(exported.getJSONArray("processes").length() == 12, "CPU top-ten must not truncate export");
        check(exported.getJSONObject("globalGpu").getJSONArray("slotDeltas").isNull(0), "unknown stays null");
        check(exported.getJSONObject("overlay").getBoolean("coverageLimited"), "retain coverage limitations");
        check(exported.getJSONObject("exportMetadata").getLong("capturedAtEpochMs") == 12345, "capture time");
        check(!report.has("exportMetadata"), "export must not modify the live report");
        report.getJSONArray("processes").getJSONObject(0).put("pid", 999);
        report.put("sampleIndex", 8);
        check(new JSONObject(frozen).getLong("sampleIndex") == 7, "snapshot survives next sample");
        check(new JSONObject(frozen).getJSONArray("processes").getJSONObject(0).getInt("pid") == 100,
                "nested snapshot must be immutable");
        for (JSONObject invalid : new JSONObject[]{null, new JSONObject(), new JSONObject().put("sampleIndex", -1)}) {
            boolean rejected = false;
            try { ReportExport.snapshot(invalid, 0); }
            catch (IllegalArgumentException expected) { rejected = true; }
            check(rejected, "missing baseline cannot be exported");
        }
        System.out.println("ReportExport: 10 regression checks passed.");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
