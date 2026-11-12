package com.gpucheck.app;

import android.os.Binder;
import android.os.Parcel;
import org.json.JSONArray;
import org.json.JSONObject;
import java.util.Arrays;

/** Synthetic protocol regressions live only in the test APK. They are not device detection evidence. */
final class OverlayBinderChecks {
    private static int checks;
    static JSONObject run() throws Exception {
        checks = 0;
        FakeBinder binder = new FakeBinder();
        LayerProbe probe = new LayerProbe("com.gpucheck.app", binder);
        JSONObject observed = probe.oplus(() -> false);
        require(observed.optBoolean("available") && hasSuspicious(observed), "Oplus discovers unknown title");
        require(observed.getInt("queryCount") <= LayerProbe.QUERY_BUDGET, "Oplus transaction budget");
        binder.mode = "clear";
        require(!hasSuspicious(probe.oplus(() -> false)), "Removed title must not remain cached");
        binder.mode = "masked";
        LayerProbe masked = new LayerProbe("com.gpucheck.app", binder);
        require(hasSuspicious(masked.oplus(() -> false)), "Find random title when all single-character queries are masked");
        binder.mode = "masked_clear";
        require(!hasSuspicious(masked.oplus(() -> false)), "Masked target disappearance clears exact-name revalidation");
        binder.mode = "vri";
        JSONObject vri = new LayerProbe("com.gpucheck.app", binder).oplus(() -> false);
        require(vri.optBoolean("available") && !hasSuspicious(vri), "VRI component must not cause overlay alert");
        boolean vriObserved = false;
        for (int i = 0; i < vri.getJSONArray("rows").length(); i++) {
            JSONObject row = vri.getJSONArray("rows").getJSONObject(i);
            if (row.optString("name").equals("VRI-com.gpucheck.app/com.gpucheck.app.MainActivity#")) {
                vriObserved = true;
                require(row.optString("normalizedName").startsWith("VRI-") && row.optString("reason").contains("已过滤"),
                        "VRI raw name and explicit exclusion reason retained");
            }
        }
        require(vriObserved, "VRI control actually returned through Binder query");
        for (String mode : new String[]{"vri_unknown", "vri_keyword"}) {
            binder.mode = mode;
            JSONObject filtered = new LayerProbe("com.gpucheck.app", binder).oplus(() -> false);
            require(filtered.optBoolean("available") && !hasSuspicious(filtered)
                    && filtered.getJSONArray("rows").length() > 0, "Exclude every VRI prefix: " + mode);
        }
        for (String mode : new String[]{"mismatch", "unhandled", "denied", "malformed"}) {
            binder.mode = mode;
            JSONObject failed = probe.oplus(() -> false);
            require(!failed.optBoolean("available") && !hasSuspicious(failed), "Reject " + mode);
            if (mode.equals("denied")) require(failed.getString("status").equals("BLOCKED"), "Distinguish denied");
            if (mode.equals("unhandled")) require(failed.getString("status").equals("UNSUPPORTED"), "Distinguish unhandled");
            if (mode.equals("malformed")) require(failed.getJSONObject("queryEvidence").has("replyBase64"), "Keep malformed reply evidence");
        }
        binder.mode = "ok";
        JSONObject nubia = probe.nubia(() -> false);
        require(nubia.optBoolean("available") && hasSuspicious(nubia), "Nubia String8 list");
        require(nubia.getJSONArray("attempts").length() == 2 && binder.nubiaCalls == 2, "Try both recovered Nubia codes");
        require(nubia.getJSONArray("rows").getJSONObject(0).isNull("ownerPid"), "Nubia layer suffix is not PID");
        binder.mode = "list_error";
        require(!probe.nubia(() -> false).optBoolean("available"), "Nubia error text is not a name");
        require(probe.oplus(() -> true).getString("status").equals("CANCELLED"), "Cancelled scan");
        binder.attachInterface(null, "not.surface.composer");
        require(probe.oplus(() -> false).getString("status").equals("UNSUPPORTED"), "Validate service descriptor");
        return new JSONObject().put("result", "PASS").put("synthetic", true).put("checks", checks);
    }

    private static boolean hasSuspicious(JSONObject report) throws Exception {
        JSONArray rows = report.getJSONArray("rows");
        for (int i = 0; i < rows.length(); i++) if (rows.getJSONObject(i).optBoolean("suspicious")) return true;
        return false;
    }
    private static void require(boolean condition, String reason) { if (!condition) throw new AssertionError(reason); checks++; }

    private static final class FakeBinder extends Binder {
        String mode = "ok";
        int nubiaCalls;
        FakeBinder() { attachInterface(null, LayerProbe.DESCRIPTOR); }
        @Override protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) {
            data.enforceInterface(LayerProbe.DESCRIPTOR);
            if (mode.equals("unhandled")) return false;
            if (mode.equals("denied")) throw new SecurityException("Test permission denial");
            if (mode.equals("malformed")) { reply.writeInt(42); return true; }
            if (code == LayerProbe.OPLUS_STATUS) {
                String target = data.readString();
                String value = "";
                if (mode.equals("mismatch")) value = "unrelated#55";
                else if (mode.startsWith("masked")) {
                    // All alphabet characters are present in an earlier, explainable component.
                    String normal = "com.example.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/abc.Main#1";
                    if (normal.contains(target)) value = normal;
                    else if (mode.equals("masked") && "j2v7random#42".contains(target)) value = "j2v7random#42";
                }
                else for (String name : mode.equals("vri_unknown") ? new String[]{"VRI-randomOverlay#17"}
                        : mode.equals("vri_keyword") ? new String[]{"VRI-ImGui#23"} : mode.equals("vri")
                        ? new String[]{"VRI-com.gpucheck.app/com.gpucheck.app.MainActivity#"}
                        : mode.equals("clear") ? new String[]{"StatusBar#1"}
                        : new String[]{"StatusBar#1", "q7randomTitle#42"}) {
                    if (name.contains(target)) { value = name; break; }
                }
                reply.writeString(value);
                return true;
            }
            if (code == 77 || code == 73) {
                nubiaCalls++;
                byte[] request = data.marshall();
                String command = LayerReplyDecoder.decode(Arrays.copyOfRange(request, data.dataPosition(), request.length), true).value;
                require(command.equals("list_layer"), "Nubia command encoding");
                if (code == 77) return false;
                byte[] bytes = LayerReplyDecoder.string8(mode.equals("list_error") ? "Permission denied" : "StatusBar#1\nrandomTitle#42\n");
                Parcel encoded = Parcel.obtain();
                try { encoded.unmarshall(bytes, 0, bytes.length); reply.appendFrom(encoded, 0, bytes.length); }
                finally { encoded.recycle(); }
                return true;
            }
            return false;
        }
    }
}
