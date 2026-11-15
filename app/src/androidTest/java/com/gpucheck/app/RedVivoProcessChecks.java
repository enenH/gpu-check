package com.gpucheck.app;

import android.app.ActivityManager;
import android.os.Binder;
import android.os.Parcel;
import org.json.JSONArray;
import org.json.JSONObject;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Synthetic Binder/decoder controls; these are not claims of MindSync or RMS device support. */
final class RedVivoProcessChecks {
    private static int checks;

    static JSONObject run() throws Exception {
        checks = 0;
        JSONObject parsed = RedVivoProcessProbe.parseMindRecord(" 42 12.5 4096 10001 com.example:worker name ", "cpu");
        require(parsed != null && parsed.getInt("pid") == 42 && parsed.getInt("uid") == -1,
                "MindSync numerical columns never become UID");
        require(parsed.getString("name").equals("com.example:worker name")
                && parsed.getJSONObject("stats").getJSONObject("cpu").getDouble("value") == 12.5,
                "MindSync five-column record retains rest-of-line name and raw statistic");
        for (String bad : new String[]{"", "42 1 2 name", "0 1 2 3 n", "42 NaN 2 3 n", "42 Infinity 2 3 n",
                "42 -1 2 3 n", "42 1 -2 3 n", "42 1 2 -3 n", "2147483648 1 2 3 n", "42 1 2 3 bad\u0000name"})
            require(RedVivoProcessProbe.parseMindRecord(bad, "mem") == null, "Reject malformed MindSync record");
        require(RedVivoProcessProbe.fingerprintTransaction(RedVivoProcessProbe.NX769J_FINGERPRINT) == 66
                && RedVivoProcessProbe.fingerprintTransaction("nubia/NX769J/other") < 0
                && RedVivoProcessProbe.fingerprintTransaction(RedVivoProcessProbe.NX769J_FINGERPRINT + "x") < 0,
                "66 only applies to exactly recovered fingerprint");

        MindBinder mind = new MindBinder();
        RedVivoProcessProbe probe = new RedVivoProcessProbe(null, mind, 66, null, -1);
        JSONObject mindResult = probe.mindsync(new int[0], () -> false);
        require(mindResult.getBoolean("available") && mind.commands.equals(Arrays.asList("init", "mem", "cpu")),
                "MindSync init, mem, cpu wire order");
        require(mindResult.getJSONArray("rows").length() == 1 && mindResult.getInt("malformedRows") == 1,
                "MindSync removes conflicting PID identities");
        JSONObject mindRow = mindResult.getJSONArray("rows").getJSONObject(0);
        require(mindRow.getInt("pid") == 44 && mindRow.getJSONObject("stats").has("mem")
                && mindRow.getJSONObject("stats").has("cpu"), "Matching MindSync identity merges phases");
        for (String mode : new String[]{"denied", "unhandled", "oversized", "trailing", "short_string"}) {
            mind.mode = mode;
            JSONObject result = probe.mindsync(new int[0], () -> false);
            require(!result.optBoolean("available") && result.getJSONArray("rows").length() == 0,
                    "MindSync rejects " + mode);
        }
        mind.mode = "more_rows";
        JSONObject truncated = probe.mindsync(new int[0], () -> false);
        require(truncated.getBoolean("available") && truncated.getBoolean("truncated")
                && truncated.getJSONArray("rows").length() == RedVivoProcessProbe.MIND_MAX_ROWS
                && truncated.getString("status").equals("PARTIAL"), "MindSync truncates a valid larger top list explicitly");
        int before = mind.commands.size();
        require(probe.mindsync(new int[0], () -> true).getString("status").equals("CANCELLED")
                && before == mind.commands.size(), "MindSync cancellation prevents request");

        VivoBinder vivo = new VivoBinder();
        ActivityManager.RunningAppProcessInfo info = RedVivoProcessProbe.queryVivo(vivo, 37, 77);
        require(info.pid == 77 && info.uid == 10077 && info.processName.equals("process.77"),
                "RMS bare PID request and Parcelable-before-exception reply");
        for (String mode : new String[]{"mismatched_pid", "invalid_uid", "unhandled", "denied", "trailer_denied",
                "truncated", "trailing", "oversized_array"}) {
            vivo.mode = mode;
            boolean rejected = false;
            try { RedVivoProcessProbe.queryVivo(vivo, 37, 77); }
            catch (Exception expected) { rejected = true; }
            require(rejected, "RMS rejects " + mode);
        }
        vivo.mode = "missing";
        require(RedVivoProcessProbe.queryVivo(vivo, 37, 77) == null, "RMS empty process is absence");
        vivo.mode = "ok";
        RedVivoProcessProbe vivoProbe = new RedVivoProcessProbe(null, null, -1, vivo, 37);
        int[] candidates = new int[300];
        for (int i = 0; i < candidates.length; i++) candidates[i] = 900000 + i;
        vivo.pids.clear();
        JSONObject first = vivoProbe.vivo(candidates, () -> false);
        require(first.getBoolean("available") && first.getInt("queriedCandidates") > 0
                && first.getInt("queriedCandidates") < candidates.length
                && vivo.pids.size() <= RedVivoProcessProbe.VIVO_QUERY_BUDGET, "RMS bounded candidate queries including control");
        Set<Integer> seen = new HashSet<>(vivo.pids);
        vivo.pids.clear();
        JSONObject second = vivoProbe.vivo(candidates, () -> false);
        seen.addAll(vivo.pids);
        require(second.getBoolean("available") && seen.contains(900299), "RMS cursor reaches candidates beyond first batch");
        require(first.getBoolean("coverageLimited") && !first.getBoolean("allCandidatesQueried"),
                "RMS does not claim whole-device enumeration");
        require(vivoProbe.vivo(candidates, () -> true).getString("status").equals("CANCELLED"), "RMS cancellation");
        return new JSONObject().put("result", "PASS").put("synthetic", true).put("checks", checks);
    }

    private static void require(boolean value, String message) {
        if (!value) throw new AssertionError(message);
        checks++;
    }

    private static final class MindBinder extends Binder {
        String mode = "ok";
        final List<String> commands = new ArrayList<>();
        MindBinder() { attachInterface(null, RedVivoProcessProbe.MIND_DESCRIPTOR); }
        @Override protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) {
            data.enforceInterface(RedVivoProcessProbe.MIND_DESCRIPTOR);
            String phase = data.readString();
            require(code == 66 && data.dataAvail() == 0, "MindSync exact request encoding");
            commands.add(phase);
            if (mode.equals("unhandled")) return false;
            if (mode.equals("denied")) { reply.writeException(new SecurityException("Synthetic denial")); return true; }
            reply.writeNoException();
            if (mode.equals("oversized")) { reply.writeInt(65); return true; }
            if (mode.equals("short_string")) { reply.writeInt(1); reply.writeInt(1000); return true; }
            if (mode.equals("more_rows")) {
                List<String> more = new ArrayList<>();
                for (int i = 0; i < 65; i++) more.add((100 + i) + " 1 2 3 proc" + i);
                reply.writeStringList(more); return true;
            }
            reply.writeStringList(phase.equals("mem") ? Arrays.asList("44 1.25 3000 10044 proc44", "55 0 10 1 first")
                    : phase.equals("cpu") ? Arrays.asList("44 23.5 3000 10044 proc44", "55 0 10 1 replacement")
                    : new ArrayList<>());
            if (mode.equals("trailing")) reply.writeInt(100);
            return true;
        }
    }

    private static final class VivoBinder extends Binder {
        String mode = "ok";
        final List<Integer> pids = new ArrayList<>();
        VivoBinder() { attachInterface(null, RedVivoProcessProbe.VIVO_DESCRIPTOR); }
        @Override protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) {
            require(code == 37 && data.dataAvail() == 4, "RMS has a bare PID without token");
            int pid = data.readInt(); pids.add(pid);
            if (mode.equals("unhandled")) return false;
            if (mode.equals("denied")) { reply.writeException(new SecurityException("Synthetic denial")); return true; }
            if (mode.equals("truncated")) { reply.writeString("process"); return true; }
            if (mode.equals("oversized_array")) {
                reply.writeString("process"); reply.writeInt(pid); reply.writeInt(10000); reply.writeInt(Integer.MAX_VALUE); return true;
            }
            ActivityManager.RunningAppProcessInfo info = new ActivityManager.RunningAppProcessInfo();
            if (!mode.equals("missing")) {
                info.processName = "process." + pid;
                info.pid = mode.equals("mismatched_pid") ? pid + 1 : pid;
                info.uid = mode.equals("invalid_uid") ? -1 : pid == android.os.Process.myPid()
                        ? android.os.Process.myUid() : 10000 + pid;
            }
            info.writeToParcel(reply, 0);
            if (mode.equals("trailer_denied")) reply.writeException(new SecurityException("Synthetic trailer denial"));
            else reply.writeNoException();
            if (mode.equals("trailing")) reply.writeInt(99);
            return true;
        }
    }
}
