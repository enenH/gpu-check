package com.gpucheck.app;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.os.SystemClock;
import android.system.Os;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.util.List;
import java.util.UUID;
import java.util.function.BooleanSupplier;

/** Reconstructed Lenovo l.S/l.p route. Probes the actual component, never Build.BRAND. */
final class ZuiLayerProbe {
    static final String PACKAGE = "com.zui.SecretCode";
    private static final int MAX_DUMP_BYTES = 2 * 1024 * 1024;
    private static long lastCollectionAt = -60000;
    private static final String[] DUMPS = {"bluetooth_manager", "alarm", "appops", "input", "location", "battery",
            "batterystats", "power", "audio", "window", "activity", "notification", "meminfo", "display", "cpuinfo",
            "sensorservice", "deviceidle", "netstats", "statusbar", "SurfaceFlinger", "media.camera", "wifi"};
    private final Context context;
    ZuiLayerProbe(Context context) { this.context = context.getApplicationContext(); }

    JSONObject collect(BooleanSupplier cancelled) throws Exception {
        JSONObject result = LayerProbe.empty("zui", "CHECKING", "");
        long started = SystemClock.elapsedRealtime();
        File directory = null;
        boolean triggered = false;
        try {
            ComponentName receiver = new ComponentName(PACKAGE, PACKAGE + ".BootCompleteReceiver");
            // Package visibility is declared in <queries>; this is a capability check, not ROM identity.
            ActivityInfo info;
            try { info = context.getPackageManager().getReceiverInfo(receiver, PackageManager.MATCH_DISABLED_COMPONENTS); }
            catch (PackageManager.NameNotFoundException absent) { throw new UnsupportedOperationException("ZUI log receiver absent"); }
            result.put("receiverFound", true).put("receiverExported", info.exported).put("receiverEnabled", info.enabled);
            if (!info.enabled || !info.applicationInfo.enabled || !info.exported)
                throw new UnsupportedOperationException("ZUI log receiver unavailable");
            if (info.permission != null && context.checkSelfPermission(info.permission) != PackageManager.PERMISSION_GRANTED)
                throw new SecurityException("ZUI receiver requires " + info.permission);
            if (cancelled.getAsBoolean()) return LayerProbe.empty("zui", "CANCELLED", "Session stopped");
            synchronized (ZuiLayerProbe.class) {
                long remaining = 60000 - (SystemClock.elapsedRealtime() - lastCollectionAt);
                if (remaining > 0) return result.put("status", "COOLDOWN").put("retryAfterMs", remaining);
            }
            File external = context.getExternalFilesDir(null);
            if (external == null) throw new UnsupportedOperationException("Own external-files directory unavailable");
            File root = external.getCanonicalFile();
            directory = new File(root, "sys_gpucheck_" + UUID.randomUUID()).getCanonicalFile();
            if (!directory.getParentFile().equals(root) || !directory.mkdir()) throw new IllegalStateException("Cannot create unique log directory");
            chmod(directory, 0777);
            for (String relative : new String[]{"dumpsys", "dumpsys/dumpsys", "anr", "pstore"}) {
                File child = new File(directory, relative);
                if (!child.mkdirs() && !child.isDirectory()) throw new IllegalStateException("Cannot prepare log directory");
                chmod(child, 0777);
            }
            for (String relative : new String[]{"dumpsys", "dumpsys/dumpsys"}) for (String name : DUMPS) {
                File file = new File(directory, relative + "/dumpsys_" + name);
                if (!file.createNewFile()) throw new IllegalStateException("Unexpected existing log file");
                chmod(file, 0666);
            }
            // The OEM collector also rotates/clears its diagnostic scratch logs. We only read SF,
            // request bugreportz=false, and throttle this expensive route to one request per minute.
            result.put("vendorLogCollection", true).put("vendorDiagnosticSideEffects", true);
            context.sendBroadcast(new Intent("com.mshell.LENOVO_LOG_PROXY_INIT").setComponent(receiver)
                    .addFlags(Intent.FLAG_RECEIVER_FOREGROUND | Intent.FLAG_INCLUDE_STOPPED_PACKAGES));
            Thread.sleep(150);
            if (cancelled.getAsBoolean()) return LayerProbe.empty("zui", "CANCELLED", "Session stopped");
            context.sendBroadcast(new Intent("android.lenovo.zui.feedback.collectlog").setPackage(PACKAGE)
                    .putExtra("desdir", directory.getAbsolutePath() + "/").putExtra("bugreportz", false)
                    .addFlags(Intent.FLAG_RECEIVER_FOREGROUND | Intent.FLAG_INCLUDE_STOPPED_PACKAGES));
            triggered = true;
            synchronized (ZuiLayerProbe.class) { lastCollectionAt = SystemClock.elapsedRealtime(); }
            result.put("broadcastSent", true);
            long sent = SystemClock.elapsedRealtime();
            String previousInventory = "";
            int stable = 0;
            File[] candidates = {new File(directory, "dumpsys/dumpsys_SurfaceFlinger"),
                    new File(directory, "dumpsys/dumpsys/dumpsys_SurfaceFlinger")};
            while (SystemClock.elapsedRealtime() - sent < 30000) {
                String inventory = inventory(directory, directory, 0, new int[]{0});
                stable = inventory.equals(previousInventory) ? stable + 1 : 0;
                previousInventory = inventory;
                // Allow the vendor request to settle even if the user has stopped monitoring.
                if (SystemClock.elapsedRealtime() - sent >= 15000 && stable >= 3) break;
                Thread.sleep(750);
            }
            if (cancelled.getAsBoolean()) return LayerProbe.empty("zui", "CANCELLED", "Session stopped");
            java.util.LinkedHashMap<String, JSONObject> unique = new java.util.LinkedHashMap<>();
            for (File file : candidates) {
                if (file.length() == 0) continue;
                byte[] bytes = readOwnFile(directory, file);
                List<LayerTextParser.Row> rows = LayerTextParser.surfaceDump(new String(bytes, StandardCharsets.UTF_8));
                JSONObject evidence = new JSONObject().put("source", directory.toPath().relativize(file.toPath()).toString())
                        .put("bytes", bytes.length).put("sha256", sha256(bytes));
                for (LayerTextParser.Row row : rows) unique.put(row.name, LayerProbe.row(row.name, "zui", evidence, row.pid, row.uid));
            }
            result.put("rows", new JSONArray(unique.values())).put("available", !unique.isEmpty())
                    .put("status", unique.isEmpty() ? "NO_DATA" : "AVAILABLE");
        } catch (Exception | LinkageError error) { LayerProbe.fail(result, error); }
        finally {
            if (directory != null && directory.exists()) {
                try { deleteOwnDirectory(directory); result.put("temporaryFilesRemoved", true); }
                catch (Exception error) { result.put("temporaryFilesRemoved", false).put("cleanupError", error.toString()); }
            }
            result.put("broadcastSent", triggered).put("durationMs", SystemClock.elapsedRealtime() - started)
                    .put("observedAtMs", SystemClock.elapsedRealtime());
        }
        return result;
    }

    private static void chmod(File file, int mode) {
        try { Os.chmod(file.getAbsolutePath(), mode); } catch (Exception ignored) { /* Emulated storage may ignore modes. */ }
    }

    private static String inventory(File root, File directory, int depth, int[] count) throws Exception {
        if (depth > 8) throw new IllegalStateException("Vendor log tree too deep");
        File[] children = directory.listFiles();
        if (children == null) throw new IllegalStateException("Vendor log tree unreadable");
        java.util.Arrays.sort(children);
        StringBuilder result = new StringBuilder();
        for (File file : children) {
            if (++count[0] > 1000 || !file.getCanonicalPath().startsWith(root.getCanonicalPath() + File.separator))
                throw new IllegalStateException("Unexpected vendor log tree");
            result.append(file.getName()).append(':').append(file.length()).append(':').append(file.lastModified()).append(';');
            if (Files.isDirectory(file.toPath(), LinkOption.NOFOLLOW_LINKS)) result.append(inventory(root, file, depth + 1, count));
        }
        return result.toString();
    }

    private static byte[] readOwnFile(File root, File file) throws Exception {
        if (!file.getCanonicalPath().startsWith(root.getCanonicalPath() + File.separator)
                || !Files.isRegularFile(file.toPath(), LinkOption.NOFOLLOW_LINKS)) throw new IllegalStateException("Unsafe log file");
        long size = file.length(), modified = file.lastModified();
        if (size > MAX_DUMP_BYTES) throw new IllegalArgumentException("SurfaceFlinger dump too large");
        try (FileInputStream in = new FileInputStream(file); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int n;
            while ((n = in.read(buffer)) >= 0) {
                if (out.size() + n > MAX_DUMP_BYTES) throw new IllegalArgumentException("SurfaceFlinger dump grew beyond limit");
                out.write(buffer, 0, n);
            }
            if (file.length() != size || file.lastModified() != modified || out.size() != size)
                throw new IllegalStateException("SurfaceFlinger dump still changing");
            return out.toByteArray();
        }
    }

    private void deleteOwnDirectory(File directory) throws Exception {
        File external = context.getExternalFilesDir(null);
        if (external == null || !directory.getCanonicalFile().getParentFile().equals(external.getCanonicalFile())
                || !directory.getName().matches("sys_gpucheck_[0-9a-f-]{36}")) throw new IllegalStateException("Unsafe cleanup root");
        deleteInside(directory, directory, 0);
    }

    private static void deleteInside(File root, File file, int depth) throws Exception {
        if (depth > 8 || (!file.equals(root) && !file.getCanonicalPath().startsWith(root.getCanonicalPath() + File.separator)))
            throw new IllegalStateException("Unsafe cleanup path");
        if (Files.isDirectory(file.toPath(), LinkOption.NOFOLLOW_LINKS)) {
            File[] children = file.listFiles();
            if (children == null) throw new IllegalStateException("Cannot list temporary log directory");
            for (File child : children) deleteInside(root, child, depth + 1);
        }
        Files.deleteIfExists(file.toPath());
    }

    private static String sha256(byte[] bytes) throws Exception {
        StringBuilder result = new StringBuilder();
        for (byte b : java.security.MessageDigest.getInstance("SHA-256").digest(bytes))
            result.append(String.format(java.util.Locale.ROOT, "%02x", b & 255));
        return result.toString();
    }
}
