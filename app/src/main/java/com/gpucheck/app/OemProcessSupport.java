package com.gpucheck.app;

import android.content.Context;
import android.os.BadParcelableException;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import android.os.SystemClock;
import dalvik.system.PathClassLoader;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.CancellationException;

/** Ordinary-app OEM service access. No guessed transaction numbers or permission bypass. */
final class OemProcessSupport {
    static final int MAX_ROWS = 4096;
    static final int MAX_REPLY_BYTES = 2 * 1024 * 1024;
    private static final boolean NATIVE_READY;
    static {
        boolean ready = false;
        try { System.loadLibrary("gpu_layer"); ready = true; }
        catch (LinkageError | SecurityException unavailable) { /* Normal Java lookup remains available. */ }
        NATIVE_READY = ready;
    }
    private OemProcessSupport() { }

    private static native IBinder lookupBinder(String name);
    private static native int openPidfdNative(int pid);
    private static native boolean pidfdAliveNative(int fd);
    private static native void closePidfdNative(int fd);

    static IBinder service(String name) throws Exception {
        if (name == null || name.isEmpty() || name.length() > 256 || name.indexOf('\0') >= 0)
            throw new IllegalArgumentException("Invalid service name");
        IBinder binder = NATIVE_READY ? lookupBinder(name) : null;
        if (binder == null) {
            try {
                Object value = Class.forName("android.os.ServiceManager")
                        .getDeclaredMethod("checkService", String.class).invoke(null, name);
                if (value instanceof IBinder) binder = (IBinder) value;
            } catch (ReflectiveOperationException error) {
                Throwable cause = rootCause(error);
                if (cause instanceof SecurityException) throw (SecurityException) cause;
                throw new UnsupportedOperationException("Service lookup unavailable: " + name, error);
            }
        }
        if (binder == null || !binder.isBinderAlive())
            throw new UnsupportedOperationException("Service absent or inaccessible: " + name);
        return binder;
    }

    static IBinder service(String name, String expectedDescriptor) throws Exception {
        IBinder binder = service(name);
        if (!expectedDescriptor.equals(binder.getInterfaceDescriptor()))
            throw new UnsupportedOperationException("Unexpected descriptor for " + name);
        return binder;
    }

    static Class<?> loadClass(Context context, String className, String... jarPaths) throws ClassNotFoundException {
        ClassLoader parent = context == null ? OemProcessSupport.class.getClassLoader() : context.getClassLoader();
        ClassNotFoundException missing;
        try { return Class.forName(className, false, parent); }
        catch (ClassNotFoundException error) { missing = error; }
        StringBuilder available = new StringBuilder();
        for (String path : jarPaths) {
            if (path == null || !(path.startsWith("/system/") || path.startsWith("/system_ext/")
                    || path.startsWith("/product/") || path.startsWith("/vendor/")) || !new File(path).isFile()) continue;
            if (available.length() > 0) available.append(File.pathSeparatorChar);
            available.append(path);
        }
        if (available.length() > 0)
            return Class.forName(className, false, new PathClassLoader(available.toString(), parent));
        throw missing;
    }

    static int transactionCode(Context context, String stubClass, String methodName, String... jarPaths) throws Exception {
        String[] fields = methodName.startsWith("TRANSACTION_") || methodName.equals(methodName.toUpperCase(java.util.Locale.ROOT))
                ? new String[]{methodName} : new String[]{"TRANSACTION_" + methodName, methodName};
        Throwable reflectionFailure = null;
        try {
            Class<?> type = loadClass(context, stubClass, jarPaths);
            for (String name : fields) {
                try {
                    Field field = type.getDeclaredField(name);
                    field.setAccessible(true);
                    int value = field.getInt(null);
                    if (validCode(value)) return value;
                } catch (ReflectiveOperationException | RuntimeException | LinkageError failure) { reflectionFailure = failure; }
            }
        } catch (ReflectiveOperationException | RuntimeException | LinkageError failure) { reflectionFailure = failure; }
        for (String name : fields) {
            int value = OemDexConstants.resolve(stubClass, name, jarPaths);
            if (validCode(value)) return value;
        }
        throw new UnsupportedOperationException("Transaction constant unavailable: " + stubClass + "." + methodName,
                reflectionFailure);
    }

    private static boolean validCode(int value) { return value >= IBinder.FIRST_CALL_TRANSACTION && value <= IBinder.LAST_CALL_TRANSACTION; }

    static JSONObject empty(String route, String status, String detail) throws JSONException {
        return new JSONObject().put("route", route).put("status", status).put("available", false)
                .put("rows", new JSONArray()).put("detail", detail == null ? "" : detail)
                .put("observedAtMs", SystemClock.elapsedRealtime()).put("coverageLimited", true)
                .put("brandGateUsed", false);
    }

    static JSONObject row(int pid, int uid, String name, int ppid, String source) throws JSONException {
        if (pid <= 0 || uid < -1 || ppid < -1) throw new IllegalArgumentException("Invalid process identity fields");
        String safeName = name == null ? "" : name;
        if (safeName.length() > 4096 || safeName.indexOf('\0') >= 0) throw new IllegalArgumentException("Invalid process name");
        return new JSONObject().put("pid", pid).put("uid", uid).put("name", safeName)
                .put("ppid", ppid).put("source", source == null ? "" : source);
    }

    static void checkReply(Parcel reply) {
        if (reply.dataSize() < 4 || reply.dataSize() > MAX_REPLY_BYTES)
            throw new IllegalArgumentException("Invalid OEM reply size: " + reply.dataSize());
    }

    static Throwable rootCause(Throwable error) {
        Throwable cause = error;
        for (int i = 0; i < 8 && cause instanceof InvocationTargetException && cause.getCause() != null; i++) cause = cause.getCause();
        return cause;
    }

    static String status(Throwable error) {
        Throwable cause = rootCause(error);
        if (cause instanceof SecurityException) return "BLOCKED";
        if (cause instanceof CancellationException || cause instanceof InterruptedException) return "CANCELLED";
        if (cause instanceof UnsupportedOperationException || cause instanceof ReflectiveOperationException || cause instanceof LinkageError)
            return "UNSUPPORTED";
        if (cause instanceof BadParcelableException || cause instanceof IllegalArgumentException) return "MALFORMED";
        if (cause instanceof RemoteException) return "UNAVAILABLE";
        return "FAILED";
    }

    static int openPidfd(int pid) { return NATIVE_READY && pid > 0 ? openPidfdNative(pid) : -1; }
    static boolean pidfdAlive(int fd) { return NATIVE_READY && fd >= 0 && pidfdAliveNative(fd); }
    static void closePidfd(int fd) { if (NATIVE_READY && fd >= 0) closePidfdNative(fd); }
}
