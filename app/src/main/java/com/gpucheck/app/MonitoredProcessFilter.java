package com.gpucheck.app;

/** Admission to observation only; cgroup anomalies never establish root identity. */
public final class MonitoredProcessFilter {
    private MonitoredProcessFilter() { }

    public static boolean accepts(boolean self, boolean rootCandidate, boolean cgroupAnomaly) {
        return !self && (rootCandidate || cgroupAnomaly);
    }

    public static boolean isSelf(int pid, int uid, int collectorPid, int appPid, int appUid) {
        return (pid > 0 && (pid == collectorPid || pid == appPid))
                || (uid >= 0 && appUid >= 0 && uid == appUid);
    }
}
