"""Validate actual Service evidence for calibrated stat UID/PID path detection."""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import statistics


def analyze(folder: Path, require_target: bool = False) -> dict:
    metadata = json.loads((folder / "service-device-summary.json").read_bytes())
    reports = [json.loads(line) for line in (folder / "service-real.jsonl").read_bytes().splitlines() if line.strip()]
    assert metadata["result"] == "PASS" and not metadata["validationIssues"], metadata
    assert reports, "No real Service samples"
    first = [r for r in reports if r["collectorPid"] == metadata["firstCollectorPid"]]
    states, reasons = Counter(), Counter()
    generations, uids = set(), set()
    available = anomalies = 0
    for report in reports:
        scan = report["cgroupScan"]
        assert scan["method"] == "stat_uid_pid_paths", scan
        assert scan["sampleIndex"] == report["sampleIndex"]
        assert not report["root"] and report["collectorUid"] >= 10000
        uids.add(report["collectorUid"])
        states[scan["status"]] += 1
        available += scan["available"] and scan["calibrationValid"]
        rows = report["processes"]
        def order(row: dict) -> tuple[float, int]:
            cpu = row.get("cpuPercent")
            return (-cpu if isinstance(cpu, (float, int)) and cpu >= 0 else 1, row["pid"])
        assert rows == sorted(rows, key=order), "Unified list is not CPU descending"
        for row in rows:
            check = row.get("cgroupCheck", {})
            reasons[check.get("reason", "no_check")] += 1
            if not row.get("cgroupAnomaly"):
                continue
            anomalies += 1
            assert scan["available"] and scan["calibrationValid"]
            assert check["state"] == "MISSING"
            for key in ("procPresent", "stableIdentity", "nonZombie", "pathCalibrationValid",
                        "pathCoverageComplete", "uidCoverageComplete"):
                assert check[key] is True, (row["pid"], key)
            assert check["pathFound"] is False
            assert check["testedPathCount"] == check["missingPathCount"] >= check["testedUidCount"] > 0
            assert check["coverageScope"] == "observed_uid_catalog"
            assert check["identityToken"] == row["identityToken"]
            assert check["sampleIndex"] == report["sampleIndex"]
            assert check["procEvidence"]["pidfdLiveBefore"] and check["procEvidence"]["pidfdLiveAfter"]
            generations.add(check["uidCatalogGeneration"])
            watch = row["cgroupWatch"]
            assert watch["status"] == "ANOMALY" and watch["consecutive"] >= 3
            assert watch["lastSampleIndex"] == report["sampleIndex"]
            assert watch["lastSampleIndex"] - watch["firstSampleIndex"] >= 2
    assert available >= 3, "Stat-path method never became consistently available"
    result = {
        "result": "PASS", "folder": str(folder), "version": metadata["installedVersion"],
        "samples": len(reports), "ordinaryAppUids": sorted(uids), "availableSamples": available,
        "scanStates": dict(states), "confirmedAnomalyObservations": anomalies,
        "catalogGenerationsWithAnomalies": sorted(generations), "checkReasons": dict(reasons),
        "cgroupAverageMs": statistics.mean(r["cgroupScan"]["durationMs"] for r in first),
        "cgroupMaxMs": max(r["cgroupScan"]["durationMs"] for r in first),
        "collectionAverageMs": statistics.mean(r["collectionMs"] for r in first),
        "collectionMaxMs": max(r["collectionMs"] for r in first),
        "maximumVisibleCandidates": max(len(r["processes"]) for r in first),
        "cpuOrderVerified": True,
    }
    target_file = folder / "dfm-test-summary.json"
    if target_file.exists():
        target = json.loads(target_file.read_bytes())
        pid = target["target"]["pid"]
        observations = [(r, p) for r in first for p in r["processes"] if p["pid"] == pid]
        matches = [(r, p) for r, p in observations if p.get("cgroupAnomaly")]
        assert target["detectorReceivedTargetPid"] is False
        assert target["enteredRenderLoop"] and target["gameInitialized"]
        assert target["terminationCommandExit"] == 0
        assert observations, "Real dfm_plus was never observed"
        assert all(not any(p["pid"] == pid for p in r["processes"]) for r in first[-3:]), "Target survived cleanup in report"
        if require_target:
            assert len(matches) >= 3, "Real dfm_plus did not receive three confirmed path-mismatch observations"
        cpus = [p["cpuPercent"] for _, p in observations if isinstance(p.get("cpuPercent"), (int, float))]
        result["dfm"] = {
            "pid": pid, "observations": len(observations), "pathAnomalyObservations": len(matches),
            "highRiskObservations": sum(p.get("risk") == "HIGH" for _, p in observations),
            "lifecycleOnsetObservations": sum(p.get("cpuGpuLifecycle", {}).get("state") == "ONSET_MATCH"
                                              for _, p in observations),
            "cpuMin": min(cpus) if cpus else None, "cpuMax": max(cpus) if cpus else None,
            "identityCount": len({p["identityToken"] for _, p in observations}),
            "autonomouslyDiscovered": True, "removedAfterExit": True,
            "firstPathAnomalySample": matches[0][0]["sampleIndex"] if matches else None,
        }
        assert result["dfm"]["identityCount"] == 1
        terminated = json.loads((folder / "dfm-termination.json").read_bytes())
        assert terminated["pidfdExited"] and terminated["pid"] == pid
        after_exit = [r for r in first if r["globalGpu"]["sampleMonotonicNs"] > terminated["monotonicNs"]
                      and not any(p["pid"] == pid for p in r["processes"])]
        assert after_exit, "No post-exit report removed the target"
        result["dfm"]["firstRemovalReportMsAfterTermination"] = (
            after_exit[0]["globalGpu"]["sampleMonotonicNs"] - terminated["monotonicNs"]) / 1_000_000
    elif require_target:
        raise AssertionError("No real dfm_plus test summary")
    for key in ("buttonStop", "backgroundStop"):
        assert metadata[key]["reportCleared"] and metadata[key]["collectorExited"] and not metadata[key]["running"]
    result["stopAndBackgroundCleanup"] = True
    (folder / "path-analysis.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("--require-target-anomaly", action="store_true")
    args = parser.parse_args()
    print(json.dumps(analyze(args.folder, args.require_target_anomaly), ensure_ascii=False, indent=2))
