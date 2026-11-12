"""Compare external fixture ground truth with actual Service and View observations."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import statistics


def read_lines(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_bytes().splitlines() if line.strip()]


def cpu_key(row: dict) -> tuple[float, int]:
    value = row.get("cpuPercent", -1)
    return (-value if isinstance(value, (int, float)) and value >= 0 else 1, row["pid"])


def fresh_root_avc(row: dict) -> bool:
    context = row.get("avcTargetContext", "").split(":")
    return (row.get("avcRootDomainHint") is True and row.get("identityVerified") is True
            and row.get("identityToken") == row.get("avcIdentityToken")
            and row.get("pid") == row.get("avcTargetPid")
            and len(context) >= 4 and context[:2] == ["u", "r"]
            and context[2] in {"su", "magisk", "ksu", "zygisk"}
            and 0 <= row.get("avcEvidenceAgeMs", -1) <= 30000)


def analyze(folder: Path, require_idle: bool) -> dict:
    metadata = json.loads((folder / "service-device-summary.json").read_bytes())
    all_reports = read_lines(folder / "service-real.jsonl")
    first_pid = metadata["firstCollectorPid"]
    reports = [r for r in all_reports if r["collectorPid"] == first_pid]
    fixtures = {mode: read_lines(folder / f"fixture-{mode}.jsonl") for mode in ("high", "low")}
    targets = {mode: data[0]["pid"] for mode, data in fixtures.items()}
    result = {"directory": str(folder), "result": metadata["result"],
              "installedVersion": metadata["installedVersion"], "reportedVersions": sorted({r["appVersion"] for r in reports}),
              "realSamples": len(reports), "targets": targets,
              "validationIssues": metadata["validationIssues"],
              "cgroupAverageMs": statistics.mean(r["cgroupScan"]["durationMs"] for r in reports),
              "cgroupMaxMs": max(r["cgroupScan"]["durationMs"] for r in reports),
              "collectionAverageMs": statistics.mean(r["collectionMs"] for r in reports),
              "collectionMaxMs": max(r["collectionMs"] for r in reports),
              "cgroupStates": sorted({r["cgroupScan"]["status"] for r in reports}),
              "cgroupAnomalyCounts": sorted({r["cgroupAnomalyCount"] for r in reports})}
    assert all(d[0]["uid"] == 0 and d[0]["euid"] == 0 for d in fixtures.values())
    assert all(d[-1]["event"] == "exiting" for d in fixtures.values())
    assert all(any(x["containsSelf"] for x in d[0]["rootFileMembership"]) for d in fixtures.values())
    assert all(not r["root"] and r["collectorUid"] >= 10000 for r in reports)
    assert all(r["processes"] == sorted(r["processes"], key=cpu_key) for r in reports)
    result["sortVerified"] = True
    result["fixturesHaveRealCgroupMembership"] = True
    high = targets["high"]
    observations = []
    for report in reports:
        visible = {p["pid"]: p for p in report["processes"]}
        for row in report["cpuSamples"]:
            if row["pid"] != high:
                continue
            observations.append({"sampleIndex": report["sampleIndex"], "elapsedMs": report["elapsedMs"],
                                 "cpuPercent": row["cpuPercent"], "identity": row["identityToken"],
                                 "freshRootAvc": fresh_root_avc(row), "visible": high in visible,
                                 "visibleCpu": visible.get(high, {}).get("cpuPercent")})
    zeros = [r for r in observations if r["cpuPercent"] == 0 and r["freshRootAvc"]]
    result["targetObservations"] = observations
    result["measuredZeroSamples"] = len(zeros)
    result["measuredZeroVisible"] = sum(r["visible"] for r in zeros)
    result["identityCountDuringTarget"] = len({r["identity"] for r in observations})
    result["busyObserved"] = sum(r["cpuPercent"] > 25 and r["visible"] for r in observations)
    assert result["busyObserved"] >= 3
    assert result["identityCountDuringTarget"] == 1
    assert all(not any(p["pid"] in targets.values() for p in r["processes"] + r["cpuSamples"]) for r in reports[-3:])
    result["targetsRemovedAfterExit"] = True
    exits = {}
    for mode, events in fixtures.items():
        pid = targets[mode]
        exited_ns = events[-1]["monotonicNs"]
        after = [r for r in reports if r["globalGpu"]["sampleMonotonicNs"]
                 - (r["collectionMs"] + 100) * 1_000_000 > exited_ns]
        assert after, "No full sampling window after fixture exit"
        assert all(not any(p["pid"] == pid for p in r["processes"] + r["cpuSamples"]) for r in after)
        signals = [e for r in after for e in r.get("recentLifecycleSignals", [])
                   if e.get("pid") == pid and e.get("kind") == "EXIT"]
        assert signals, "No actual pidfd exit signal for fixture"
        exits[mode] = {"pid": pid, "firstPostExitSample": after[0]["sampleIndex"],
                       "firstPostExitReportMs": (after[0]["globalGpu"]["sampleMonotonicNs"] - exited_ns) / 1_000_000,
                       "pidfdExitIdentity": signals[0]["identityToken"]}
    result["exitEvidence"] = exits
    report_by_key = {(r["collectorPid"], r["sampleIndex"]): r for r in all_reports}
    ui_matches = 0
    zero_hidden = 0
    resumed_shown = 0
    for ui in read_lines(folder / "service-ui.jsonl"):
        report = report_by_key.get((ui["collectorPid"], ui["sampleIndex"]))
        if report is None:
            continue
        expected = [p["pid"] for p in report["processes"]
                    if (not ui.get("zeroCpuHidden") or p.get("cpuPercent") != 0)
                    and (cpu_key(p)[0] > 0 or -cpu_key(p)[0] >= ui.get("minimumVisibleCpuPercent", 0))]
        expected = expected[:ui.get("displayLimit", len(expected))]
        assert ui["pidOrder"] == expected, (ui, expected)
        if ui.get("zeroCpuHidden"):
            target = next((p for p in report["processes"] if p["pid"] == high), None)
            if target is not None and target.get("cpuPercent") == 0:
                assert high not in ui["pidOrder"]
                zero_hidden += 1
            elif target is not None and zero_hidden and high in ui["pidOrder"]:
                resumed_shown += 1
        if expected:
            ui_matches += 1
    result["nonemptyUiOrderMatches"] = ui_matches
    result["measuredZeroUiHidden"] = zero_hidden
    result["resumedUiVisibleAfterIdle"] = resumed_shown
    assert ui_matches >= 3
    for key in ("buttonStop", "backgroundStop"):
        assert metadata[key]["reportCleared"] and metadata[key]["collectorExited"] and not metadata[key]["running"]
    result["stopAndBackgroundCleanup"] = True
    if require_idle:
        assert len(zeros) >= 3 and all(r["visible"] and r["visibleCpu"] == 0 for r in zeros), zeros
        assert metadata["result"] == "PASS" and not metadata["validationIssues"]
        assert result["reportedVersions"] == [metadata["installedVersion"]]
    (folder / "analysis.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("--require-idle", action="store_true")
    args = parser.parse_args()
    result = analyze(args.folder, args.require_idle)
    print(json.dumps({k: v for k, v in result.items() if k != "targetObservations"}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
