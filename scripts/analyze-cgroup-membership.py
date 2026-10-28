"""Summarize cgroup audit snapshots without treating EACCES as presence."""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import posixpath
import re
import stat


def rows(data: dict, key: str) -> dict[int, dict]:
    return {row["pid"]: row for row in data[key]["pids"]}


def identity(row: dict) -> int | None:
    stat = row["stat"]
    return stat.get("starttime") if stat["errno"] == 0 and stat.get("parse_errno", 0) == 0 else None


def stable_between(first: dict[int, dict], last: dict[int, dict]) -> dict[int, dict]:
    return {pid: row for pid, row in first.items()
            if pid in last and identity(row) is not None and identity(row) == identity(last[pid])}


def assignments(row: dict) -> list[tuple[str, str, str]]:
    if row["cgroup"]["errno"]:
        return []
    result = []
    for line in row["cgroup"]["text"].splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3:
            result.append(tuple(parts))
    return result


def membership(data: dict) -> tuple[set[int], set[int], set[int]]:
    procs, tids, directory_pids = set(), set(), set()
    for mount in data["mounts"]:
        for group in mount["groups"]:
            procs.update(group["procs"].get("members", []))
            for key in ("tasks", "threads"):
                tids.update(group.get(key, {}).get("members", []))
            match = re.search(r"/pid_(\d+)$", group["path"])
            if match:
                directory_pids.add(int(match.group(1)))
    return procs, tids, directory_pids


def mapped_groups(data: dict, assignment: tuple[str, str, str]) -> list[dict]:
    hierarchy, controllers, cgpath = assignment
    result = []
    for mount in data["mounts"]:
        if hierarchy == "0":
            if mount["fstype"] != "cgroup2":
                continue
        elif mount["fstype"] != "cgroup" or not set(controllers.split(",")).issubset(
                set(mount["super_options"].split(","))):
            continue
        root = mount["root"].rstrip("/")
        if root and cgpath != root and not cgpath.startswith(root + "/"):
            continue
        relative = cgpath[len(root):].lstrip("/")
        fullpath = posixpath.normpath(posixpath.join(mount["mountpoint"], relative))
        result.extend(group for group in mount["groups"] if group["path"] == fullpath)
    return result


def short_row(row: dict) -> dict:
    raw = row["stat"].get("raw", "")
    comm = raw[raw.find("(") + 1:raw.rfind(")")] if "(" in raw else None
    return {"pid": row["pid"], "uid": row["status"].get("uid"), "comm": comm,
            "state": row["stat"].get("state"), "starttime": row["stat"].get("starttime"),
            "cgroup": row["cgroup"].get("text"), "cgroup_errno": row["cgroup"]["errno"]}


def dedicated_present(row: dict) -> bool:
    return any(probe["errno"] == 0 and stat.S_ISDIR(probe["mode"])
               and probe["path"].endswith("/pid_" + str(row["pid"]))
               for probe in row.get("directory_probes", []))


def summarize(data: dict) -> dict:
    before, after = rows(data, "proc_before"), rows(data, "proc_after")
    stable = stable_between(before, after)
    alive = {pid: row for pid, row in stable.items()
             if row["stat"].get("state") not in ("Z", "X", "x")
             and after[pid]["stat"].get("state") not in ("Z", "X", "x")}
    zombies = {pid: row for pid, row in stable.items()
               if row["stat"].get("state") == "Z" and after[pid]["stat"].get("state") == "Z"}
    procs, tids, directory_pids = membership(data)
    stable_ids, live_ids = set(stable), set(alive)
    with_assignment = {pid for pid, row in stable.items() if assignments(row)}
    mapped, matched, unchanged = set(), set(), set()
    location_misses = []
    for pid, row in stable.items():
        entries = assignments(row)
        if row["cgroup"] == after[pid]["cgroup"]:
            unchanged.add(pid)
        groups_per_entry = [mapped_groups(data, entry) for entry in entries]
        if entries and all(groups_per_entry):
            mapped.add(pid)
            if all(any(pid in group["procs"].get("members", []) for group in groups)
                   for groups in groups_per_entry):
                matched.add(pid)
            elif pid in alive and pid in unchanged:
                location_misses.append(short_row(row))
    hierarchy = []
    for mount in data["mounts"]:
        members = set()
        root_members = set()
        errors = Counter()
        scans = Counter()
        entry_errors = Counter()
        parse_errors = Counter()
        for group in mount["groups"]:
            if group["procs"]["errno"]:
                errors[group["procs"]["errno"]] += 1
            if group["procs"].get("parse_errno", 0):
                parse_errors[group["procs"]["parse_errno"]] += 1
            entry_errors.update(entry["errno"] for entry in group.get("entry_errors", []))
            members.update(group["procs"].get("members", []))
            if group["path"] == mount["mountpoint"]:
                root_members.update(group["procs"].get("members", []))
            if group["scan_errno"]:
                scans[group["scan_errno"]] += 1
        hierarchy.append({"mountpoint": mount["mountpoint"], "fstype": mount["fstype"],
                          "controllers": mount["super_options"], "groups": len(mount["groups"]),
                          "procs_read_errors": dict(errors), "directory_scan_errors": dict(scans),
                          "procs_parse_errors": dict(parse_errors), "directory_entry_errors": dict(entry_errors),
                          "complete_read": not any([errors, scans, parse_errors, entry_errors]),
                          "stable_live_found": len(live_ids & members),
                          "stable_live_missing": sorted(live_ids - members),
                          "stable_zombies_found": sorted(set(zombies) & members),
                          "stable_live_at_root": len(live_ids & root_members),
                          "root_pids_sample": sorted(live_ids & root_members)[:20]})
    fixtures = data.get("fixtures", {})
    fixture_evidence = {}
    for name in ("live_pid", "zombie_pid"):
        pid = fixtures.get(name)
        if pid in before:
            fixture_evidence[name] = {**short_row(before[pid]), "stable": pid in stable,
                                      "in_procs_union": pid in procs, "in_tasks_threads_union": pid in tids,
                                      "has_dedicated_directory": dedicated_present(before[pid])}
    return {
        "uid": data["meta"]["uid"], "selinux": data["meta"]["selinux"],
        "proc_before_count": len(before), "proc_after_count": len(after),
        "proc_list_errno": data["proc_before"]["errno"], "stable_count": len(stable),
        "proc_list_entry_errors": data["proc_before"].get("entry_errors", []),
        "mountinfo_errno": data["mountinfo"]["errno"],
        "all_mounts_read_completely": bool(hierarchy) and data["mountinfo"]["errno"] == 0
                                     and all(item["complete_read"] for item in hierarchy),
        "unstable_or_unreadable_pids": sorted(set(before) - stable_ids),
        "stable_live_count": len(alive), "stable_zombie_count": len(zombies),
        "stable_with_cgroup_record": len(with_assignment), "stable_all_groups_mapped": len(mapped),
        "stable_matched_in_every_recorded_group": len(matched),
        "stable_found_in_procs_union": len(stable_ids & procs),
        "stable_live_found_in_procs_union": len(live_ids & procs),
        "stable_live_missing_from_procs": [short_row(alive[pid]) for pid in sorted(live_ids - procs)],
        "stable_zombies": [{**short_row(row), "in_procs_union": pid in procs,
                             "in_tasks_threads_union": pid in tids} for pid, row in zombies.items()],
        "stable_live_with_dedicated_pid_directory": sum(dedicated_present(row) for row in alive.values()),
        "stable_live_pid_directory_name_discovered": len(live_ids & directory_pids),
        "stable_live_without_dedicated_directory_examples": [short_row(row) for row in alive.values()
                                                               if not dedicated_present(row)][:12],
        "live_same_assignment_missing_from_recorded_group": location_misses,
        "hierarchies": hierarchy, "fixtures": fixtures, "fixture_evidence": fixture_evidence,
        "autonomous_procs_union_size": len(procs), "autonomous_directory_pid_count": len(directory_pids),
    }


def observer_comparison(observed: dict, bracket_before: dict, bracket_after: dict) -> dict:
    reference = stable_between(rows(bracket_before, "proc_after"), rows(bracket_after, "proc_before"))
    reference = {pid: row for pid, row in reference.items()
                 if row["stat"].get("state") not in ("Z", "X", "x")
                 and rows(bracket_after, "proc_before")[pid]["stat"].get("state") not in ("Z", "X", "x")}
    procs, tids, directory_pids = membership(observed)
    ids = set(reference)
    own_uid = observed["meta"]["uid"]
    foreign = {pid for pid, row in reference.items() if row["status"].get("uid") != own_uid}
    visible = set(rows(observed, "proc_before"))
    supplied = {item["supplied_pid"]: {**item["observation"],
                                       "supplied_starttime": item["supplied_starttime"]}
                for item in observed.get("targets", {}).get("rows", [])}
    scoped = [row for pid, row in supplied.items() if pid in reference
              and row.get("supplied_starttime") == identity(reference[pid])]
    errors = Counter(row["cgroup"]["errno"] for row in scoped)
    probes = Counter(probe["errno"] for row in scoped for probe in row.get("directory_probes", [])
                     if probe["path"].endswith("/pid_" + str(row["pid"])))
    return {"root_bracket_stable_live_count": len(ids), "foreign_uid_count": len(foreign),
            "autonomous_proc_visible": len(ids & visible),
            "autonomous_cgroup_procs_found": len(ids & procs),
            "autonomous_tasks_threads_found": len(ids & tids),
            "autonomous_directory_names_found": len(ids & directory_pids),
            "foreign_cgroup_procs_found": len(foreign & procs),
            "missing_from_cgroup_procs_examples": [short_row(reference[pid]) for pid in sorted(ids - procs)][:12],
            "external_known_targets_tested": len(scoped), "known_targets_cgroup_read_errno": dict(errors),
            "known_targets_dedicated_pid_directory_present": sum(dedicated_present(row) for row in scoped),
            "known_targets_dedicated_directory_stat_errno": dict(probes)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directories", type=Path, nargs="+")
    args = parser.parse_args()
    for directory in args.directories:
        evidence = {}
        for path in sorted(directory.glob("*.json")):
            if path.name in ("device.json", "summary.json") or path.name.endswith("-artifact-hashes.json"):
                continue
            data = json.loads(path.read_bytes())
            if data.get("schema_version") == 1:
                evidence[path.stem] = data
        summary = {name: summarize(data) for name, data in evidence.items()}
        for observer, before, after in [("shell", "shell-bracket-before", "shell-bracket-after"),
                                         ("app-known-targets", "app-bracket-before", "app-bracket-after")]:
            if all(name in evidence for name in (observer, before, after)):
                summary[observer]["root_bracket_comparison"] = observer_comparison(
                    evidence[observer], evidence[before], evidence[after])
        (directory / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
        print(directory)
        for name, item in summary.items():
            print(f"  {name}: uid={item['uid']}, stable={item['stable_count']}, "
                  f"live={item['stable_live_count']}, zombies={item['stable_zombie_count']}, "
                  f"live_in_procs={item['stable_live_found_in_procs_union']}, "
                  f"live_pid_dirs={item['stable_live_with_dedicated_pid_directory']}")
            if "root_bracket_comparison" in item:
                print("    bracket:", json.dumps(item["root_bracket_comparison"], ensure_ascii=False))


if __name__ == "__main__":
    main()
