#pragma once

// Read-only, calibrated name probes. Missing names are not missing kernel membership.
#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <poll.h>
#include <set>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <time.h>
#include <unistd.h>
#include <vector>

namespace cgroup_watch {
inline uint64_t now() {
    timespec t{};
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return 0;
    return uint64_t(t.tv_sec) * 1000000000ULL + uint64_t(t.tv_nsec);
}
inline std::string quote(const std::string& value) {
    static const char hex[] = "0123456789abcdef";
    std::string out = "\"";
    for (unsigned char c : value) {
        if (c == '"' || c == '\\') { out += '\\'; out += char(c); }
        else if (c >= 32 && c < 127) out += char(c);
        else { out += "\\u00"; out += hex[c >> 4]; out += hex[c & 15]; }
    }
    return out + '"';
}
inline bool uintValue(const std::string& s, uint64_t& n) {
    n = 0;
    if (s.empty()) return false;
    for (unsigned char c : s) {
        if (c < '0' || c > '9' || n > (UINT64_MAX - (c - '0')) / 10) return false;
        n = n * 10 + c - '0';
    }
    return true;
}
inline std::vector<std::string> fields(const std::string& s) {
    std::istringstream in(s); std::vector<std::string> result; std::string part;
    while (in >> part) result.push_back(part);
    return result;
}
struct Probe {
    std::string path;
    int error = EIO;
    void json(std::ostream& out) const {
        out << "{\"path\":" << quote(path) << ",\"returnCode\":" << (error ? -1 : 0)
            << ",\"errno\":" << error << ",\"result\":"
            << quote(!error ? "present" : error == EACCES ? "presence_hint" : error == ENOENT ? "missing" : "unknown") << '}';
    }
};
inline bool presenceHint(int error) { return error == 0 || error == EACCES; }
inline bool calibrated(int positive, int negativeName, int negativeNumber) {
    return presenceHint(positive) && negativeName == ENOENT && negativeNumber == ENOENT;
}
inline void probeArray(std::ostream& out, const std::vector<Probe>& probes) {
    out << '[';
    for (size_t i = 0; i < probes.size(); ++i) { if (i) out << ','; probes[i].json(out); }
    out << ']';
}
struct Error { std::string path; int code; std::string reason; };
struct Life {
    bool present = false, parsed = false, nonZombie = false;
    int directoryError = 0, statError = 0, uid = -1;
    uint64_t start = 0; std::string name;
};
inline bool parseLife(const std::string& text, Life& life) {
    const auto left = text.find('('), right = text.rfind(')');
    if (left == std::string::npos || right == std::string::npos || right <= left) return false;
    const auto f = fields(text.substr(right + 1));
    if (f.size() < 20 || f[0].size() != 1 || !uintValue(f[19], life.start)
        || std::string("RSDZTtWXxKPI").find(f[0][0]) == std::string::npos) return false;
    life.name = text.substr(left + 1, right - left - 1);
    life.nonZombie = f[0] != "Z" && f[0] != "X" && f[0] != "x";
    life.parsed = true;
    return true;
}
struct Held { int fd = -1; uint64_t start = 0; std::string identity; bool startKnown = false; };
inline int heldState(int fd) {
    if (fd < 0) return -1;
    pollfd p{fd, POLLIN, 0};
    const int rc = poll(&p, 1, 0);
    if (!rc) return 0;
    if (rc > 0 && (p.revents & (POLLIN | POLLHUP))) return 1;
    return -1;
}
struct Check {
    std::string state = "UNKNOWN", identityToken, reason = "not_observed";
    bool procPresent = false, stableIdentity = false, nonZombie = false;
    bool pathCalibrationValid = false, pathCoverageComplete = false, uidCoverageComplete = false, pathFound = false;
    bool pidfdLiveBefore = false, pidfdLiveAfter = false;
    int procBeforeErrno = EIO, procAfterErrno = EIO;
    size_t testedUidCount = 0, testedPathCount = 0, missingPathCount = 0;
    uint64_t uidCatalogGeneration = 0;
    unsigned sampleIndex = 0;
    std::vector<Probe> paths;
    void json(std::ostream& out) const {
        out << "{\"state\":" << quote(state) << ",\"procPresent\":" << procPresent
            << ",\"stableIdentity\":" << stableIdentity << ",\"nonZombie\":" << nonZombie
            << ",\"identityToken\":" << quote(identityToken) << ",\"sampleIndex\":" << sampleIndex
            << ",\"reason\":" << quote(reason) << ",\"method\":\"stat_uid_pid_paths\""
            << ",\"pathCalibrationValid\":" << pathCalibrationValid << ",\"pathCoverageComplete\":" << pathCoverageComplete
            << ",\"uidCoverageComplete\":" << uidCoverageComplete << ",\"pathFound\":" << pathFound
            << ",\"testedUidCount\":" << testedUidCount << ",\"testedPathCount\":" << testedPathCount
            << ",\"missingPathCount\":" << missingPathCount << ",\"uidCatalogGeneration\":" << uidCatalogGeneration
            << ",\"coverageScope\":\"observed_uid_catalog\",\"procEvidence\":{\"method\":\"fstatat_and_held_pidfd\""
            << ",\"beforeErrno\":" << procBeforeErrno << ",\"afterErrno\":" << procAfterErrno
            << ",\"pidfdLiveBefore\":" << pidfdLiveBefore << ",\"pidfdLiveAfter\":" << pidfdLiveAfter
            << "},\"pathsTruncated\":" << (testedPathCount > paths.size()) << ",\"paths\":";
        probeArray(out, paths); out << '}';
    }
};
inline void evaluate(Check& check, const Life& before, const Life& after,
                     int heldBefore, int heldAfter, bool bindingMatches) {
    check.procBeforeErrno = before.directoryError; check.procAfterErrno = after.directoryError;
    check.pidfdLiveBefore = heldBefore == 0; check.pidfdLiveAfter = heldAfter == 0;
    check.procPresent = before.present && after.present;
    const bool parsedMismatch = before.parsed && after.parsed && before.start != after.start;
    check.nonZombie = heldBefore == 0 && heldAfter == 0
        && (!before.parsed || before.nonZombie) && (!after.parsed || after.nonZombie);
    check.stableIdentity = check.procPresent && check.nonZombie && bindingMatches && !parsedMismatch;
    if (heldBefore == 1 || heldAfter == 1 || (before.parsed && !before.nonZombie) || (after.parsed && !after.nonZombie)) {
        check.state = "EXITED"; check.reason = "exit_or_zombie";
    } else if (!check.procPresent) check.reason = "proc_path_presence_unverified";
    else if (!check.stableIdentity) check.reason = "held_process_identity_unverified";
    else if (check.pathFound) { check.state = "PRESENT"; check.reason = "calibrated_named_path_observed"; }
    else if (!check.pathCalibrationValid || !check.uidCoverageComplete || !check.pathCoverageComplete
             || !check.testedUidCount || !check.testedPathCount || check.missingPathCount != check.testedPathCount)
        check.reason = "named_path_coverage_incomplete";
    else { check.state = "MISSING"; check.reason = "stable_live_proc_without_named_path_in_observed_uid_catalog"; }
}
struct Observation { Life before, after; Check check; };
struct Layout {
    std::string root;
    bool active = false, calibrated = false, catalogComplete = true;
    std::vector<Probe> controls;
    std::map<int, std::string> uidPaths;
    std::string positivePath;
    void json(std::ostream& out) const {
        out << "{\"root\":" << quote(root) << ",\"active\":" << active << ",\"calibrated\":" << calibrated
            << ",\"uidCount\":" << uidPaths.size() << ",\"catalogComplete\":" << catalogComplete << ",\"controls\":";
        probeArray(out, controls); out << '}';
    }
};
struct Result {
    bool complete = true, available = false, calibrationValid = false, uidComplete = true, errorsTruncated = false;
    bool preflightComplete = false, procScanSkipped = true;
    int error = 0; unsigned sampleIndex = 0; uint64_t durationMs = 0, generation = 0;
    size_t uidCount = 0, uidProbeCount = 0, pathProbeCount = 0, completedPidCount = 0, eligiblePidCount = 0, errorCount = 0;
    std::string status = "unavailable";
    std::vector<Error> errors;
    std::vector<Probe> procControls;
    std::vector<Layout> layouts;
    std::vector<std::pair<int, int>> ranges;
    std::map<int, Observation> processes;
    void fail(const std::string& path, int code, const std::string& reason) {
        complete = false; ++errorCount; if (!error) error = code ? code : EIO;
        if (errors.size() < 16) errors.push_back({path, code, reason}); else errorsTruncated = true;
    }
    void json(std::ostream& out) const {
        out << "{\"method\":\"stat_uid_pid_paths\",\"coverageScope\":\"observed_uid_catalog\""
            << ",\"complete\":" << complete << ",\"available\":" << available << ",\"calibrationValid\":" << calibrationValid
            << ",\"errno\":" << error << ",\"status\":" << quote(status) << ",\"sampleIndex\":" << sampleIndex
            << ",\"durationMs\":" << durationMs << ",\"preflightComplete\":" << preflightComplete
            << ",\"procScanSkipped\":" << procScanSkipped << ",\"eligiblePidCount\":" << eligiblePidCount
            << ",\"completedPidCount\":" << completedPidCount << ",\"pathProbeCount\":" << pathProbeCount
            << ",\"errorCount\":" << errorCount << ",\"errorsTruncated\":" << errorsTruncated
            << ",\"uidCatalog\":{\"complete\":" << uidComplete << ",\"generation\":" << generation
            << ",\"uidCount\":" << uidCount << ",\"probeCount\":" << uidProbeCount
            << ",\"scope\":\"observed_uid_catalog\",\"rangeEndInclusive\":true,\"ranges\":[";
        for (size_t i = 0; i < ranges.size(); ++i) {
            if (i) out << ',';
            out << "{\"start\":" << ranges[i].first << ",\"end\":" << ranges[i].second << '}';
        }
        out << "],\"meaning\":\"fresh named UID directories in these finite ranges; not an exhaustive Android UID or cgroup membership inventory\"}"
            << ",\"procControls\":"; probeArray(out, procControls);
        out << ",\"layouts\":[";
        for (size_t i = 0; i < layouts.size(); ++i) { if (i) out << ','; layouts[i].json(out); }
        out << "],\"errors\":[";
        for (size_t i = 0; i < errors.size(); ++i) {
            if (i) out << ',';
            out << "{\"path\":" << quote(errors[i].path) << ",\"errno\":" << errors[i].code
                << ",\"reason\":" << quote(errors[i].reason) << '}';
        }
        out << "],\"semantics\":\"names only; EACCES is a calibrated presence hint; missing names do not prove absent kernel membership, root credentials or GPU ownership\"}";
    }
};
class Scanner {
    static constexpr uint64_t durationLimitNs = 650000000ULL;
    static constexpr size_t probeLimit = 500000, byteLimit = 8 * 1024 * 1024;
    Result result;
    uint64_t began = now(), generation = 0;
    size_t probes = 0, bytes = 0;
    bool exhausted = false, procCalibrated = false;
    int nextPid = 0;
    std::string previousCatalog;
    bool budget(const std::string& path) {
        if (exhausted) return false;
        if (now() - began > durationLimitNs || probes >= probeLimit || bytes >= byteLimit) {
            result.fail(path, EOVERFLOW, "scan_budget_exhausted"); exhausted = true; return false;
        }
        return true;
    }
    Probe probe(const std::string& path, struct stat* info = nullptr) {
        Probe value{path, EOVERFLOW};
        if (!budget(path)) return value;
        ++probes; struct stat local{};
        const int rc = fstatat(AT_FDCWD, path.c_str(), &local, AT_SYMLINK_NOFOLLOW);
        value.error = rc ? errno : S_ISDIR(local.st_mode) ? 0 : ENOTDIR;
        if (!value.error && info) *info = local;
        return value;
    }
    bool readFile(const std::string& path, std::string& out, size_t limit, int& error) {
        if (!budget(path)) { error = EOVERFLOW; return false; }
        const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW);
        if (fd < 0) { error = errno; return false; }
        bool ok = false; char buffer[4096];
        for (;;) {
            if (!budget(path)) { error = EOVERFLOW; break; }
            const size_t room = limit >= out.size() ? limit - out.size() : 0;
            const ssize_t n = read(fd, buffer, std::min(sizeof(buffer), room + 1));
            if (n < 0) { if (errno == EINTR) continue; error = errno; break; }
            if (!n) { ok = true; break; }
            bytes += size_t(n);
            if (size_t(n) > room) { error = EOVERFLOW; break; }
            out.append(buffer, size_t(n));
        }
        close(fd); return ok;
    }
    Life life(int pid) {
        Life value; const std::string path = "/proc/" + std::to_string(pid); struct stat info{};
        value.directoryError = probe(path, &info).error;
        value.present = !value.directoryError || (procCalibrated && value.directoryError == EACCES);
        if (!value.present) return value;
        if (!value.directoryError && (info.st_mode & (S_IFMT | 07777)) == (S_IFDIR | 0555) && info.st_uid <= INT_MAX)
            value.uid = int(info.st_uid);
        if (value.directoryError == EACCES) { value.statError = EACCES; return value; }
        std::string text;
        if (readFile(path + "/stat", text, 16384, value.statError) && !parseLife(text, value)) value.statError = EINVAL;
        return value;
    }
    void addRange(int first, int last) {
        const std::pair<int, int> range{first, last};
        if (std::find(result.ranges.begin(), result.ranges.end(), range) == result.ranges.end()) result.ranges.push_back(range);
    }
    void discover(Layout& layout, const std::map<int, Held>& held) {
        layout.controls.push_back(probe(layout.root));
        if (layout.controls.back().error == ENOENT) return;
        const Probe badUid = probe(layout.root + "/uid_"), badNumber = probe(layout.root + "/uid_2147483647");
        layout.controls.push_back(badUid); layout.controls.push_back(badNumber);
        if (!calibrated(layout.controls[0].error, badUid.error, badNumber.error)) {
            layout.active = true; layout.catalogComplete = false; result.uidComplete = false;
            result.fail(layout.root, EACCES, "uid_negative_controls_not_distinguishable"); return;
        }
        for (const auto& range : result.ranges) {
            for (int uid = range.first; uid <= range.second; ++uid) {
                const std::string path = layout.root + "/uid_" + std::to_string(uid);
                const Probe found = probe(path); ++result.uidProbeCount;
                if (presenceHint(found.error)) layout.uidPaths.emplace(uid, path);
                else if (found.error != ENOENT) {
                    layout.catalogComplete = false; result.uidComplete = false;
                    if (!exhausted) result.fail(path, found.error, "uid_probe_ambiguous");
                }
                if (exhausted) break;
            }
            if (exhausted) break;
        }
        layout.active = !layout.uidPaths.empty() || !layout.catalogComplete;
        if (!layout.active) return;
        const auto own = layout.uidPaths.find(int(geteuid()));
        if (own != layout.uidPaths.end()) {
            // The collector inherits its app parent's group, not a pid_<collector> name.
            for (int pid : {int(getppid()), int(getpid())}) {
                Probe positive = probe(own->second + "/pid_" + std::to_string(pid));
                layout.controls.push_back(positive);
                if (presenceHint(positive.error)) { layout.positivePath = positive.path; break; }
            }
        }
        // The legacy system family may not contain the app. Calibrate a numeric path with a live held PID.
        if (layout.positivePath.empty() && layout.root == "/sys/fs/cgroup/system") {
            const auto rootUid = layout.uidPaths.find(0);
            if (rootUid != layout.uidPaths.end()) for (const auto& entry : held) {
                if (heldState(entry.second.fd) != 0) continue;
                Probe positive = probe(rootUid->second + "/pid_" + std::to_string(entry.first));
                if (presenceHint(positive.error)) { layout.controls.push_back(positive); layout.positivePath = positive.path; break; }
                if (exhausted) break;
            }
        }
        bool controlsValid = !layout.positivePath.empty();
        for (const auto& uid : layout.uidPaths) {
            const Probe negative = probe(uid.second + "/pid_"), negativeNumber = probe(uid.second + "/pid_2147483647");
            controlsValid = controlsValid && negative.error == ENOENT && negativeNumber.error == ENOENT;
            if ((layout.controls.size() < 12 || negative.error != ENOENT || negativeNumber.error != ENOENT) && layout.controls.size() < 24) {
                layout.controls.push_back(negative); layout.controls.push_back(negativeNumber);
            }
            if (exhausted) break;
        }
        layout.calibrated = controlsValid && !exhausted && layout.catalogComplete;
        if (!layout.calibrated) result.fail(layout.root, ENODATA, "pid_path_controls_not_calibrated");
    }
    Result finish() {
        result.durationMs = (now() - began) / 1000000ULL;
        result.status = result.complete && result.available ? "complete" : result.available ? "partial" : "unavailable";
        return std::move(result);
    }
public:
    Life recheck(int pid) { return life(pid); }
    bool truncationSelfTest() {
        std::string text; int error = 0;
        return !readFile("/proc/self/stat", text, 1, error) && error == EOVERFLOW;
    }
    Result run(const std::set<int>& excluded, const std::map<int, Held>& held, unsigned sample, bool enabled) {
        result = Result{}; result.sampleIndex = sample; began = now(); probes = bytes = 0; exhausted = procCalibrated = false;
        if (!enabled) { result.fail("", ENOTSUP, "diagnostic_mode"); return finish(); }
        result.procControls = {probe("/proc/" + std::to_string(getpid())), probe("/proc/pid_"), probe("/proc/2147483647")};
        struct statfs fs{};
        procCalibrated = result.procControls[0].error == 0 && result.procControls[1].error == ENOENT
            && result.procControls[2].error == ENOENT && !statfs("/proc", &fs) && uint64_t(fs.f_type) == 0x9fa0;
        if (!procCalibrated) { result.fail("/proc", EACCES, "proc_presence_controls_not_calibrated"); return finish(); }
        addRange(0, 19999); addRange(90000, 99999);
        const int userBase = (int(geteuid()) / 100000) * 100000;
        if (userBase > 0 && userBase <= INT_MAX - 99999) { addRange(userBase, userBase + 19999); addRange(userBase + 90000, userBase + 99999); }
        for (const char* root : {"/sys/fs/cgroup", "/sys/fs/cgroup/apps", "/sys/fs/cgroup/system"}) {
            Layout layout; layout.root = root; discover(layout, held); result.layouts.push_back(std::move(layout));
            if (exhausted) { result.uidComplete = false; break; }
        }
        bool anyLayout = false, allCalibrated = true;
        std::set<int> uids; std::ostringstream signature;
        for (const auto& layout : result.layouts) {
            if (!layout.active) continue;
            anyLayout = true; allCalibrated = allCalibrated && layout.calibrated;
            signature << layout.root << ':';
            for (const auto& uid : layout.uidPaths) { uids.insert(uid.first); signature << uid.first << ','; }
            signature << ';';
        }
        result.uidCount = uids.size(); result.calibrationValid = anyLayout && allCalibrated && result.uidComplete;
        result.available = result.calibrationValid;
        if (!result.available) { result.fail("/sys/fs/cgroup", ENODATA, "no_complete_calibrated_named_layout"); return finish(); }
        if (signature.str() != previousCatalog) { previousCatalog = signature.str(); ++generation; }
        result.generation = generation; result.preflightComplete = true; result.procScanSkipped = false;
        std::vector<int> pids;
        for (const auto& entry : held) if (!excluded.count(entry.first)) pids.push_back(entry.first);
        result.eligiblePidCount = pids.size();
        const auto start = std::lower_bound(pids.begin(), pids.end(), nextPid);
        std::rotate(pids.begin(), start, pids.end()); nextPid = 0;
        for (int pid : pids) {
            // Leave 50 ms for the final controls. A bounded partial batch must not
            // erase already completed PID observations solely because other PIDs wait.
            if (now() - began >= 600000000ULL || probes >= probeLimit - 2048) {
                result.fail("/proc", EOVERFLOW, "target_path_batch_limit"); nextPid = pid; break;
            }
            if (!budget("/proc/" + std::to_string(pid))) { nextPid = pid; break; }
            const Held& identity = held.at(pid);
            Observation observation; Check& check = observation.check;
            check.sampleIndex = sample; check.identityToken = identity.identity;
            check.uidCatalogGeneration = generation; check.uidCoverageComplete = result.uidComplete;
            check.pathCalibrationValid = result.calibrationValid;
            const int beforeHeld = heldState(identity.fd);
            observation.before = life(pid);
            std::set<int> testedUids;
            bool partial = false;
            if (beforeHeld == 0 && observation.before.present) {
                for (const auto& layout : result.layouts) {
                    if (!layout.active) continue;
                    for (const auto& uid : layout.uidPaths) {
                        if (now() - began >= 600000000ULL || probes >= probeLimit - 2048) { partial = true; break; }
                        const Probe value = probe(uid.second + "/pid_" + std::to_string(pid));
                        ++check.testedPathCount; ++result.pathProbeCount; testedUids.insert(uid.first);
                        if (check.paths.size() < 4 || (presenceHint(value.error) && check.paths.size() < 5)) check.paths.push_back(value);
                        if (value.error == ENOENT) ++check.missingPathCount;
                        else if (presenceHint(value.error)) { check.pathFound = true; break; }
                        if (exhausted) break;
                    }
                    if (check.pathFound || exhausted || partial) break;
                }
                check.testedUidCount = testedUids.size();
                check.pathCoverageComplete = !exhausted && !partial && !check.pathFound
                    && check.testedUidCount == result.uidCount && check.testedPathCount == check.missingPathCount;
            }
            observation.after = life(pid);
            const int afterHeld = heldState(identity.fd);
            const bool binding = !identity.startKnown || ((!observation.before.parsed || identity.start == observation.before.start)
                && (!observation.after.parsed || identity.start == observation.after.start));
            evaluate(check, observation.before, observation.after, beforeHeld, afterHeld, binding);
            if (check.pathCoverageComplete || check.pathFound) ++result.completedPidCount;
            result.processes.emplace(pid, std::move(observation));
            if (exhausted) { nextPid = pid; break; }
            if (partial) { result.fail("/proc", EOVERFLOW, "target_path_batch_limit"); nextPid = pid; break; }
        }
        bool afterControls = !exhausted;
        for (const auto& layout : result.layouts) {
            if (!layout.active) continue;
            for (const auto& control : layout.controls) {
                const Probe after = probe(control.path);
                afterControls = afterControls && (control.error == ENOENT ? after.error == ENOENT : presenceHint(after.error));
            }
        }
        for (const auto& control : result.procControls) {
            const Probe after = probe(control.path);
            afterControls = afterControls && (control.error == ENOENT ? after.error == ENOENT : after.error == 0);
        }
        if (!afterControls) {
            result.calibrationValid = false; result.available = false;
            result.fail("/sys/fs/cgroup", ESTALE, "path_controls_changed_or_budget_exhausted");
            for (auto& entry : result.processes) {
                auto& check = entry.second.check; check.pathCalibrationValid = false;
                if (check.state == "MISSING") { check.state = "UNKNOWN"; check.reason = "path_controls_changed_or_budget_exhausted"; }
            }
        }
        return finish();
    }
};
inline bool selfTest() {
    bool ok = calibrated(0, ENOENT, ENOENT) && calibrated(EACCES, ENOENT, ENOENT)
        && !calibrated(EACCES, EACCES, ENOENT) && !calibrated(ENOENT, ENOENT, ENOENT)
        && !calibrated(0, ENOTDIR, ENOENT) && !presenceHint(EPERM);
    Life a; a.present = true; a.directoryError = EACCES; a.statError = EACCES;
    Check complete; complete.pathCalibrationValid = complete.pathCoverageComplete = complete.uidCoverageComplete = true;
    complete.testedUidCount = complete.testedPathCount = complete.missingPathCount = 2;
    const auto state = [&](const Life& b, int before, int after, bool binding, Check check) {
        evaluate(check, a, b, before, after, binding); return check.state;
    };
    ok = ok && state(a, 0, 0, true, complete) == "MISSING" && state(a, -1, 0, true, complete) == "UNKNOWN"
        && state(a, 0, 1, true, complete) == "EXITED" && state(a, 0, 0, false, complete) == "UNKNOWN";
    Check incomplete = complete; incomplete.pathCoverageComplete = false;
    ok = ok && state(a, 0, 0, true, incomplete) == "UNKNOWN";
    incomplete = complete; incomplete.missingPathCount--;
    ok = ok && state(a, 0, 0, true, incomplete) == "UNKNOWN";
    incomplete = complete; incomplete.pathFound = true;
    ok = ok && state(a, 0, 0, true, incomplete) == "PRESENT";
    Life b = a; b.present = false;
    ok = ok && state(b, 0, 0, true, complete) == "UNKNOWN";
    ok = ok && parseLife("7 (a ) b) S 1 2 3 0 5 6 7 8 9 10 1 2 0 0 0 0 1 0 999 0 1", a)
        && a.start == 999 && a.name == "a ) b";
    b = a; ++b.start; ok = ok && state(b, 0, 0, true, complete) == "UNKNOWN";
    b = a; b.nonZombie = false; ok = ok && state(b, 0, 0, true, complete) == "EXITED";
    Scanner scanner; return ok && scanner.truncationSelfTest();
}
} // namespace cgroup_watch
