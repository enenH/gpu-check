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
// Narrow syscall seam: production and deterministic host tests run the same scanner.
struct Io {
    uint64_t readDeadlineNs = UINT64_MAX;
    virtual ~Io() = default;
    virtual uint64_t timeNs() { return now(); }
    virtual void setReadDeadline(uint64_t deadline) { readDeadlineNs = deadline; }
    virtual int statDirectory(const std::string& path, struct stat& info) {
        if (fstatat(AT_FDCWD, path.c_str(), &info, AT_SYMLINK_NOFOLLOW)) return errno;
        return S_ISDIR(info.st_mode) ? 0 : ENOTDIR;
    }
    virtual bool readText(const std::string& path, std::string& out, size_t limit, int& error) {
        const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW);
        if (fd < 0) { error = errno; return false; }
        bool ok = false; char buffer[4096];
        for (;;) {
            if (timeNs() >= readDeadlineNs) { error = EOVERFLOW; break; }
            const size_t room = limit >= out.size() ? limit - out.size() : 0;
            const ssize_t n = read(fd, buffer, std::min(sizeof(buffer), room + 1));
            if (n < 0) { if (errno == EINTR) continue; error = errno; break; }
            if (!n) { ok = true; error = 0; break; }
            if (size_t(n) > room) { error = EOVERFLOW; break; }
            out.append(buffer, size_t(n));
        }
        close(fd); return ok;
    }
    virtual int pidfdState(int fd) { return heldState(fd); }
    virtual bool isProcFs() {
        struct statfs fs{};
        return !statfs("/proc", &fs) && uint64_t(fs.f_type) == 0x9fa0;
    }
    virtual int uid() { return int(geteuid()); }
    virtual int pid() { return int(getpid()); }
    virtual int parentPid() { return int(getppid()); }
};
struct Check {
    std::string state = "UNKNOWN", identityToken, reason = "not_observed";
    bool procPresent = false, stableIdentity = false, nonZombie = false;
    bool pathCalibrationValid = false, pathCoverageComplete = false, uidCoverageComplete = false, pathFound = false;
    bool pidfdLiveBefore = false, pidfdLiveAfter = false;
    int procBeforeErrno = EIO, procAfterErrno = EIO;
    size_t testedUidCount = 0, testedPathCount = 0, missingPathCount = 0;
    uint64_t uidCatalogGeneration = 0;
    unsigned sampleIndex = 0;
    std::string observedLayout;
    int observedUid = -1;
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
            << ",\"observedLayout\":" << quote(observedLayout) << ",\"observedUid\":" << observedUid
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
    else if (check.pathFound && check.pathCalibrationValid) { check.state = "PRESENT"; check.reason = "calibrated_named_path_observed"; }
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
    bool rootCalibrated = false, rootAbsent = false, catalogFresh = false;
    bool freshCoverageThisSample = false, validatedThisSample = false, refreshing = true;
    int positiveUid = -1;
    int64_t catalogAgeMs = -1;
    size_t scanCompleted = 0, scanTotal = 0, scannedThisSample = 0;
    std::set<int> usableUids;
    std::map<int, std::vector<Probe>> uidControls;
    struct stat rootInfo{};
    void json(std::ostream& out) const {
        out << "{\"root\":" << quote(root) << ",\"active\":" << active << ",\"calibrated\":" << calibrated
            << ",\"uidCount\":" << uidPaths.size() << ",\"usableUidCount\":" << usableUids.size()
            << ",\"catalogComplete\":" << catalogComplete << ",\"catalogFresh\":" << catalogFresh
            << ",\"catalogAgeMs\":" << catalogAgeMs << ",\"refreshing\":" << refreshing
            << ",\"freshCoverageThisSample\":" << freshCoverageThisSample
            << ",\"validatedThisSample\":" << validatedThisSample
            << ",\"scanCompleted\":" << scanCompleted << ",\"scanTotal\":" << scanTotal
            << ",\"scannedThisSample\":" << scannedThisSample << ",\"controls\":";
        probeArray(out, controls); out << '}';
    }
};
struct Result {
    bool complete = true, available = false, calibrationValid = false, uidComplete = true, errorsTruncated = false;
    bool preflightComplete = false, procScanSkipped = true;
    bool missingDetectionAvailable = false, freshCoverageThisSample = false;
    bool catalogFresh = false, catalogRefreshing = true, catalogValidatedThisSample = false;
    int64_t catalogAgeMs = -1;
    size_t catalogScanCompleted = 0, catalogScanTotal = 0;
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
            << ",\"missingDetectionAvailable\":" << missingDetectionAvailable
            << ",\"freshCoverageThisSample\":" << freshCoverageThisSample
            << ",\"errno\":" << error << ",\"status\":" << quote(status) << ",\"sampleIndex\":" << sampleIndex
            << ",\"durationMs\":" << durationMs << ",\"preflightComplete\":" << preflightComplete
            << ",\"procScanSkipped\":" << procScanSkipped << ",\"eligiblePidCount\":" << eligiblePidCount
            << ",\"completedPidCount\":" << completedPidCount << ",\"pathProbeCount\":" << pathProbeCount
            << ",\"errorCount\":" << errorCount << ",\"errorsTruncated\":" << errorsTruncated
            << ",\"uidCatalog\":{\"complete\":" << uidComplete << ",\"generation\":" << generation
            << ",\"uidCount\":" << uidCount << ",\"probeCount\":" << uidProbeCount
            << ",\"ageMs\":" << catalogAgeMs << ",\"ttlMs\":10000,\"fresh\":" << catalogFresh
            << ",\"refreshing\":" << catalogRefreshing << ",\"discoveredThisSample\":" << freshCoverageThisSample
            << ",\"validatedThisSample\":" << catalogValidatedThisSample
            << ",\"scanCompleted\":" << catalogScanCompleted << ",\"scanTotal\":" << catalogScanTotal
            << ",\"scope\":\"observed_uid_catalog\",\"rangeEndInclusive\":true,\"ranges\":[";
        for (size_t i = 0; i < ranges.size(); ++i) {
            if (i) out << ',';
            out << "{\"start\":" << ranges[i].first << ",\"end\":" << ranges[i].second << '}';
        }
        out << "],\"meaning\":\"cached or incrementally discovered names are candidates only; complete requires this sample's full finite-range discovery and revalidation, never exhaustive Android UID or kernel membership coverage\"}"
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
    static constexpr uint64_t durationLimitNs = 650000000ULL, discoveryLimitNs = 350000000ULL;
    static constexpr uint64_t uidValidationLimitNs = 425000000ULL, preflightLimitNs = 450000000ULL, targetLimitNs = 600000000ULL;
    static constexpr uint64_t catalogTtlNs = 10000000000ULL;
    static constexpr size_t probeLimit = 500000, byteLimit = 8 * 1024 * 1024, discoveryChunk = 128;
    struct Catalog {
        std::set<int> known;
        std::set<int> sweepNames;
        size_t cursor = 0;
        unsigned sweepSample = 0;
        uint64_t sweepBegan = 0, completedBegan = 0;
        bool sweeping = false, sweepValid = true, established = false;
        std::string rootIdentity;
    };
    Io ownedIo;
    Io& io;
    Result result;
    uint64_t began = 0, generation = 0, probeTimeNs = 0;
    size_t probes = 0, bytes = 0, nextLayout = 0;
    bool exhausted = false, procCalibrated = false;
    int nextPid = 0, catalogOwner = -1;
    std::string previousCatalog;
    std::map<std::string, Catalog> catalogs;
    uint64_t elapsed() {
        const uint64_t current = io.timeNs();
        return current >= began ? current - began : UINT64_MAX;
    }
    bool within(uint64_t limit, size_t reserve = 0) {
        return reserve < probeLimit && !exhausted && elapsed() < limit && probes < probeLimit - reserve && bytes < byteLimit;
    }
    bool budget(const std::string& path) {
        if (exhausted) return false;
        if (!within(durationLimitNs)) {
            result.fail(path, EOVERFLOW, "scan_budget_exhausted"); exhausted = true; return false;
        }
        return true;
    }
    Probe probe(const std::string& path, struct stat* info = nullptr) {
        Probe value{path, EOVERFLOW};
        if (!budget(path)) return value;
        ++probes; struct stat local{}; const uint64_t started = io.timeNs();
        value.error = io.statDirectory(path, local);
        const uint64_t ended = io.timeNs();
        if (ended >= started) probeTimeNs += ended - started;
        if (!value.error && info) *info = local;
        return value;
    }
    bool readFile(const std::string& path, std::string& out, size_t limit, int& error) {
        if (!budget(path)) { error = EOVERFLOW; return false; }
        const bool ok = io.readText(path, out, std::min(limit, byteLimit - bytes), error);
        bytes += out.size();
        if (!budget(path)) { error = EOVERFLOW; return false; }
        return ok;
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
    size_t rangeSize() const {
        size_t count = 0;
        for (const auto& range : result.ranges) count += size_t(range.second - range.first) + 1;
        return count;
    }
    int uidAt(size_t offset) const {
        for (const auto& range : result.ranges) {
            const size_t size = size_t(range.second - range.first) + 1;
            if (offset < size) return range.first + int(offset);
            offset -= size;
        }
        return -1;
    }
    bool inRange(int uid) const {
        for (const auto& range : result.ranges) if (uid >= range.first && uid <= range.second) return true;
        return false;
    }
    static std::string rootIdentity(const Probe& root, const struct stat& info) {
        return std::to_string(root.error) + ":" + std::to_string(uint64_t(info.st_dev))
            + ":" + std::to_string(uint64_t(info.st_ino));
    }
    void remember(Catalog& catalog, int uid, const Probe& observed) {
        if (presenceHint(observed.error)) {
            catalog.known.insert(uid); catalog.sweepNames.insert(uid);
        } else if (observed.error == ENOENT) {
            catalog.known.erase(uid); catalog.sweepNames.erase(uid);
        } else {
            catalog.sweepValid = false;
            result.fail(observed.path, observed.error, "uid_probe_ambiguous");
        }
    }
    void prepare(Layout& layout, unsigned sample) {
        Catalog& catalog = catalogs[layout.root];
        const Probe root = probe(layout.root, &layout.rootInfo);
        layout.controls.push_back(root); layout.active = root.error != ENOENT;
        const std::string identity = rootIdentity(root, layout.rootInfo);
        if (catalog.rootIdentity != identity) { catalog = Catalog{}; catalog.rootIdentity = identity; }
        if (root.error == ENOENT) {
            catalog.known.clear(); catalog.sweeping = catalog.established = false;
            layout.rootAbsent = layout.freshCoverageThisSample = layout.validatedThisSample = true;
            layout.catalogComplete = true; layout.refreshing = false; return;
        }
        layout.scanTotal = rangeSize();
        const Probe negative = probe(layout.root + "/uid_"), negativeNumber = probe(layout.root + "/uid_2147483647");
        layout.controls.push_back(negative); layout.controls.push_back(negativeNumber);
        layout.rootCalibrated = calibrated(root.error, negative.error, negativeNumber.error);
        if (!layout.rootCalibrated) {
            catalog.sweeping = catalog.established = false; catalog.cursor = 0;
            layout.catalogComplete = false;
            result.fail(layout.root, EACCES, "uid_negative_controls_not_distinguishable"); return;
        }
        if (!catalog.sweeping) {
            catalog.sweeping = true; catalog.cursor = 0; catalog.sweepNames.clear();
            catalog.sweepValid = true; catalog.sweepSample = sample; catalog.sweepBegan = io.timeNs();
        }
        // Seed a positive candidate immediately; progress through the full ranges is independent.
        for (int uid : {io.uid(), 0}) {
            if (!inRange(uid)) continue;
            const Probe found = probe(layout.root + "/uid_" + std::to_string(uid));
            ++result.uidProbeCount; remember(catalog, uid, found);
        }
    }
    void discover(unsigned sample) {
        std::set<size_t> finished;
        size_t visited = 0;
        while (within(discoveryLimitNs, 4096) && visited < result.layouts.size()) {
            const size_t index = nextLayout++ % result.layouts.size();
            Layout& layout = result.layouts[index];
            Catalog& catalog = catalogs[layout.root];
            if (!layout.rootCalibrated || finished.count(index)) { ++visited; continue; }
            visited = 0;
            size_t chunk = 0;
            while (chunk++ < discoveryChunk && catalog.cursor < layout.scanTotal && within(discoveryLimitNs, 4096)) {
                const int uid = uidAt(catalog.cursor);
                const Probe found = probe(layout.root + "/uid_" + std::to_string(uid));
                ++result.uidProbeCount; ++layout.scannedThisSample;
                remember(catalog, uid, found); ++catalog.cursor;
            }
            layout.scanCompleted = catalog.cursor;
            if (catalog.cursor == layout.scanTotal) {
                layout.freshCoverageThisSample = catalog.sweepSample == sample && catalog.sweepValid;
                catalog.established = catalog.sweepValid;
                if (catalog.established) {
                    catalog.completedBegan = catalog.sweepBegan;
                    for (auto it = catalog.known.begin(); it != catalog.known.end();) {
                        if (!catalog.sweepNames.count(*it)) it = catalog.known.erase(it); else ++it;
                    }
                }
                catalog.sweeping = false; catalog.cursor = 0; finished.insert(index);
            }
        }
        for (auto& layout : result.layouts) {
            if (layout.rootAbsent) continue;
            const auto& catalog = catalogs.at(layout.root);
            if (catalog.sweeping) layout.scanCompleted = catalog.cursor;
            layout.refreshing = catalog.sweeping || !catalog.established;
            layout.catalogAgeMs = catalog.established && io.timeNs() >= catalog.completedBegan
                ? int64_t((io.timeNs() - catalog.completedBegan) / 1000000ULL) : -1;
            layout.catalogFresh = catalog.established && layout.catalogAgeMs >= 0
                && uint64_t(layout.catalogAgeMs) < catalogTtlNs / 1000000ULL;
            layout.catalogComplete = layout.freshCoverageThisSample;
            if (layout.rootCalibrated) for (int uid : catalog.known)
                layout.uidPaths.emplace(uid, layout.root + "/uid_" + std::to_string(uid));
        }
    }
    bool positive(Layout& layout, int uid, int pid) {
        if (!layout.usableUids.count(uid) || !within(preflightLimitNs, 2048)) return false;
        const Probe value = probe(layout.uidPaths.at(uid) + "/pid_" + std::to_string(pid));
        if (!presenceHint(value.error)) return false;
        layout.positiveUid = uid; layout.positivePath = value.path; layout.controls.push_back(value); return true;
    }
    void calibrateUids(const std::map<int, Held>& held) {
        std::vector<std::vector<int>> ordered(result.layouts.size());
        std::vector<size_t> cursor(result.layouts.size(), 0);
        for (size_t index = 0; index < result.layouts.size(); ++index) {
            const auto& layout = result.layouts[index];
            if (!layout.rootCalibrated) continue;
            if (layout.uidPaths.count(io.uid())) ordered[index].push_back(io.uid());
            for (const auto& uid : layout.uidPaths) if (uid.first != io.uid()) ordered[index].push_back(uid.first);
        }
        bool remaining = true;
        while (remaining && within(uidValidationLimitNs, 3072)) {
            remaining = false;
            for (size_t index = 0; index < result.layouts.size() && within(uidValidationLimitNs, 3072); ++index) {
                if (cursor[index] >= ordered[index].size()) continue;
                remaining = true;
                Layout& layout = result.layouts[index];
                const int uid = ordered[index][cursor[index]++];
                const std::string& path = layout.uidPaths.at(uid);
                auto& controls = layout.uidControls[uid];
                controls = {probe(path), probe(path + "/pid_"), probe(path + "/pid_2147483647")};
                if (calibrated(controls[0].error, controls[1].error, controls[2].error)) {
                    layout.usableUids.insert(uid);
                    // Establish the App positive before a large UID catalog uses the preflight slice.
                    if (uid == io.uid() && layout.positivePath.empty()
                        && !positive(layout, uid, io.parentPid())) positive(layout, uid, io.pid());
                }
                else {
                    layout.freshCoverageThisSample = false;
                    if (controls[0].error == ENOENT) catalogs[layout.root].known.erase(uid);
                    result.fail(path, ENODATA, "uid_pid_controls_not_calibrated");
                }
            }
        }
        for (auto& layout : result.layouts) {
            if (!layout.rootCalibrated) continue;
            layout.validatedThisSample = layout.usableUids.size() == layout.uidPaths.size();
            if (!layout.validatedThisSample) layout.freshCoverageThisSample = false;
            if (layout.positivePath.empty() && !positive(layout, io.uid(), io.parentPid())) positive(layout, io.uid(), io.pid());
            // A layout need not contain our App. Bound the search for a held-live positive.
            size_t attempts = 0;
            if (layout.positivePath.empty()) for (int uid : layout.usableUids) {
                for (const auto& entry : held) {
                    if (++attempts > 64 || !within(preflightLimitNs, 2048)) break;
                    if (io.pidfdState(entry.second.fd) != 0) continue;
                    if (positive(layout, uid, entry.first)) {
                        if (io.pidfdState(entry.second.fd) == 0) break;
                        layout.controls.pop_back(); layout.positivePath.clear(); layout.positiveUid = -1;
                    }
                }
                if (!layout.positivePath.empty() || attempts > 64 || !within(preflightLimitNs, 2048)) break;
            }
            layout.calibrated = !layout.positivePath.empty() && !layout.usableUids.empty();
            if (!layout.calibrated && !layout.uidPaths.empty()) {
                layout.freshCoverageThisSample = false;
                result.fail(layout.root, ENODATA, "pid_path_controls_not_calibrated");
            }
            layout.catalogComplete = layout.freshCoverageThisSample;
        }
    }
    void summarize() {
        bool allCoverage = true, allValidated = true, allFresh = true, anyRoot = false;
        bool available = false; std::set<int> uids;
        result.catalogScanCompleted = result.catalogScanTotal = 0;
        result.catalogAgeMs = -1; result.catalogRefreshing = false;
        for (const auto& layout : result.layouts) {
            available = available || layout.calibrated;
            allCoverage = allCoverage && layout.freshCoverageThisSample;
            allValidated = allValidated && layout.validatedThisSample;
            result.catalogScanCompleted += layout.scanCompleted; result.catalogScanTotal += layout.scanTotal;
            if (!layout.rootAbsent) {
                anyRoot = true; allFresh = allFresh && layout.catalogFresh;
                result.catalogRefreshing = result.catalogRefreshing || layout.refreshing;
                result.catalogAgeMs = std::max(result.catalogAgeMs, layout.catalogAgeMs);
            }
            for (const auto& uid : layout.uidPaths) uids.insert(uid.first);
        }
        result.uidCount = uids.size();
        result.available = result.calibrationValid = procCalibrated && available;
        result.freshCoverageThisSample = procCalibrated && allCoverage && allValidated;
        result.uidComplete = result.missingDetectionAvailable = result.available && result.freshCoverageThisSample;
        result.catalogValidatedThisSample = procCalibrated && allValidated;
        result.catalogFresh = anyRoot && allFresh;
        if (!result.missingDetectionAvailable) result.complete = false;
    }
    void catalogGeneration() {
        std::ostringstream signature;
        for (const auto& layout : result.layouts) {
            signature << layout.root << ':' << catalogs[layout.root].rootIdentity << ':';
            for (const auto& uid : layout.uidPaths) signature << uid.first << ',';
            signature << ';';
        }
        if (signature.str() != previousCatalog) { previousCatalog = signature.str(); ++generation; }
        result.generation = generation;
    }
    bool revalidate(const std::vector<Probe>& controls, bool exactPositive = false, size_t first = 0) {
        bool valid = true;
        for (size_t index = first; index < controls.size(); ++index) {
            const auto& control = controls[index];
            const Probe after = probe(control.path);
            valid = valid && (control.error == ENOENT ? after.error == ENOENT
                : exactPositive ? after.error == 0 : presenceHint(after.error));
        }
        return valid;
    }
    size_t finalProbeReserve() const {
        size_t count = result.procControls.size() + 16;
        for (const auto& layout : result.layouts) {
            count += layout.controls.size();
            for (int uid : layout.usableUids) count += layout.uidControls.at(uid).size();
        }
        return count;
    }
    uint64_t targetDeadline(size_t reserve) const {
        // Reserve measured syscall time as well as a probe count. A large catalog
        // must not spend the controls' budget on more target PID combinations.
        const uint64_t average = probes ? probeTimeNs / probes : 0;
        const uint64_t perProbe = average > durationLimitNs / 2 ? durationLimitNs : average * 2;
        if (reserve >= probeLimit || (perProbe && reserve > durationLimitNs / perProbe)) return 0;
        const uint64_t needed = uint64_t(reserve) * perProbe + 10000000ULL;
        return needed >= durationLimitNs ? 0 : std::min(targetLimitNs, durationLimitNs - needed);
    }
    void finalControls() {
        // Check shared proc evidence first; later local failures must not revoke other layouts.
        const bool procValid = revalidate(result.procControls, true);
        if (!procValid) {
            procCalibrated = false; result.fail("/proc", ESTALE, "proc_controls_changed_or_budget_exhausted");
        }
        for (auto& layout : result.layouts) {
            struct stat rootAfter{};
            const Probe root = probe(layout.root, &rootAfter);
            const bool sameRoot = rootIdentity(root, rootAfter) == catalogs[layout.root].rootIdentity;
            const bool controlsValid = revalidate(layout.controls, false, 1);
            const bool rootValid = sameRoot && controlsValid;
            if (!rootValid) {
                layout.calibrated = layout.rootCalibrated = layout.validatedThisSample = layout.freshCoverageThisSample = false;
                layout.catalogFresh = false; layout.catalogAgeMs = -1; layout.refreshing = true;
                layout.usableUids.clear();
                auto& catalog = catalogs[layout.root]; catalog.sweeping = catalog.established = false; catalog.cursor = 0;
                result.fail(layout.root, ESTALE, "layout_controls_changed_or_budget_exhausted");
            } else if (layout.rootAbsent) continue;
            else if (layout.rootCalibrated) {
                std::vector<int> order;
                if (layout.usableUids.count(layout.positiveUid)) order.push_back(layout.positiveUid);
                for (int uid : layout.usableUids) if (uid != layout.positiveUid) order.push_back(uid);
                for (int uid : order) {
                    if (!revalidate(layout.uidControls.at(uid))) {
                        layout.usableUids.erase(uid);
                        layout.validatedThisSample = layout.freshCoverageThisSample = false;
                        result.fail(layout.uidPaths.at(uid), ESTALE, "uid_controls_changed_or_budget_exhausted");
                    }
                }
                layout.calibrated = layout.calibrated && layout.usableUids.count(layout.positiveUid) && !layout.usableUids.empty();
                if (!layout.calibrated && !layout.uidPaths.empty()) layout.freshCoverageThisSample = false;
            }
            layout.catalogComplete = layout.freshCoverageThisSample;
        }
        summarize();
        result.completedPidCount = 0;
        for (auto& entry : result.processes) {
            auto& check = entry.second.check;
            bool positiveValid = false;
            if (check.pathFound && procCalibrated) for (const auto& layout : result.layouts)
                if (layout.root == check.observedLayout && layout.calibrated && layout.usableUids.count(check.observedUid)) positiveValid = true;
            check.uidCoverageComplete = result.uidComplete;
            if (check.pathFound) check.pathCalibrationValid = positiveValid;
            else check.pathCalibrationValid = result.missingDetectionAvailable;
            if (!check.pathCalibrationValid || !check.uidCoverageComplete) check.pathCoverageComplete = false;
            if (check.state == "PRESENT" && !positiveValid) {
                check.state = "UNKNOWN"; check.pathFound = false; check.reason = "matched_path_controls_changed_or_budget_exhausted";
            } else if (check.state == "MISSING" && !result.missingDetectionAvailable) {
                check.state = "UNKNOWN"; check.reason = "named_path_coverage_incomplete";
            }
            if (check.pathFound || check.pathCoverageComplete) ++result.completedPidCount;
        }
    }
    Result finish() {
        result.durationMs = elapsed() / 1000000ULL;
        result.status = result.complete && result.available ? "complete" : result.available ? "partial" : "unavailable";
        return std::move(result);
    }
public:
    Scanner() : io(ownedIo) { began = io.timeNs(); io.setReadDeadline(began + durationLimitNs); }
    explicit Scanner(Io& value) : io(value) { began = io.timeNs(); io.setReadDeadline(began + durationLimitNs); }
    Life recheck(int pid) { return life(pid); }
    bool truncationSelfTest() {
        std::string text; int error = 0;
        return !readFile("/proc/self/stat", text, 1, error) && error == EOVERFLOW;
    }
    Result run(const std::set<int>& excluded, const std::map<int, Held>& held, unsigned sample, bool enabled) {
        result = Result{}; result.uidComplete = false; result.sampleIndex = sample; began = io.timeNs();
        io.setReadDeadline(began + durationLimitNs);
        probes = bytes = 0; probeTimeNs = 0; exhausted = procCalibrated = false;
        if (!enabled) { result.fail("", ENOTSUP, "diagnostic_mode"); return finish(); }
        result.procControls = {probe("/proc/" + std::to_string(io.pid())), probe("/proc/pid_"), probe("/proc/2147483647")};
        procCalibrated = result.procControls[0].error == 0 && result.procControls[1].error == ENOENT
            && result.procControls[2].error == ENOENT && io.isProcFs();
        if (!procCalibrated) { result.fail("/proc", EACCES, "proc_presence_controls_not_calibrated"); return finish(); }
        if (catalogOwner != io.uid()) { catalogs.clear(); previousCatalog.clear(); catalogOwner = io.uid(); }
        addRange(0, 19999); addRange(90000, 99999);
        const int userBase = (io.uid() / 100000) * 100000;
        if (userBase > 0 && userBase <= INT_MAX - 99999) { addRange(userBase, userBase + 19999); addRange(userBase + 90000, userBase + 99999); }
        for (const char* root : {"/sys/fs/cgroup", "/sys/fs/cgroup/apps", "/sys/fs/cgroup/system"}) {
            Layout layout; layout.root = root; prepare(layout, sample); result.layouts.push_back(std::move(layout));
        }
        discover(sample); calibrateUids(held); summarize(); catalogGeneration();
        result.preflightComplete = result.freshCoverageThisSample;
        if (!result.available) {
            result.fail("/sys/fs/cgroup", ENODATA, "no_calibrated_observable_named_layout"); return finish();
        }
        result.procScanSkipped = false;
        if (!result.freshCoverageThisSample) result.fail("/sys/fs/cgroup", EAGAIN, "uid_catalog_partial_or_cached");
        std::vector<int> pids;
        for (const auto& entry : held) if (!excluded.count(entry.first)) pids.push_back(entry.first);
        result.eligiblePidCount = pids.size();
        const auto start = std::lower_bound(pids.begin(), pids.end(), nextPid);
        std::rotate(pids.begin(), start, pids.end()); nextPid = 0;
        const size_t finalReserve = finalProbeReserve();
        const uint64_t targetEnd = targetDeadline(finalReserve);
        for (int pid : pids) {
            if (!within(targetEnd, finalReserve)) { result.fail("/proc", EOVERFLOW, "target_path_batch_limit"); nextPid = pid; break; }
            const Held& identity = held.at(pid);
            Observation observation; Check& check = observation.check;
            check.sampleIndex = sample; check.identityToken = identity.identity;
            check.uidCatalogGeneration = generation; check.uidCoverageComplete = result.uidComplete;
            check.pathCalibrationValid = result.calibrationValid;
            const int beforeHeld = io.pidfdState(identity.fd);
            observation.before = life(pid);
            std::set<int> testedUids; bool partial = false;
            if (beforeHeld == 0 && observation.before.present) {
                for (const auto& layout : result.layouts) {
                    if (!layout.calibrated) continue;
                    for (int uid : layout.usableUids) {
                        if (!within(targetEnd, finalReserve)) { partial = true; break; }
                        const Probe value = probe(layout.uidPaths.at(uid) + "/pid_" + std::to_string(pid));
                        ++check.testedPathCount; ++result.pathProbeCount; testedUids.insert(uid);
                        if (check.paths.size() < 4 || (presenceHint(value.error) && check.paths.size() < 5)) check.paths.push_back(value);
                        if (value.error == ENOENT) ++check.missingPathCount;
                        else if (presenceHint(value.error)) {
                            check.pathFound = true; check.observedLayout = layout.root; check.observedUid = uid; break;
                        }
                    }
                    if (check.pathFound || exhausted || partial) break;
                }
                check.testedUidCount = testedUids.size();
                check.pathCoverageComplete = result.missingDetectionAvailable && !exhausted && !partial && !check.pathFound
                    && check.testedUidCount == result.uidCount && check.testedPathCount == check.missingPathCount;
            }
            observation.after = life(pid);
            const int afterHeld = io.pidfdState(identity.fd);
            const bool binding = !identity.startKnown || ((!observation.before.parsed || identity.start == observation.before.start)
                && (!observation.after.parsed || identity.start == observation.after.start));
            evaluate(check, observation.before, observation.after, beforeHeld, afterHeld, binding);
            result.processes.emplace(pid, std::move(observation));
            if (exhausted || partial) { result.fail("/proc", EOVERFLOW, "target_path_batch_limit"); nextPid = pid; break; }
        }
        finalControls();
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
