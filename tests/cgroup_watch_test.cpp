#include "../native/cgroup_watch.h"

#include <functional>
#include <iostream>
#include <stdexcept>

namespace {
constexpr const char* root = "/sys/fs/cgroup";
constexpr const char* apps = "/sys/fs/cgroup/apps";
constexpr int appUid = 10042, collectorPid = 1000, appPid = 999;
constexpr int missingPid = 2001, presentPid = 2002;
constexpr uint64_t millisecond = 1000000ULL, second = 1000 * millisecond;
unsigned assertions = 0;

void expect(bool value, const std::string& message) {
    ++assertions;
    if (!value) throw std::runtime_error(message);
}

std::string uidPath(const std::string& layout, int uid) {
    return layout + "/uid_" + std::to_string(uid);
}

std::string pidPath(const std::string& layout, int uid, int pid) {
    return uidPath(layout, uid) + "/pid_" + std::to_string(pid);
}

bool within(const std::string& path, const std::string& directory) {
    return path == directory || path.compare(0, directory.size() + 1, directory + "/") == 0;
}

// This models the OS boundary only. Every scenario executes the production
// Scanner::run, including discovery, cache handling, calibration and PID checks.
class FakeIo final : public cgroup_watch::Io {
public:
    uint64_t clock = second, statCostNs = 1000, uidProbeCostNs = 1000;
    size_t sampleStatCalls = 0;
    std::vector<int> sampleUidProbes;
    std::set<std::string> directories;
    std::map<std::string, int> exactErrors;
    std::map<std::string, int> deniedTrees;
    std::map<std::string, ino_t> directoryInodes;
    std::map<int, int> pidfdStates;
    std::map<int, uint64_t> starts;
    std::map<int, int> processUids;
    std::function<void(FakeIo&, const std::string&)> beforeStat;
    bool procFs = true;

    FakeIo() {
        directories.insert("/proc");
        addProcess(collectorPid, appUid);
        addProcess(appPid, appUid);
        addProcess(missingPid, 0);
        addProcess(presentPid, 0);
        addPid(root, appUid, appPid);
        addPid(root, 0, presentPid);
    }

    void addProcess(int value, int processUid) {
        directories.insert("/proc/" + std::to_string(value));
        starts[value] = uint64_t(value) * 100;
        processUids[value] = processUid;
        pidfdStates[value + 10000] = 0;
    }

    void addUid(const std::string& layout, int value) {
        directories.insert(layout);
        directories.insert(uidPath(layout, value));
    }

    void addPid(const std::string& layout, int value, int pidValue) {
        addUid(layout, value);
        directories.insert(pidPath(layout, value, pidValue));
    }

    void removeDirectory(const std::string& path) {
        for (auto it = directories.begin(); it != directories.end();) {
            if (within(*it, path)) it = directories.erase(it);
            else ++it;
        }
    }

    void beginSample() {
        sampleStatCalls = 0;
        sampleUidProbes.clear();
    }

    uint64_t timeNs() override { return clock; }
    int uid() override { return appUid; }
    int pid() override { return collectorPid; }
    int parentPid() override { return appPid; }
    bool isProcFs() override { return procFs; }

    int statDirectory(const std::string& path, struct stat& info) override {
        ++sampleStatCalls;
        const std::string prefix = std::string(root) + "/uid_";
        uint64_t numeric = 0;
        const bool rootUidProbe = path.compare(0, prefix.size(), prefix) == 0
            && cgroup_watch::uintValue(path.substr(prefix.size()), numeric) && numeric < 100000;
        if (rootUidProbe) sampleUidProbes.push_back(int(numeric));
        clock += rootUidProbe ? uidProbeCostNs : statCostNs;
        if (beforeStat) beforeStat(*this, path);
        const auto forced = exactErrors.find(path);
        if (forced != exactErrors.end() && forced->second) return forced->second;
        for (const auto& tree : deniedTrees) if (within(path, tree.first)) return tree.second;
        if (!directories.count(path)) return ENOENT;
        info = {};
        info.st_mode = S_IFDIR | 0555;
        info.st_uid = appUid;
        info.st_dev = 1;
        info.st_ino = directoryInodes.count(path) ? directoryInodes.at(path) : 1;
        if (path.compare(0, 6, "/proc/") == 0) {
            uint64_t value = 0;
            if (cgroup_watch::uintValue(path.substr(6), value) && processUids.count(int(value)))
                info.st_uid = processUids.at(int(value));
        }
        return 0;
    }

    bool readText(const std::string& path, std::string& out, size_t limit, int& error) override {
        clock += statCostNs;
        const size_t suffix = path.rfind("/stat");
        uint64_t value = 0;
        if (path.compare(0, 6, "/proc/") != 0 || suffix == std::string::npos
            || suffix + 5 != path.size()
            || !cgroup_watch::uintValue(path.substr(6, suffix - 6), value)
            || !starts.count(int(value))) {
            error = EACCES;
            return false;
        }
        std::ostringstream text;
        text << value << " (fixture) R";
        for (int field = 1; field < 19; ++field) text << " 0";
        text << ' ' << starts.at(int(value));
        if (text.str().size() > limit) { error = EOVERFLOW; return false; }
        out = text.str();
        error = 0;
        return true;
    }

    int pidfdState(int fd) override {
        const auto found = pidfdStates.find(fd);
        return found == pidfdStates.end() ? -1 : found->second;
    }
};

struct Fixture {
    FakeIo io;
    cgroup_watch::Scanner scanner{io};
    std::map<int, cgroup_watch::Held> held;
    unsigned index = 0;

    Fixture() {
        hold(missingPid);
        hold(presentPid);
    }

    void hold(int value) {
        held[value] = {value + 10000, io.starts.at(value), "held:" + std::to_string(value), true};
    }

    cgroup_watch::Result run() {
        io.beginSample();
        return scanner.run({}, held, index++, true);
    }
};

std::string state(const cgroup_watch::Result& result, int pid) {
    const auto row = result.processes.find(pid);
    return row == result.processes.end() ? "UNKNOWN" : row->second.check.state;
}

void noMissing(const cgroup_watch::Result& result, const std::string& message) {
    for (const auto& row : result.processes) expect(row.second.check.state != "MISSING", message);
}

void fullCurrentCoverage() {
    Fixture f;
    for (int frame = 0; frame < 3; ++frame) {
        const auto result = f.run();
        expect(result.available && result.calibrationValid, "complete layout was unavailable");
        expect(result.freshCoverageThisSample && result.missingDetectionAvailable,
               "complete current scan did not enable strict missing checks");
        expect(state(result, presentPid) == "PRESENT", "known path was not present");
        expect(state(result, missingPid) == "MISSING", "fully checked live PID was not missing");
        expect(result.processes.at(missingPid).check.uidCoverageComplete,
               "strict missing lacked UID coverage");
        f.io.clock += second;
    }
}

void slowDiscoveryResumes() {
    Fixture f;
    f.io.removeDirectory(pidPath(root, 0, presentPid));
    f.io.addPid(root, 95000, presentPid);
    f.io.uidProbeCostNs = 60000;
    std::set<int> visited;
    bool reachedHighUid = false;
    for (int frame = 0; frame < 12 && !reachedHighUid; ++frame) {
        const uint64_t began = f.io.clock;
        const auto result = f.run();
        visited.insert(f.io.sampleUidProbes.begin(), f.io.sampleUidProbes.end());
        expect(f.io.clock - began <= 651 * millisecond, "slow scan exceeded the 650 ms bound");
        expect(f.io.sampleStatCalls < 20000, "one slow frame performed an unbounded discovery pass");
        expect(!result.freshCoverageThisSample && !result.missingDetectionAvailable,
               "a cross-frame UID catalog was treated as current full coverage");
        noMissing(result, "slow cached coverage manufactured missing evidence");
        reachedHighUid = state(result, presentPid) == "PRESENT";
        f.io.clock += 100 * millisecond;
    }
    expect(reachedHighUid, "discovery never reached uid_95000; the cursor may restart each frame");
    expect(visited.count(95000) != 0 && visited.count(0) != 0, "UID sweep did not advance across ranges");
    // Restore fast IO; after finishing any in-flight pass, a new complete pass
    // in one frame must restore strict missing detection without a restart.
    f.io.uidProbeCostNs = 1000;
    bool restored = false;
    for (int frame = 0; frame < 4 && !restored; ++frame) {
        const auto result = f.run();
        restored = result.freshCoverageThisSample && result.missingDetectionAvailable
            && state(result, missingPid) == "MISSING";
    }
    expect(restored, "fast IO did not restore same-frame strict coverage");
}

void blockedLayoutKeepsPositiveOnly() {
    Fixture f;
    f.io.deniedTrees[apps] = EACCES;
    const auto partial = f.run();
    expect(partial.available && partial.calibrationValid, "one blocked layout disabled the good layout");
    expect(!partial.missingDetectionAvailable && !partial.freshCoverageThisSample,
           "blocked layout was silently omitted from absence coverage");
    expect(state(partial, presentPid) == "PRESENT", "blocked layout discarded independently verified presence");
    expect(state(partial, missingPid) == "UNKNOWN", "blocked layout allowed a missing conclusion");
    expect(!partial.complete && partial.status == "partial", "partial capability was reported as complete");
    f.io.deniedTrees.clear();
    const auto restored = f.run();
    expect(restored.missingDetectionAvailable && state(restored, missingPid) == "MISSING",
           "an actually absent optional layout did not restore strict coverage");
}

void discoveryIsFairAcrossLayouts() {
    Fixture f;
    f.io.addPid(apps, appUid, appPid);
    f.io.uidProbeCostNs = 60000;
    const auto result = f.run();
    size_t rootProgress = 0, appsProgress = 0;
    for (const auto& layout : result.layouts) {
        if (layout.root == root) rootProgress = layout.scanCompleted;
        if (layout.root == apps) appsProgress = layout.scanCompleted;
    }
    expect(rootProgress > 0 && appsProgress > 0,
           "a slow first layout starved discovery of another accessible layout");
    expect(!result.missingDetectionAvailable, "unfinished multi-layout discovery authorized absence");
}

void slowOptionalUidChecksKeepKnownPositive() {
    Fixture f;
    for (int uid = 0; uid < 300; ++uid) f.io.addUid(root, uid);
    std::map<std::string, unsigned> visits;
    f.io.beforeStat = [&](FakeIo& io, const std::string& path) {
        const size_t marker = path.rfind("/pid_");
        if (marker == std::string::npos) return;
        const std::string number = path.substr(marker + 5);
        if ((number.empty() || number == "2147483647") && visits[path]++ == 0)
            io.clock += millisecond;
    };
    const uint64_t began = f.io.clock;
    const auto result = f.run();
    expect(f.io.clock - began <= 651 * millisecond, "slow optional UID checks exceeded the frame budget");
    expect(result.available && state(result, presentPid) == "PRESENT",
           "late optional UID calibration starved an independently checkable positive");
    expect(!result.missingDetectionAvailable && !result.complete,
           "unfinished optional UID calibration was reported as complete absence coverage");
    noMissing(result, "unfinished UID calibration authorized missing evidence");
}

void noUsableLayout() {
    Fixture f;
    f.io.deniedTrees[root] = EACCES;
    const auto result = f.run();
    expect(!result.available && !result.missingDetectionAvailable, "fully blocked tree was usable");
    noMissing(result, "fully blocked tree produced missing evidence");
}

void cachedCatalogIsNotFreshCoverage() {
    Fixture f;
    const auto first = f.run();
    expect(first.missingDetectionAvailable, "initial catalog did not complete");
    // The next UID has never been in the old positive catalog. A live process
    // acquires a path there before this round; cached positives are insufficient.
    f.io.addPid(root, 95000, missingPid);
    f.io.uidProbeCostNs = 60000;
    f.io.clock += second;
    const auto cached = f.run();
    expect(!cached.freshCoverageThisSample && !cached.missingDetectionAvailable,
           "fresh old positives were mistaken for a complete current UID inventory");
    expect(state(cached, missingPid) != "MISSING", "a new UID was missed while old cache authorized absence");
    expect(state(cached, presentPid) == "PRESENT", "safe positive cache candidate was not rechecked");
}

void expiredCatalogCannotAuthorizeAbsence() {
    Fixture f;
    expect(f.run().missingDetectionAvailable, "initial catalog did not complete");
    f.io.clock += 11 * second;
    f.io.uidProbeCostNs = 60000;
    const auto result = f.run();
    expect(!result.missingDetectionAvailable && !result.freshCoverageThisSample,
           "expired catalog authorized strict absence");
    noMissing(result, "expired cache produced missing evidence");
}

void permissionsAreRechecked() {
    Fixture f;
    expect(f.run().missingDetectionAvailable, "initial catalog did not complete");
    f.io.deniedTrees[root] = EACCES;
    const auto result = f.run();
    expect(!result.available && !result.missingDetectionAvailable, "cached permission survived current denial");
    expect(state(result, presentPid) != "PRESENT", "old positive survived a blocked current tree");
    noMissing(result, "permission change produced missing evidence");
}

void catalogGenerationTracksUidChanges() {
    Fixture f;
    const auto original = f.run();
    const auto unchanged = f.run();
    expect(original.generation == unchanged.generation, "identical fresh catalog changed identity");
    f.io.addUid(root, 12345);
    const auto added = f.run();
    expect(added.generation != original.generation, "adding a UID did not change catalog generation");
    expect(added.missingDetectionAvailable, "complete new UID inventory was not usable");
    f.io.removeDirectory(uidPath(root, 12345));
    const auto removed = f.run();
    expect(removed.generation != added.generation, "removing a UID did not change catalog generation");
    expect(removed.missingDetectionAvailable, "complete inventory after removal was not usable");
}

void finalCalibrationRevokesEvidence() {
    Fixture f;
    bool targetSeen = false;
    const std::string control = pidPath(root, appUid, appPid);
    f.io.exactErrors[pidPath(root, 0, presentPid)] = EACCES;
    f.io.beforeStat = [&](FakeIo& io, const std::string& path) {
        if (path == pidPath(root, 0, presentPid)) targetSeen = true;
        if (targetSeen && path == control) io.exactErrors[control] = ENOENT;
    };
    const auto result = f.run();
    expect(targetSeen, "test did not reach a PID path before the final control change");
    expect(!result.missingDetectionAvailable, "changed final calibration retained strict absence");
    noMissing(result, "changed final controls left a previously generated missing result");
    expect(state(result, presentPid) != "PRESENT", "changed calibration retained inferred EACCES presence");
}

void allUidControlsAreRechecked() {
    Fixture f;
    for (int uid = 0; uid < 40; ++uid) f.io.addUid(root, uid);
    f.io.removeDirectory(pidPath(root, 0, presentPid));
    const std::string match = pidPath(root, 39, presentPid);
    const std::string changedControl = uidPath(root, 39) + "/pid_";
    f.io.addPid(root, 39, presentPid);
    f.io.exactErrors[match] = EACCES;
    bool targetSeen = false;
    f.io.beforeStat = [&](FakeIo& io, const std::string& path) {
        if (path == match) {
            targetSeen = true;
            io.exactErrors[changedControl] = EACCES;
        }
    };
    const auto result = f.run();
    expect(targetSeen, "test never probed the UID beyond the diagnostic control output limit");
    expect(!result.missingDetectionAvailable, "unreported UID control was not revalidated");
    expect(state(result, presentPid) != "PRESENT", "EACCES presence survived an invalid negative control");
    noMissing(result, "truncated diagnostic controls weakened absence validation");
}

void finalUnrelatedControlFailureKeepsPositive() {
    for (bool differentLayout : {false, true}) {
        Fixture f;
        const std::string other = differentLayout ? apps : root;
        f.io.addUid(other, 12345);
        if (differentLayout) f.io.addPid(other, appUid, appPid);
        const std::string match = pidPath(root, 0, presentPid);
        const std::string failedControl = uidPath(other, 12345) + "/pid_";
        f.io.exactErrors[match] = EACCES;
        bool targetSeen = false;
        f.io.beforeStat = [&](FakeIo& io, const std::string& path) {
            if (path == match) {
                targetSeen = true;
                io.exactErrors[failedControl] = EACCES;
            }
        };
        const auto result = f.run();
        expect(targetSeen, "test never reached the independent positive path");
        expect(result.available && result.calibrationValid,
               "an unrelated final control disabled all good observations");
        expect(state(result, presentPid) == "PRESENT",
               "final failure in another UID or layout discarded a valid positive");
        expect(!result.missingDetectionAvailable, "unrelated failed control still permitted global absence");
        noMissing(result, "partial final calibration retained a whole-scope missing claim");
    }
}

void layoutReplacementRevokesEvidence() {
    Fixture f;
    bool targetSeen = false;
    f.io.beforeStat = [&](FakeIo& io, const std::string& path) {
        if (path == pidPath(root, 0, presentPid)) {
            targetSeen = true;
            io.directoryInodes[root] = 2;
        }
    };
    const auto result = f.run();
    expect(targetSeen, "test never reached the target before replacing the layout");
    expect(!result.available && !result.missingDetectionAvailable,
           "replaced root identity was accepted because errno stayed zero");
    expect(state(result, presentPid) != "PRESENT", "a positive from the old layout epoch survived replacement");
    noMissing(result, "replaced root retained a missing claim from its previous epoch");
}

void noPidfdMeansUnknown() {
    Fixture f;
    f.held.at(missingPid).fd = -1;
    f.held.at(presentPid).fd = -1;
    const auto result = f.run();
    expect(state(result, missingPid) == "UNKNOWN", "missing pidfd was replaced by a stat identity");
    expect(state(result, presentPid) == "UNKNOWN", "presence was attributed without live identity");
    noMissing(result, "missing pidfd produced absence evidence");
}

void currentPathsAreNeverReused() {
    Fixture f;
    expect(state(f.run(), presentPid) == "PRESENT", "initial path not observed");
    f.io.removeDirectory(pidPath(root, 0, presentPid));
    f.io.uidProbeCostNs = 60000;
    const auto result = f.run();
    expect(state(result, presentPid) != "PRESENT", "old PID presence was reused without a current match");
    expect(state(result, presentPid) != "MISSING", "incomplete new scan reused previous complete coverage");
}

void partialPidBatchPreservesCompletedRows() {
    Fixture f;
    for (int value = 3000; value < 3120; ++value) {
        f.io.addProcess(value, 0);
        f.hold(value);
    }
    // Discovery and its final validation are fast. Only positive numeric PID
    // paths are slow, forcing the real target batch limit after some full rows.
    f.io.beforeStat = [](FakeIo& io, const std::string& path) {
        const size_t pos = path.rfind("/pid_");
        uint64_t numeric = 0;
        if (pos != std::string::npos && cgroup_watch::uintValue(path.substr(pos + 5), numeric)
            && numeric >= 3000 && numeric < 3120) io.clock += 5 * millisecond;
    };
    const auto result = f.run();
    expect(result.available && result.missingDetectionAvailable && result.freshCoverageThisSample,
           "target batch truncation discarded fresh preflight coverage");
    expect(!result.complete && result.status == "partial", "slow target batch was not bounded");
    expect(state(result, presentPid) == "PRESENT", "batch truncation discarded a completed positive row");
    expect(state(result, missingPid) == "MISSING", "batch truncation discarded a completed missing row");
    expect(result.completedPidCount < result.eligiblePidCount, "target batch did not leave pending rows");
}

void probeBudgetRemainsBounded() {
    Fixture f;
    f.io.statCostNs = f.io.uidProbeCostNs = 0;
    for (int uid = 0; uid < 1300; ++uid) f.io.addUid(root, uid);
    for (int value = 3000; value < 3420; ++value) {
        f.io.addProcess(value, 0);
        f.hold(value);
    }
    const auto result = f.run();
    expect(f.io.sampleStatCalls <= 500000, "probe count exceeded its hard cap with a stationary fake clock");
    expect(!result.complete && result.completedPidCount < result.eligiblePidCount,
           "probe budget did not stop the target batch");
    expect(state(result, presentPid) == "PRESENT", "bounded target probing lost a completed positive");
    expect(state(result, missingPid) == "MISSING",
           "probe-budget final-control reservation lost an earlier complete missing check");
}

void invalidProcCalibrationBlocksEvidence() {
    Fixture f;
    f.io.procFs = false;
    const auto result = f.run();
    expect(!result.available && !result.missingDetectionAvailable, "unverified procfs permitted path evidence");
    noMissing(result, "invalid proc controls allowed missing evidence");
}
} // namespace

int main() {
    unsigned passed = 0, failed = 0;
    const std::vector<std::pair<const char*, std::function<void()>>> scenarios{
        {"current complete coverage permits strict missing checks", fullCurrentCoverage},
        {"slow discovery resumes and fast IO restores strict coverage", slowDiscoveryResumes},
        {"blocked layout keeps independent positive evidence only", blockedLayoutKeepsPositiveOnly},
        {"discovery makes progress in each accessible layout", discoveryIsFairAcrossLayouts},
        {"slow optional UID calibration retains a usable positive", slowOptionalUidChecksKeepKnownPositive},
        {"no usable layout stays unavailable", noUsableLayout},
        {"a valid cached catalog is not fresh exhaustive coverage", cachedCatalogIsNotFreshCoverage},
        {"expired catalog cannot authorize absence", expiredCatalogCannotAuthorizeAbsence},
        {"permission changes invalidate cached evidence", permissionsAreRechecked},
        {"UID additions and removals change generation", catalogGenerationTracksUidChanges},
        {"final calibration failure revokes current evidence", finalCalibrationRevokesEvidence},
        {"all UID controls are checked despite diagnostic truncation", allUidControlsAreRechecked},
        {"unrelated final control failures retain independent positives", finalUnrelatedControlFailureKeepsPositive},
        {"a replaced layout inode revokes old-epoch evidence", layoutReplacementRevokesEvidence},
        {"missing pidfd leaves both path states unknown", noPidfdMeansUnknown},
        {"previous PID matches are never replayed", currentPathsAreNeverReused},
        {"partial target batches preserve completed PID checks", partialPidBatchPreservesCompletedRows},
        {"the probe-count budget bounds work with a stationary clock", probeBudgetRemainsBounded},
        {"invalid procfs calibration blocks evidence", invalidProcCalibrationBlocksEvidence},
    };
    for (const auto& scenario : scenarios) {
        try {
            scenario.second();
            ++passed;
            std::cout << "PASS: " << scenario.first << '\n';
        } catch (const std::exception& error) {
            ++failed;
            std::cerr << "FAIL: " << scenario.first << ": " << error.what() << '\n';
        }
    }
    std::cout << "Cgroup scanner: " << passed << " scenarios passed, " << failed
              << " failed, " << assertions << " assertions.\n";
    return failed ? 1 : 0;
}
