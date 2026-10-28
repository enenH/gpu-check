// Ordinary-UID process CPU-clock observer. No privilege escalation or target memory access.
#include <algorithm>
#include <cerrno>
#include <climits>
#include <cmath>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <iomanip>
#include <map>
#include <poll.h>
#include <set>
#include <sstream>
#include <string>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
#include <vector>
#include "cgroup_watch.h"

namespace {
volatile sig_atomic_t stopped = 0, syscallBlocked = 0;
bool watchStdin = false;
void onStop(int) { stopped = 1; }
void onSigsys(int) { syscallBlocked = 1; }
uint64_t nowNs(clockid_t clock = CLOCK_MONOTONIC) {
    timespec value{};
    if (clock_gettime(clock, &value)) return 0;
    return uint64_t(value.tv_sec) * 1000000000ULL + uint64_t(value.tv_nsec);
}
bool alive() {
    if (stopped) return false;
    if (watchStdin) {
        pollfd p{STDIN_FILENO, POLLIN | POLLHUP | POLLERR, 0};
        if (poll(&p, 1, 0) > 0) {
            if (p.revents & (POLLHUP | POLLERR | POLLNVAL)) { stopped = 1; return false; }
            if (p.revents & POLLIN) { char bytes[256]; if (read(STDIN_FILENO, bytes, sizeof(bytes)) <= 0) { stopped = 1; return false; } }
        }
    }
    return true;
}
void sleepUntil(uint64_t end) {
    while (alive()) {
        uint64_t now = nowNs();
        if (now >= end) break;
        uint64_t delay = std::min<uint64_t>(end - now, 50000000ULL);
        timespec duration{time_t(delay / 1000000000ULL), long(delay % 1000000000ULL)};
        nanosleep(&duration, nullptr);
    }
}
std::string q(const std::string& input) {
    std::string result = "\"";
    for (unsigned char c : input) {
        if (c == '\\' || c == '"') { result += '\\'; result += char(c); }
        else if (c >= 32 && c < 127) result += char(c);
        else { char escaped[7]; snprintf(escaped, sizeof(escaped), "\\u%04x", unsigned(c)); result += escaped; }
    }
    return result + '"';
}
void strings(std::ostream& out, const std::vector<std::string>& values) {
    out << '[';
    for (size_t i = 0; i < values.size(); ++i) { if (i) out << ','; out << q(values[i]); }
    out << ']';
}
bool digits(const std::string& s) {
    return !s.empty() && std::all_of(s.begin(), s.end(), [](unsigned char c) { return c >= '0' && c <= '9'; });
}
bool number(const std::string& s, uint64_t& value) {
    if (!digits(s)) return false;
    char* end = nullptr; errno = 0; value = strtoull(s.c_str(), &end, 10);
    return !errno && end && !*end;
}
std::string trim(std::string s) {
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ' || s.back() == '\0')) s.pop_back();
    return s;
}
bool starts(const std::string& s, const std::string& prefix) { return s.compare(0, prefix.size(), prefix) == 0; }
struct Text { std::string value; int error = 0; bool ok = false; };
Text readText(const std::string& path, size_t limit = 16384) {
    Text result;
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) { result.error = errno; return result; }
    char buffer[4096];
    while (result.value.size() < limit) {
        ssize_t n = read(fd, buffer, std::min(sizeof(buffer), limit - result.value.size()));
        if (n < 0) { result.error = errno; break; }
        if (!n) { result.ok = true; break; }
        result.value.append(buffer, size_t(n));
    }
    if (result.value.size() == limit) result.ok = true;
    close(fd); return result;
}
Text readLink(const std::string& path) {
    Text result; char buffer[4096];
    ssize_t n = readlink(path.c_str(), buffer, sizeof(buffer));
    if (n < 0) result.error = errno;
    else if (size_t(n) == sizeof(buffer)) result.error = ENAMETOOLONG;
    else { result.value.assign(buffer, size_t(n)); result.ok = true; }
    return result;
}
Text selinuxXattr(const std::string& path) {
    Text result; char buffer[512];
    ssize_t n = lgetxattr(path.c_str(), "security.selinux", buffer, sizeof(buffer));
    if (n < 0) result.error = errno;
    else { result.value = trim(std::string(buffer, size_t(n))); result.ok = true; }
    return result;
}
struct StatFields { std::string name; uint64_t start = 0, ticks = 0; int64_t tty = 0, rss = 0, threads = 0; };
bool parseStat(const std::string& raw, StatFields& value) {
    auto left = raw.find('('), right = raw.rfind(')');
    if (left == std::string::npos || right == std::string::npos || right <= left) return false;
    std::istringstream in(raw.substr(right + 1));
    std::vector<std::string> fields; std::string field;
    while (in >> field) fields.push_back(field);
    if (fields.size() < 22) return false;
    uint64_t user = 0, kernel = 0;
    if (!number(fields[11], user) || !number(fields[12], kernel) || !number(fields[19], value.start) || user > UINT64_MAX - kernel) return false;
    value.name = raw.substr(left + 1, right - left - 1); value.ticks = user + kernel;
    value.tty = strtoll(fields[4].c_str(), nullptr, 10); value.threads = strtoll(fields[17].c_str(), nullptr, 10);
    value.rss = strtoll(fields[21].c_str(), nullptr, 10); return true;
}
int parseUid(const std::string& raw) {
    std::istringstream in(raw); std::string line;
    while (std::getline(in, line)) {
        if (!starts(line, "Uid:")) continue;
        std::istringstream values(line.substr(4)); uint64_t real = 0, effective = 0;
        if (values >> real >> effective && effective <= INT_MAX) return int(effective);
    }
    return -1;
}
bool processClock(int pid, uint64_t& cpu) {
    clockid_t clock = clockid_t(int32_t((~uint32_t(pid) << 3) | 2U));
    timespec t{};
    if (clock_gettime(clock, &t) || t.tv_sec < 0 || t.tv_nsec < 0 || t.tv_nsec >= 1000000000L) return false;
    cpu = uint64_t(t.tv_sec) * 1000000000ULL + uint64_t(t.tv_nsec); return true;
}
std::set<int> ownProcesses(int appPid) {
    std::set<int> result{int(getpid()), appPid};
    DIR* directory = opendir("/proc");
    if (!directory) return result;
    while (dirent* entry = readdir(directory)) {
        uint64_t pid = 0;
        if (!number(entry->d_name, pid) || pid == 0 || pid > INT_MAX) continue;
        const Text status = readText("/proc/" + std::to_string(pid) + "/status");
        if (status.ok && parseUid(status.value) == int(geteuid())) result.insert(int(pid));
    }
    closedir(directory);
    return result;
}
int openPidfd(int pid) {
#if defined(SYS_pidfd_open)
    syscallBlocked = 0; int fd = int(syscall(SYS_pidfd_open, pid, 0));
    if (syscallBlocked) { errno = ENOSYS; return -1; }
    return fd;
#else
    (void)pid; errno = ENOSYS; return -1;
#endif
}
struct PidfdPollResult { int rc = -1; short revents = 0; int error = 0; };
PidfdPollResult pollPidfd(int fd) {
    pollfd p{fd, POLLIN, 0};
    const int rc = poll(&p, 1, 0);
    return {rc, p.revents, rc < 0 ? errno : 0};
}
const char* pidfdExitEvidence(const PidfdPollResult& result) {
    if (result.rc <= 0) return nullptr;
    if (result.revents & POLLIN) return "pidfd_readable";
    if (result.revents & POLLHUP) return "pidfd_hup";
    return nullptr;
}
bool pidfdLive(int fd) { return pollPidfd(fd).rc == 0; }
struct PidInfo { uint64_t mask, cgroupid; uint32_t pid,tgid,ppid,ruid,rgid,euid,egid,suid,sgid,fsuid,fsgid,spare; };
static_assert(sizeof(PidInfo) == 64);
bool pidfdCredentials(int fd, int pid, int& uid) {
    PidInfo info{}; info.mask = 3;
    if (ioctl(fd, 0xc040ff0bUL, &info) || (info.mask & 3) != 3 || int(info.pid) != pid || info.euid > INT_MAX) return false;
    uid = int(info.euid); return true;
}
bool gpuPath(const std::string& path) {
    if (path == "/dev/kgsl-3d0" || path == "/dev/mali" || path == "/dev/pvrsrvkm") return true;
    for (const std::string prefix : {"/dev/mali", "/dev/dri/renderD", "/dev/dri/card"})
        if (starts(path, prefix) && digits(path.substr(prefix.size()))) return true;
    return false;
}
struct Previous {
    uint64_t cpu = 0, time = 0, start = 0, epoch = 0;
    int pidfd = -1;
    bool hasCpuBaseline = false, startKnown = false;
};
std::string heldIdentity(int pid, uint64_t epoch) {
    return "held_pidfd:" + std::to_string(pid) + ":" + std::to_string(epoch);
}
bool canReportAppearance(unsigned sample, bool previousRangeComplete, bool currentRangeComplete, bool previouslyObserved) {
    return sample > 0 && previousRangeComplete && currentRangeComplete && !previouslyObserved;
}
class ProcessEventBatch {
    struct Event { std::string type; int pid; std::string identity; uint64_t time; std::string evidence; short pollRevents; };
    std::vector<Event> events;
public:
    static constexpr size_t capacity = 512;
    bool truncated = false;
    void clear() { events.clear(); truncated = false; }
    size_t size() const { return events.size(); }
    void add(const char* type, int pid, const std::string& identity, const char* evidence, short revents = 0) {
        if (events.size() >= capacity) { truncated = true; return; }
        events.push_back({type, pid, identity, nowNs(), evidence, revents});
    }
    void json(std::ostream& out) const {
        out << '[';
        for (size_t i = 0; i < events.size(); ++i) {
            if (i) out << ',';
            const auto& e = events[i];
            out << "{\"type\":" << q(e.type) << ",\"pid\":" << e.pid << ",\"identityToken\":" << q(e.identity)
                << ",\"observedMonotonicNs\":" << e.time << ",\"evidence\":" << q(e.evidence)
                << ",\"pidfdPollRevents\":" << e.pollRevents << '}';
        }
        out << ']';
    }
};
struct Process {
    int pid = 0, uid = -1;
    std::string name, exe, cmdline, uidSource = "unknown", identitySource = "unverified", identityToken;
    std::string background = "unknown", backgroundReason = "Foreground/background metadata inaccessible", context, probeState = "not_probed";
    uint64_t start = 0, probeEpochMs = 0, probeEndEpochMs = 0, probeMonotonicNs = 0, probeEndMonotonicNs = 0;
    uint64_t cpuWindowStartNs = 0, cpuWindowEndNs = 0;
    int64_t rssKb = -1, threads = -1; double cpu = -1;
    bool identityVerified = false, gpuDeviceOpen = false, gpuReadable = false, procReadable = false, selinuxRootDomainHint = false;
    bool pidfdOpenedForProbe = false, pidfdAliveBeforeStat = false, pidfdAliveAfterStat = false;
    bool pidfdProcMismatchObserved = false, pidfdProcMismatch = false;
    unsigned pidfdProcMismatchConsecutive = 0;
    int procDirectoryErrno = -1, statusErrno = -1, statErrno = -1, xattrErrno = -1;
    std::vector<std::string> gpuEvidence, errors;
    cgroup_watch::Check cgroupCheck;
};

// A separate, bounded signal feed keeps observed zero-CPU intervals even when the
// UI omits idle rows. It never backfills a missing clock sample with zero.
struct CpuSample {
    int pid = 0;
    bool identityVerified = false;
    std::string identityToken;
    double cpu = -1;
    uint64_t beginNs = 0, endNs = 0;
};
CpuSample cpuSample(const Process& p) {
    return {p.pid, p.identityVerified, p.identityToken, p.cpu, p.cpuWindowStartNs, p.cpuWindowEndNs};
}
bool validCpuSample(const CpuSample& p) {
    return p.pid > 0 && !p.identityToken.empty() && std::isfinite(p.cpu) && p.cpu >= 0
        && p.beginNs > 0 && p.endNs > p.beginNs;
}
class CpuSignalCache {
    struct Track {
        std::string identityToken;
        uint64_t lastActiveNs = 0, lastSampleNs = 0;
        double recentPeak = 0;
    };
    std::map<int, Track> tracks;
public:
    static constexpr size_t capacity = 128;
    static constexpr uint64_t retentionNs = 120000000000ULL;
    std::vector<CpuSample> samples;
    bool truncated = false;
    size_t eligibleCount = 0, capacityOmissions = 0, capacityEvictions = 0;
    void update(const std::map<int, CpuSample>& current, const std::set<int>& priority = {}) {
        samples.clear(); truncated = false; eligibleCount = capacityOmissions = capacityEvictions = 0;
        for (auto it = tracks.begin(); it != tracks.end();) {
            const auto found = current.find(it->first);
            if (found == current.end() || !validCpuSample(found->second)
                || found->second.identityToken != it->second.identityToken) {
                it = tracks.erase(it);
                continue;
            }
            const CpuSample& p = found->second;
            Track& track = it->second;
            if (p.endNs <= track.lastSampleNs || p.beginNs != track.lastSampleNs) { it = tracks.erase(it); continue; }
            // Priority is not a measured signal: discount old bursts to admit newly busy PIDs.
            const double decay = std::exp(-double(p.endNs - track.lastSampleNs) / double(retentionNs));
            track.recentPeak = std::max(p.cpu, track.recentPeak * decay);
            track.lastSampleNs = p.endNs;
            if (p.cpu > 0) track.lastActiveNs = p.endNs;
            if (p.endNs - track.lastActiveNs > retentionNs && !priority.count(it->first)) { it = tracks.erase(it); continue; }
            ++it;
        }
        std::set<int> previouslyTracked;
        for (const auto& entry : tracks) previouslyTracked.insert(entry.first);
        for (const auto& entry : current) {
            const CpuSample& p = entry.second;
            if (!validCpuSample(p) || (p.cpu <= 0 && !priority.count(entry.first)) || tracks.count(entry.first)) continue;
            tracks.emplace(entry.first, Track{p.identityToken, p.endNs, p.endNs, p.cpu});
        }
        eligibleCount = tracks.size();
        std::vector<int> ranking;
        for (const auto& entry : tracks) ranking.push_back(entry.first);
        std::sort(ranking.begin(), ranking.end(), [&](int a, int b) {
            const double scoreA = std::max(current.at(a).cpu, tracks.at(a).recentPeak * 0.25);
            const double scoreB = std::max(current.at(b).cpu, tracks.at(b).recentPeak * 0.25);
            if (scoreA != scoreB) return scoreA > scoreB;
            if (current.at(a).cpu != current.at(b).cpu) return current.at(a).cpu > current.at(b).cpu;
            if (tracks.at(a).lastActiveNs != tracks.at(b).lastActiveNs) return tracks.at(a).lastActiveNs > tracks.at(b).lastActiveNs;
            return a < b;
        });
        if (ranking.size() > capacity) {
            truncated = true;
            capacityOmissions = ranking.size() - capacity;
            for (size_t i = capacity; i < ranking.size(); ++i) {
                if (previouslyTracked.count(ranking[i])) ++capacityEvictions;
                tracks.erase(ranking[i]);
            }
            ranking.resize(capacity);
        }
        for (int pid : ranking) samples.push_back(current.at(pid));
    }
    void json(std::ostream& out) const {
        out << '[';
        for (size_t i = 0; i < samples.size(); ++i) {
            if (i) out << ',';
            const CpuSample& p = samples[i];
            out << "{\"pid\":" << p.pid << ",\"identityVerified\":" << p.identityVerified << ",\"identityToken\":" << q(p.identityToken)
                << ",\"cpuPercent\":" << std::defaultfloat << std::setprecision(12) << p.cpu << std::fixed << std::setprecision(3) << '}';
        }
        out << ']';
    }
};

struct EnvironmentObservation {
    int pid = 0;
    std::string identityToken;
    bool pidfdOpen = false, aliveBefore = false, aliveAfter = false, statAttempted = false;
    int procStatErrno = -1;
    uint64_t probeEpochMs = 0, probeEndEpochMs = 0, probeMonotonicNs = 0, probeEndMonotonicNs = 0;
};
EnvironmentObservation environmentObservation(const Process& p) {
    return {p.pid, p.identityToken, p.pidfdOpenedForProbe, p.pidfdAliveBeforeStat, p.pidfdAliveAfterStat,
        p.probeEpochMs != 0, p.procDirectoryErrno, p.probeEpochMs, p.probeEndEpochMs,
        p.probeMonotonicNs, p.probeEndMonotonicNs};
}
bool existenceViewsConflict(const EnvironmentObservation& p) {
    return p.pid > 0 && !p.identityToken.empty() && p.statAttempted && p.pidfdOpen
        && p.aliveBefore && p.aliveAfter && (p.procStatErrno == ENOENT || p.procStatErrno == ESRCH);
}
class EnvironmentChecks {
    struct State {
        std::string identityToken;
        unsigned lastSample = 0, consecutive = 0;
        uint64_t firstObservedEpochMs = 0;
    };
    struct Check { EnvironmentObservation observation; State state; };
    std::map<int, State> previous;
    std::vector<Check> checks;
public:
    bool anomaly = false;
    size_t attempted = 0, livePidfdChecks = 0;
    void update(unsigned sample, const std::vector<EnvironmentObservation>& observations) {
        checks.clear(); anomaly = false; attempted = livePidfdChecks = 0;
        std::map<int, State> next;
        for (const auto& p : observations) {
            if (p.statAttempted) ++attempted;
            if (p.statAttempted && p.pidfdOpen && p.aliveBefore && p.aliveAfter) ++livePidfdChecks;
            if (!existenceViewsConflict(p) || next.count(p.pid)) continue;
            State state{p.identityToken, sample, 1, p.probeEpochMs};
            const auto old = previous.find(p.pid);
            if (old != previous.end() && old->second.identityToken == p.identityToken
                && sample > 0 && old->second.lastSample == sample - 1) {
                state.consecutive = old->second.consecutive + 1;
                state.firstObservedEpochMs = old->second.firstObservedEpochMs;
            }
            if (state.consecutive >= 2) anomaly = true;
            next.emplace(p.pid, state);
            checks.push_back({p, state});
        }
        // A skipped sample, permission denial, success, exit or changed identity resets evidence.
        previous = std::move(next);
    }
    unsigned consecutive(int pid, const std::string& identity) const {
        const auto found = previous.find(pid);
        return found != previous.end() && found->second.identityToken == identity ? found->second.consecutive : 0;
    }
    size_t size() const { return checks.size(); }
    void json(std::ostream& out) const {
        out << '[';
        for (size_t i = 0; i < checks.size(); ++i) {
            if (i) out << ',';
            const auto& p = checks[i].observation;
            const auto& state = checks[i].state;
            const bool confirmed = state.consecutive >= 2;
            out << "{\"pid\":" << p.pid << ",\"identityToken\":" << q(p.identityToken)
                << ",\"pidfdOpen\":true,\"pidfdAlive\":true,\"pidfdAliveBeforeStat\":true,\"pidfdAliveAfterStat\":true"
                << ",\"procPath\":" << q("/proc/" + std::to_string(p.pid)) << ",\"procStatReturn\":-1,\"procStatErrno\":" << p.procStatErrno
                << ",\"procStatErrnoName\":" << q(p.procStatErrno == ENOENT ? "ENOENT" : "ESRCH")
                << ",\"consecutiveFailures\":" << state.consecutive << ",\"requiredConsecutiveFailures\":2,\"sampleIndex\":" << state.lastSample
                << ",\"firstObservedEpochMs\":" << state.firstObservedEpochMs << ",\"probeEpochMs\":" << p.probeEpochMs
                << ",\"probeEndEpochMs\":" << p.probeEndEpochMs << ",\"probeMonotonicNs\":" << p.probeMonotonicNs
                << ",\"probeEndMonotonicNs\":" << p.probeEndMonotonicNs << ",\"status\":" << q(confirmed ? "ANOMALY" : "PENDING")
                << ",\"reason\":" << q(confirmed
                    ? "The same live held-pidfd identity conflicts with proc PID-directory nonexistence in consecutive samples; existence views disagree, without proving root identity or malicious hiding"
                    : "One live-pidfd versus proc-nonexistence conflict observed; another consecutive sample with the same identity is required") << '}';
        }
        out << ']';
    }
};

struct Capabilities {
    bool pidfd = false, pidfdUid = false, selfClock = false, externalClock = false, pidMaxReadable = false;
    int pidfdErrno = 0, pidfdInfoErrno = 0, selfClockErrno = 0, externalClockErrno = 0, pidMaxErrno = 0;
    unsigned pidMax = 0; std::string selinux;
};
Capabilities capabilities() {
    Capabilities caps; uint64_t cpu = 0;
    caps.selfClock = processClock(getpid(), cpu); if (!caps.selfClock) caps.selfClockErrno = errno;
    caps.externalClock = processClock(1, cpu); if (!caps.externalClock) caps.externalClockErrno = errno;
    int fd = openPidfd(getpid()); caps.pidfd = fd >= 0;
    if (fd < 0) caps.pidfdErrno = errno;
    else { int uid = -1; caps.pidfdUid = pidfdCredentials(fd, getpid(), uid); if (!caps.pidfdUid) caps.pidfdInfoErrno = errno; close(fd); }
    Text maximum = readText("/proc/sys/kernel/pid_max", 64); uint64_t parsed = 0;
    caps.pidMaxErrno = maximum.error;
    if (maximum.ok && number(trim(maximum.value), parsed) && parsed > 0 && parsed <= INT_MAX) {
        caps.pidMax = unsigned(parsed); caps.pidMaxReadable = true;
    }
    Text label = readText("/proc/self/attr/current", 512); if (label.ok) caps.selinux = trim(label.value);
    return caps;
}
void inspect(Process& p, Previous& observed, const Capabilities& caps) {
    p.probeEpochMs = nowNs(CLOCK_REALTIME) / 1000000ULL;
    p.probeMonotonicNs = nowNs();
    p.probeState = "attempted";
    std::string base = "/proc/" + std::to_string(p.pid);
    if (p.uid < 0 && caps.pidfdUid && observed.pidfd >= 0 && pidfdCredentials(observed.pidfd, p.pid, p.uid)) p.uidSource = "pidfd_get_info_effective_uid";
    struct stat directory{};
    p.pidfdOpenedForProbe = observed.pidfd >= 0;
    p.pidfdAliveBeforeStat = p.pidfdOpenedForProbe && pidfdLive(observed.pidfd);
    const int directoryResult = ::stat(base.c_str(), &directory);
    p.procDirectoryErrno = directoryResult ? errno : 0;
    p.pidfdAliveAfterStat = p.pidfdOpenedForProbe && pidfdLive(observed.pidfd);
    p.pidfdProcMismatchObserved = existenceViewsConflict(environmentObservation(p));
    if (directoryResult) {
        p.probeState = p.procDirectoryErrno == ENOENT || p.procDirectoryErrno == ESRCH
            ? "proc_directory_nonexistent" : "proc_directory_denied";
        // A single precise denial provides the target directory for AVC correlation.
        // Do not flood the audit buffer with repeated inaccessible child metadata probes.
        p.errors.push_back("Proc PID directory stat unavailable; additional metadata probes skipped to bound AVC volume");
        if (p.uid < 0) p.errors.push_back("Target effective UID remains unknown");
        p.probeEndEpochMs = nowNs(CLOCK_REALTIME) / 1000000ULL;
        p.probeEndMonotonicNs = nowNs();
        return;
    }
    if (S_ISDIR(directory.st_mode) && (directory.st_mode & 0777) == 0555 && directory.st_uid <= INT_MAX && p.uid < 0) {
        p.uid = int(directory.st_uid); p.uidSource = "proc_pid_directory_owner_effective_uid";
    }
    Text status = readText(base + "/status"), stat = readText(base + "/stat");
    p.statusErrno = status.error; p.statErrno = stat.error;
    if (status.ok) { int effective = parseUid(status.value); if (effective >= 0) { p.uid = effective; p.uidSource = "proc_status_effective_uid"; } }
    StatFields fields;
    if (stat.ok && parseStat(stat.value, fields)) {
        p.procReadable = true; p.name = fields.name; p.start = fields.start;
        p.rssKb = std::max<int64_t>(0, fields.rss) * std::max(1L, sysconf(_SC_PAGESIZE) / 1024); p.threads = fields.threads;
        if (observed.startKnown && observed.start != fields.start) {
            p.cpu = -1;
            // A held pidfd owns the lifecycle token even if path metadata races with PID reuse.
            if (observed.pidfd < 0) observed.epoch = nowNs();
        }
        observed.start = fields.start; observed.startKnown = true;
        p.identityVerified = true; p.identitySource = "proc_starttime";
    }
    if (observed.pidfd >= 0) { p.identityVerified = true; p.identitySource = "held_pidfd"; }
    p.identityToken = p.identityVerified ? p.identitySource + ":" + std::to_string(p.pid) + ":" + std::to_string(observed.epoch)
        : "unverified:" + std::to_string(p.pid) + ":" + std::to_string(nowNs());
    Text exe = readLink(base + "/exe"), cmd = readText(base + "/cmdline", 4096), group = readText(base + "/cgroup");
    if (exe.ok) p.exe = exe.value;
    if (cmd.ok) { p.cmdline = trim(cmd.value); std::replace(p.cmdline.begin(), p.cmdline.end(), '\0', ' '); }
    if (group.ok && group.value.find("top-app") != std::string::npos) { p.background = "foreground"; p.backgroundReason = "top-app cgroup"; }
    else if (group.ok && (group.value.find("background") != std::string::npos || group.value.find("cached") != std::string::npos)) {
        p.background = "background"; p.backgroundReason = "background/cached cgroup";
    } else if (group.ok && p.procReadable && fields.tty == 0 && !p.exe.empty() && p.exe[0] == '/' && p.exe.find("/app_process") == std::string::npos) {
        p.background = "background"; p.backgroundReason = "inferred native executable without controlling terminal; Activity visibility not established";
    }
    Text xattr = selinuxXattr(base); p.xattrErrno = xattr.error;
    if (xattr.ok) p.context = xattr.value;
    if (p.context.empty()) { Text attr = readText(base + "/attr/current", 512); if (attr.ok) p.context = trim(attr.value); }
    for (const std::string hint : {":su:", ":magisk:", ":zygisk:", ":ksu:"})
        if (p.context.find(hint) != std::string::npos) p.selinuxRootDomainHint = true;
    DIR* fds = opendir((base + "/fd").c_str());
    if (fds) {
        p.gpuReadable = true; unsigned visited = 0;
        while (dirent* entry = readdir(fds)) {
            if (!digits(entry->d_name)) continue;
            if (++visited > 4096) { p.gpuReadable = false; break; }
            Text target = readLink(base + "/fd/" + entry->d_name);
            if (!target.ok) { if (target.error == EACCES || target.error == EPERM) p.gpuReadable = false; continue; }
            if (!gpuPath(target.value)) continue;
            struct stat st{};
            if (::stat((base + "/fd/" + entry->d_name).c_str(), &st) == 0 && S_ISCHR(st.st_mode)) {
                p.gpuDeviceOpen = true; p.gpuEvidence.push_back("Readable target GPU device FD " + std::string(entry->d_name) + " -> " + target.value);
            }
        }
        closedir(fds);
    }
    if (p.uid < 0) p.errors.push_back("Target effective UID is unknown under ordinary app permissions");
    if (!p.gpuReadable) p.errors.push_back("Per-PID GPU association inaccessible; global GPU activity is not attributed to this PID");
    if (!p.identityVerified) p.errors.push_back("PID lifecycle unverified; CPU delta is only a candidate observation");
    p.probeState = "completed";
    p.probeEndEpochMs = nowNs(CLOCK_REALTIME) / 1000000ULL;
    p.probeEndMonotonicNs = nowNs();
}
void processJson(std::ostream& out, const Process& p) {
    out << "{\"pid\":" << p.pid << ",\"uid\":" << p.uid << ",\"name\":" << q(p.name.empty() ? "PID " + std::to_string(p.pid) : p.name)
        << ",\"exe\":" << q(p.exe) << ",\"cmdline\":" << q(p.cmdline) << ",\"startTimeTicks\":" << (p.procReadable ? std::to_string(p.start) : "null")
        << ",\"startTimeKnown\":" << p.procReadable
        << ",\"identityVerified\":" << p.identityVerified << ",\"identitySource\":" << q(p.identitySource) << ",\"identityToken\":" << q(p.identityToken)
        << ",\"uidSource\":" << q(p.uidSource) << ",\"cpuPercent\":" << p.cpu << ",\"cpuSource\":\"dynamic_process_sched_clock\""
        << ",\"metadataAccessible\":" << (p.procReadable || p.uid >= 0)
        << ",\"probeTargetPid\":" << p.pid << ",\"probeSourcePid\":" << getpid() << ",\"probeEpochMs\":" << p.probeEpochMs
        << ",\"probeEndEpochMs\":" << p.probeEndEpochMs << ",\"probeMonotonicNs\":" << p.probeMonotonicNs << ",\"probeEndMonotonicNs\":" << p.probeEndMonotonicNs
        << ",\"metadataProbeState\":" << q(p.probeState) << ",\"metadataProbeAttempted\":" << (p.probeEpochMs != 0)
        << ",\"pidfdOpenForProbe\":" << p.pidfdOpenedForProbe << ",\"pidfdAliveBeforeStat\":" << p.pidfdAliveBeforeStat
        << ",\"pidfdAliveAfterStat\":" << p.pidfdAliveAfterStat << ",\"pidfdProcMismatchObserved\":" << p.pidfdProcMismatchObserved
        << ",\"pidfdProcMismatch\":" << p.pidfdProcMismatch << ",\"pidfdProcMismatchConsecutiveFailures\":" << p.pidfdProcMismatchConsecutive
        << ",\"rssKb\":" << p.rssKb << ",\"threads\":" << p.threads << ",\"background\":" << q(p.background) << ",\"backgroundReason\":" << q(p.backgroundReason)
        << ",\"gpuDeviceOpen\":" << p.gpuDeviceOpen << ",\"gpuActive\":false,\"gpuCountersAvailable\":false,\"gpuScanComplete\":" << p.gpuReadable
        << ",\"gpuEvidenceReadable\":" << p.gpuReadable << ",\"selinuxContext\":" << q(p.context) << ",\"selinuxRootDomainHint\":" << p.selinuxRootDomainHint
        << ",\"procDirectoryErrno\":" << p.procDirectoryErrno << ",\"statusErrno\":" << p.statusErrno << ",\"statErrno\":" << p.statErrno << ",\"xattrErrno\":" << p.xattrErrno
        << ",\"gpuEvidence\":"; strings(out, p.gpuEvidence); out << ",\"errors\":"; strings(out, p.errors);
    out << ",\"cgroupCheck\":"; p.cgroupCheck.json(out); out << '}';
}

// Global KGSL memstore observations are deliberately separate from all Process evidence.
// This opens only this collector's GPU file and maps its exported shadow read-only.
// No contexts are created, no GPU commands are submitted, and no target FDs are duplicated.
struct KgslProperty { uint32_t type, pad; uint64_t value, size; };
struct KgslShadow { uint64_t offset, size; uint32_t flags, pad; };
static_assert(sizeof(KgslProperty) == 24 && sizeof(KgslShadow) == 24);

// These are conservative data-quality bounds, not a measured GPU throughput limit.
// A plausible uint32 wrap requires both values to lie within the current allowed
// increment of the rollover boundary. Even that cannot prove a slot was not reused.
constexpr uint64_t kSlotMaxRatePerSecond = 1000000ULL;
constexpr uint64_t kSlotMaxIncrement = 1ULL << 24;
constexpr uint64_t kSlotMinAllowance = 1024ULL;
constexpr uint64_t kSlotMaxIntervalNs = 60000000000ULL;
uint64_t slotDeltaAllowance(uint64_t intervalNs) {
    if (!intervalNs || intervalNs > kSlotMaxIntervalNs) return 0;
    const uint64_t rateAllowance = (intervalNs * kSlotMaxRatePerSecond + 999999999ULL) / 1000000000ULL;
    return std::min(kSlotMaxIncrement, std::max(kSlotMinAllowance, rateAllowance));
}
int64_t comparableSlotDelta(uint32_t before, uint32_t after, bool previouslyPresent,
                           bool currentlyPresent, uint64_t intervalNs, bool& wrapped) {
    wrapped = false;
    const uint64_t allowance = slotDeltaAllowance(intervalNs);
    // A first appearance or disappearance starts a new comparison epoch for this slot.
    if (!allowance || previouslyPresent != currentlyPresent) return -1;
    if (after >= before) {
        const uint64_t delta = uint64_t(after) - before;
        return delta <= allowance ? int64_t(delta) : -1;
    }
    const uint64_t delta = (uint64_t(UINT32_MAX) + 1ULL - before) + after;
    const uint64_t highBoundary = uint64_t(UINT32_MAX) + 1ULL - allowance;
    if (uint64_t(before) >= highBoundary && uint64_t(after) < allowance && delta <= allowance) {
        wrapped = true;
        return int64_t(delta);
    }
    return -1; // ordinary rollback/reset, ambiguous reuse, or unreasonable jump
}

class GlobalGpu {
    int fd = -1;
    void* mapping = MAP_FAILED;
    size_t bytes = 0, slots = 0;
    uint64_t lastTime = 0;
    std::vector<uint32_t> previous;
    std::vector<bool> previousPresent;
    std::vector<std::string> errors;
    bool truncated = false;
    void failure(const std::string& stage, int error) {
        errors.push_back(stage + ": errno=" + std::to_string(error) + " " + strerror(error));
    }
public:
    GlobalGpu() {
        fd = open("/dev/kgsl-3d0", O_RDWR | O_CLOEXEC);
        if (fd < 0) { failure("ordinary UID KGSL open", errno); return; }
        struct stat st{};
        if (fstat(fd, &st) || !S_ISCHR(st.st_mode)) { errors.push_back("KGSL file is not a verified character device"); return; }
        KgslShadow shadow{};
        KgslProperty property{2, 0, uint64_t(uintptr_t(&shadow)), sizeof(shadow)};
        if (ioctl(fd, 0xc0180902UL, &property)) { failure("KGSL shadow GETPROPERTY", errno); return; }
        if (shadow.size < 40 || shadow.size > 16 * 1024 * 1024ULL || shadow.offset > INT64_MAX) {
            errors.push_back("KGSL shadow layout outside bounded supported range"); return;
        }
        bytes = size_t(shadow.size);
        mapping = mmap(nullptr, bytes, PROT_READ, MAP_SHARED, fd, off_t(shadow.offset));
        if (mapping == MAP_FAILED) { failure("ordinary UID read-only KGSL shadow mmap", errno); return; }
        slots = std::min<size_t>(bytes / 40, 4096);
        truncated = bytes / 40 > slots;
    }
    ~GlobalGpu() {
        if (mapping != MAP_FAILED) munmap(mapping, bytes);
        if (fd >= 0) close(fd);
    }
    GlobalGpu(const GlobalGpu&) = delete;
    GlobalGpu& operator=(const GlobalGpu&) = delete;
    bool supported() const { return mapping != MAP_FAILED && slots > 0; }
    void json(std::ostream& out) {
        const uint64_t now = nowNs();
        const bool sampled = supported() && previous.size() == slots && lastTime > 0;
        const uint64_t intervalNs = sampled && now > lastTime ? now - lastTime : 0;
        unsigned observed = 0, advanced = 0;
        unsigned invalidDeltas = 0, wrappedDeltas = 0;
        std::vector<uint32_t> current;
        std::vector<bool> currentPresent;
        std::vector<int64_t> deltas(slots, -1);
        std::vector<size_t> wrappedSlots;
        std::vector<size_t> appearedSlots, disappearedSlots, resetSlots;
        if (supported()) {
            current.reserve(slots);
            currentPresent.reserve(slots);
            const auto* data = static_cast<volatile const uint8_t*>(mapping);
            for (size_t i = 0; i < slots; ++i) {
                const uint32_t submitted = *reinterpret_cast<volatile const uint32_t*>(data + i * 40);
                const uint32_t retired = *reinterpret_cast<volatile const uint32_t*>(data + i * 40 + 8);
                const bool present = submitted || retired;
                if (present) ++observed;
                if (sampled) {
                    const uint32_t delta = retired - previous[i];
                    if (delta > 0 && delta < 0x80000000U) ++advanced;
                    if (previousPresent.size() == slots) {
                        if (!previousPresent[i] && present) appearedSlots.push_back(i);
                        if (previousPresent[i] && !present) disappearedSlots.push_back(i);
                        bool wrapped = false;
                        deltas[i] = comparableSlotDelta(previous[i], retired, previousPresent[i], present, intervalNs, wrapped);
                        if (wrapped) { ++wrappedDeltas; wrappedSlots.push_back(i); }
                    }
                    if (deltas[i] < 0) resetSlots.push_back(i);
                }
                if (deltas[i] < 0) ++invalidDeltas;
                current.push_back(retired);
                currentPresent.push_back(present);
            }
        }
        const uint64_t readEnd = nowNs();
        out << "{\"supported\":" << supported() << ",\"sampled\":" << sampled << ",\"active\":" << (sampled && advanced > 0)
            << ",\"source\":\"kgsl_memstore\",\"scope\":\"device_global_unattributed\",\"observedSlots\":" << observed
            << ",\"advancedSlots\":" << advanced << ",\"monitoredSlots\":" << slots << ",\"intervalMs\":" << intervalNs / 1000000ULL
            << ",\"intervalNs\":" << intervalNs << ",\"sampleMonotonicNs\":" << now
            << ",\"readEndMonotonicNs\":" << readEnd
            << ",\"slotStrideBytes\":40,\"layoutAssumption\":\"bounded KGSL DEVICE_SHADOW with known 40-byte slot layout\",\"includesInternalAndReusedSlots\":true"
            << ",\"lifecycleSlotFirst\":1,\"lifecycleSlotEndExclusive\":" << (slots >= 8 ? slots - 7 : 1)
            << ",\"lifecycleSlotRangeAssumption\":\"reference KGSL layout: user slots [1, slotCount-7); excludes slot 0 and final 7 global/RB/LPAC slots; vendor layout not independently verified\""
            << ",\"slotDeltas\":[";
        for (size_t i = 0; i < deltas.size(); ++i) {
            if (i) out << ',';
            if (deltas[i] < 0) out << "null"; else out << deltas[i];
        }
        out << "],\"slotDeltaWrappedSlots\":[";
        for (size_t i = 0; i < wrappedSlots.size(); ++i) { if (i) out << ','; out << wrappedSlots[i]; }
        out << "],\"appearedSlots\":[";
        for (size_t i = 0; i < appearedSlots.size(); ++i) { if (i) out << ','; out << appearedSlots[i]; }
        out << "],\"disappearedSlots\":[";
        for (size_t i = 0; i < disappearedSlots.size(); ++i) { if (i) out << ','; out << disappearedSlots[i]; }
        out << "],\"resetSlots\":[";
        for (size_t i = 0; i < resetSlots.size(); ++i) { if (i) out << ','; out << resetSlots[i]; }
        out << "],\"slotEventSemantics\":\"presence is nonzero SOP or retired; appearance/disappearance are observation transitions and also invalidate the delta; reset means an invalid non-baseline delta, not verified context creation/destruction\""
            << ",\"slotDeltaInvalidCount\":" << invalidDeltas << ",\"slotDeltaWrapCount\":" << wrappedDeltas
            << ",\"slotDeltaPolicy\":{\"maxRatePerSecond\":" << kSlotMaxRatePerSecond << ",\"absoluteMaxIncrement\":" << kSlotMaxIncrement
            << ",\"minimumAllowance\":" << kSlotMinAllowance << ",\"maxIntervalMs\":" << kSlotMaxIntervalNs / 1000000ULL
            << ",\"currentAllowance\":" << slotDeltaAllowance(intervalNs)
            << ",\"wrapRule\":\"before >= 2^32 - allowance; after < allowance; modular delta <= allowance\""
            << ",\"nullRule\":\"baseline, presence change, rollback outside bounded wrap, excessive increment, or invalid interval\""
            << ",\"wrapIsHeuristic\":true,\"forwardReuseMayBeUndetectable\":true}"
            << ",\"truncated\":" << truncated << ",\"readOnlyMapping\":true,\"pidAssociationAvailable\":false,\"errors\":";
        strings(out, errors); out << '}';
        previous = std::move(current); previousPresent = std::move(currentPresent); lastTime = now;
    }
};
bool selfTest() {
    StatFields stat;
    bool ok = cgroup_watch::selfTest() && parseStat("123 (odd ) name) S 1 2 3 0 5 6 7 8 9 10 123 77 13 14 15 16 4 18 9999 1000 42", stat)
        && stat.start == 9999 && stat.ticks == 200 && stat.name == "odd ) name"
        && parseUid("Uid:\t1000\t0\t0\t0\n") == 0 && parseUid("Uid: bad") == -1
        && int32_t((~uint32_t(2) << 3) | 2U) == -22;
    bool wrapped = false;
    ok = ok && comparableSlotDelta(10, 10, true, true, 2000000000ULL, wrapped) == 0 && !wrapped
        && comparableSlotDelta(10, 35, true, true, 2000000000ULL, wrapped) == 25 && !wrapped
        && comparableSlotDelta(100, 4, true, true, 2000000000ULL, wrapped) == -1
        && comparableSlotDelta(UINT32_MAX - 4, 3, true, true, 2000000000ULL, wrapped) == 8 && wrapped
        && comparableSlotDelta(0x80000000U, 5, true, true, 2000000000ULL, wrapped) == -1 && !wrapped
        && comparableSlotDelta(100, 2000101, true, true, 2000000000ULL, wrapped) == -1
        && comparableSlotDelta(0, 100, false, true, 2000000000ULL, wrapped) == -1
        && comparableSlotDelta(0, 0, true, false, 2000000000ULL, wrapped) == -1
        && comparableSlotDelta(0, 0, false, false, 2000000000ULL, wrapped) == 0
        && comparableSlotDelta(10, 15, true, true, 0, wrapped) == -1
        && comparableSlotDelta(10, 15, true, true, kSlotMaxIntervalNs + 1, wrapped) == -1;
    const auto cpu = [](int pid, const std::string& identity, double value, uint64_t begin, uint64_t end) {
        return CpuSample{pid, true, identity, value, begin * 1000000000ULL, end * 1000000000ULL};
    };
    CpuSignalCache signalTest;
    signalTest.update({{7, cpu(7, "first", 35, 2, 4)}});
    ok = ok && signalTest.samples.size() == 1 && signalTest.samples.front().cpu == 35;
    signalTest.update({{7, cpu(7, "first", 0, 4, 6)}});
    ok = ok && signalTest.samples.size() == 1 && signalTest.samples.front().cpu == 0;
    signalTest.update({{7, cpu(7, "first", 0, 6, 124)}});
    ok = ok && signalTest.samples.size() == 1; // exactly 120 seconds since observed activity
    signalTest.update({{7, cpu(7, "first", 0, 124, 126)}});
    ok = ok && signalTest.samples.empty();
    signalTest.update({{7, cpu(7, "first", 10, 126, 128)}});
    signalTest.update({{7, cpu(7, "replacement", 0, 128, 130)}});
    ok = ok && signalTest.samples.empty(); // a reused PID is never given the old zero history
    signalTest.update({{7, cpu(7, "replacement", 10, 130, 132)}});
    signalTest.update({});
    ok = ok && signalTest.samples.empty(); // missing is not an idle sample
    signalTest.update({{7, cpu(7, "replacement", 0, 134, 136)}});
    ok = ok && signalTest.samples.empty();
    signalTest.update({{7, cpu(7, "cgroup-idle", 0, 136, 138)}}, {7});
    ok = ok && signalTest.samples.size() == 1 && signalTest.samples[0].cpu == 0;
    signalTest.update({{7, cpu(7, "cgroup-idle", 0, 138, 400)}}, {7});
    ok = ok && signalTest.samples.size() == 1 && signalTest.samples[0].cpu == 0;
    signalTest.update({{7, cpu(7, "cgroup-idle", -1, 400, 402)}}, {7});
    ok = ok && signalTest.samples.empty();
    std::map<int, CpuSample> crowded;
    for (int pid = 1; pid <= 129; ++pid) crowded.emplace(pid, cpu(pid, "bounded", double(pid), 2, 4));
    signalTest.update(crowded);
    ok = ok && signalTest.samples.size() == 128 && signalTest.truncated && signalTest.capacityOmissions == 1
        && std::none_of(signalTest.samples.begin(), signalTest.samples.end(), [](const CpuSample& p) { return p.pid == 1; });
    crowded[1] = cpu(1, "idle-priority", 0, 4, 6);
    signalTest.update(crowded, {1});
    ok = ok && signalTest.samples.size() == 128 && signalTest.samples.front().pid == 129
        && std::none_of(signalTest.samples.begin(), signalTest.samples.end(), [](const CpuSample& p) { return p.pid == 1; });
    const auto conflict = [](const std::string& identity, int error, bool opened, bool before, bool after) {
        return EnvironmentObservation{77, identity, opened, before, after, true, error, 1000, 1001, 1000000, 2000000};
    };
    EnvironmentChecks environmentTest;
    environmentTest.update(0, {conflict("epoch-a", ENOENT, true, true, true)});
    ok = ok && !environmentTest.anomaly && environmentTest.size() == 1 && environmentTest.consecutive(77, "epoch-a") == 1;
    environmentTest.update(1, {conflict("epoch-a", ENOENT, true, true, true)});
    ok = ok && environmentTest.anomaly && environmentTest.consecutive(77, "epoch-a") == 2;
    environmentTest.update(2, {conflict("epoch-a", EACCES, true, true, true)});
    ok = ok && !environmentTest.anomaly && environmentTest.size() == 0;
    environmentTest.update(3, {conflict("epoch-a", ENOENT, true, true, true)});
    environmentTest.update(4, {conflict("epoch-a", ENOENT, true, true, false)});
    ok = ok && !environmentTest.anomaly && environmentTest.size() == 0;
    environmentTest.update(5, {conflict("epoch-a", ESRCH, true, true, true)});
    environmentTest.update(6, {conflict("epoch-b", ESRCH, true, true, true)});
    ok = ok && !environmentTest.anomaly && environmentTest.consecutive(77, "epoch-b") == 1 && environmentTest.consecutive(77, "epoch-a") == 0;
    environmentTest.update(7, {conflict("epoch-b", 0, true, true, true)});
    ok = ok && !environmentTest.anomaly && environmentTest.size() == 0;
    environmentTest.update(8, {conflict("epoch-b", ENOENT, true, true, true)});
    ok = ok && !environmentTest.anomaly && environmentTest.consecutive(77, "epoch-b") == 1;
    environmentTest.update(9, {conflict("epoch-b", ENOENT, false, true, true)});
    ok = ok && !environmentTest.anomaly && environmentTest.size() == 0; // clock visibility cannot replace a pidfd
    environmentTest.update(10, {conflict("epoch-b", EPERM, true, true, true)});
    ok = ok && !environmentTest.anomaly && environmentTest.size() == 0;
    environmentTest.update(11, {conflict("epoch-b", ENOENT, true, true, true)});
    environmentTest.update(12, {});
    environmentTest.update(13, {conflict("epoch-b", ENOENT, true, true, true)});
    ok = ok && !environmentTest.anomaly && environmentTest.consecutive(77, "epoch-b") == 1;
    environmentTest.update(15, {conflict("epoch-b", ENOENT, true, true, true)});
    ok = ok && !environmentTest.anomaly && environmentTest.consecutive(77, "epoch-b") == 1;
    environmentTest.update(16, {conflict("epoch-b", ENOENT, true, false, true)});
    ok = ok && !environmentTest.anomaly && environmentTest.size() == 0;
    ok = ok && !canReportAppearance(0, true, true, false)
        && !canReportAppearance(1, false, true, false)
        && !canReportAppearance(1, true, false, false)
        && !canReportAppearance(1, true, true, true)
        && canReportAppearance(1, true, true, false)
        && pidfdExitEvidence({0, POLLIN, 0}) == nullptr
        && pidfdExitEvidence({-1, POLLIN, EINTR}) == nullptr
        && pidfdExitEvidence({1, POLLERR, 0}) == nullptr
        && pidfdExitEvidence({1, POLLNVAL, 0}) == nullptr
        && std::strcmp(pidfdExitEvidence({1, POLLIN, 0}), "pidfd_readable") == 0
        && std::strcmp(pidfdExitEvidence({1, POLLHUP, 0}), "pidfd_hup") == 0;
    printf("{\"selfTest\":%s,\"mode\":\"unprivileged\"}\n", ok ? "true" : "false"); return ok;
}
} // namespace
int main(int argc, char** argv) {
    unsigned interval = 2000, samples = 0, limit = 65536; bool diagnostics = false, test = false;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--once") samples = 1;
        else if (arg == "--capabilities") { diagnostics = true; samples = 1; }
        else if (arg == "--watch-stdin") watchStdin = true;
        else if (arg == "--self-test") test = true;
        else if ((arg == "--interval-ms" || arg == "--samples" || arg == "--pid-limit") && i + 1 < argc) {
            uint64_t n = 0; if (!number(argv[++i], n) || n > 10000000) return 2;
            if (arg == "--interval-ms") { if (n < 500 || n > 10000) return 2; interval = unsigned(n); }
            else if (arg == "--pid-limit") { if (n < 1024 || n > 262144) return 2; limit = unsigned(n); }
            else samples = unsigned(n);
        } else { fprintf(stderr, "Usage: libgpu_probe.so [--interval-ms 500..10000] [--samples N|--once|--capabilities] [--pid-limit 1024..262144] [--watch-stdin] [--self-test]\n"); return 2; }
    }
    if (test) return selfTest() ? 0 : 1;
    struct sigaction action{}; sigemptyset(&action.sa_mask); action.sa_handler = onStop;
    sigaction(SIGTERM, &action, nullptr); sigaction(SIGINT, &action, nullptr);
    action.sa_handler = onSigsys; sigaction(SIGSYS, &action, nullptr); signal(SIGPIPE, SIG_IGN);
    Capabilities caps = capabilities(); if (caps.pidMaxReadable) limit = std::min(limit, caps.pidMax);
    GlobalGpu globalGpu;
    uint64_t session = nowNs(), epoch = session, nextAt = session;
    std::map<int, Previous> previous;
    CpuSignalCache cpuSignals;
    EnvironmentChecks environment;
    ProcessEventBatch processEvents;
    std::set<int> observedPids;
    std::set<int> previousCgroupCandidates;
    cgroup_watch::Scanner cgroupScanner;
    constexpr size_t candidateLimit = 1024;
    bool previousRangeComplete = false;
    const int appPid = int(getppid());
    for (unsigned sample = 0; alive() && (!samples || sample < samples); ++sample) {
        processEvents.clear();
        uint64_t begin = nowNs(); std::map<int, std::pair<uint64_t, uint64_t>> clocks;
        const std::set<int> excluded = ownProcesses(appPid);
        unsigned scanned = 0; bool complete = true;
        if (diagnostics) {
            for (int pid : {1, int(getpid()), int(getppid())}) { uint64_t value = 0; ++scanned; if (!excluded.count(pid) && processClock(pid, value)) clocks[pid] = {value, nowNs()}; }
        } else {
            for (unsigned pid = 1; pid <= limit; ++pid) {
                if ((pid & 1023) == 0 && (!alive() || nowNs() - begin > 1000000000ULL)) { complete = false; break; }
                ++scanned; uint64_t value = 0;
                if (excluded.count(int(pid))) continue;
                if (processClock(int(pid), value)) clocks[int(pid)] = {value, nowNs()};
            }
        }
        for (int pid : previousCgroupCandidates) {
            if (excluded.count(pid) || clocks.count(pid)) continue;
            uint64_t value = 0;
            if (processClock(pid, value)) clocks[pid] = {value, nowNs()};
        }
        const bool eventRangeComplete = complete && !diagnostics;
        const auto recordExit = [&](int pid, const Previous& observation, const PidfdPollResult& state) {
            const char* evidence = pidfdExitEvidence(state);
            if (observation.pidfd < 0 || !evidence) return;
            processEvents.add("EXITED", pid, heldIdentity(pid, observation.epoch), evidence, state.revents);
            observedPids.erase(pid);
        };
        for (auto it = previous.begin(); it != previous.end();) {
            if (excluded.count(it->first)) {
                if (it->second.pidfd >= 0) close(it->second.pidfd);
                it = previous.erase(it); continue;
            }
            const PidfdPollResult state = it->second.pidfd >= 0 ? pollPidfd(it->second.pidfd) : PidfdPollResult{};
            if (it->second.pidfd >= 0 && state.rc != 0) {
                recordExit(it->first, it->second, state); // only POLLIN/HUP produces an event
                close(it->second.pidfd); it = previous.erase(it); continue;
            }
            if (!clocks.count(it->first)) {
                if (it->second.pidfd >= 0) {
                    // Keep the live identity for future exit evidence, but discard the CPU baseline.
                    it->second.hasCpuBaseline = false; ++it;
                } else if (previousCgroupCandidates.count(it->first)) {
                    it->second.hasCpuBaseline = false; ++it;
                } else it = previous.erase(it);
            } else ++it;
        }
        std::vector<Process> rows;
        std::map<int, CpuSample> signalReadings;
        for (const auto& entry : clocks) {
            int pid = entry.first; auto found = previous.find(pid); Process p; p.pid = pid;
            uint64_t currentCpu = entry.second.first, currentTime = entry.second.second;
            if (found != previous.end() && found->second.hasCpuBaseline
                && entry.second.first >= found->second.cpu && entry.second.second > found->second.time) {
                p.cpu = double(entry.second.first - found->second.cpu) * 100.0 / double(entry.second.second - found->second.time);
                p.cpuWindowStartNs = found->second.time;
            } else if (found != previous.end() && found->second.hasCpuBaseline) {
                if (found->second.pidfd >= 0) {
                    const PidfdPollResult state = pollPidfd(found->second.pidfd);
                    recordExit(pid, found->second, state);
                    close(found->second.pidfd);
                }
                previous.erase(found); found = previous.end();
            }
            if (found == previous.end()) {
                Previous observation; observation.epoch = ++epoch;
                if (caps.pidfd) observation.pidfd = openPidfd(pid);
                // The discovery clock may predate PID reuse. Bind a fresh baseline to the held pidfd.
                if (observation.pidfd >= 0) {
                    const PidfdPollResult before = pollPidfd(observation.pidfd);
                    const bool clockRead = before.rc == 0 && processClock(pid, currentCpu);
                    const PidfdPollResult after = before.rc == 0 ? pollPidfd(observation.pidfd) : before;
                    if (before.rc != 0 || !clockRead || after.rc != 0) {
                        // Do not mark an already-dead/zombie PID as a live observation; reuse can follow.
                        if (!pidfdExitEvidence(before) && !pidfdExitEvidence(after)) observedPids.insert(pid);
                        close(observation.pidfd); continue;
                    }
                    currentTime = nowNs();
                    if (canReportAppearance(sample, previousRangeComplete, eventRangeComplete, observedPids.count(pid) != 0))
                        processEvents.add("APPEARED", pid, heldIdentity(pid, observation.epoch), "new_pidfd_after_baseline");
                }
                found = previous.emplace(pid, observation).first;
            }
            observedPids.insert(pid);
            p.cpuWindowEndNs = currentTime;
            found->second.cpu = currentCpu; found->second.time = currentTime;
            found->second.hasCpuBaseline = true;
            p.identityVerified = found->second.pidfd >= 0;
            p.identitySource = p.identityVerified ? "held_pidfd" : "unverified";
            p.identityToken = p.identityVerified ? heldIdentity(pid, found->second.epoch)
                : "unverified:" + std::to_string(pid) + ":" + std::to_string(nowNs());
            p.probeState = p.cpu < 0 ? "cpu_baseline" : "deferred_for_audit_budget";
            signalReadings.emplace(pid, cpuSample(p));
            if ((sample == 0 || p.cpu >= 0.05 || diagnostics) && pid != getpid()) rows.push_back(std::move(p));
        }
        const auto cpuOrder = [](const Process& a, const Process& b) {
            if (a.cpu != b.cpu) return a.cpu > b.cpu;
            return a.pid < b.pid;
        };
        std::sort(rows.begin(), rows.end(), cpuOrder);
        unsigned metadataProbes = 0;
        std::vector<EnvironmentObservation> environmentObservations;
        // Probe the highest CPU candidates before the broad cgroup /proc checks,
        // so their AVC evidence gets first access to the finite kernel audit budget.
        // Baseline rows never generate target metadata denials.
        for (auto& p : rows) {
            if ((!diagnostics && p.cpu < 0.05) || metadataProbes >= 8) continue;
            auto observation = previous.find(p.pid);
            if (observation == previous.end()) continue;
            if (observation->second.pidfd >= 0 && !pidfdLive(observation->second.pidfd)) continue;
            inspect(p, observation->second, caps);
            environmentObservations.push_back(environmentObservation(p));
            if (p.uid == int(geteuid())) signalReadings.erase(p.pid);
            else signalReadings[p.pid] = cpuSample(p);
            ++metadataProbes;
        }
        std::map<int, cgroup_watch::Held> cgroupHeld;
        for (const auto& entry : previous) {
            const auto& value = entry.second;
            const std::string identity = value.pidfd >= 0 ? heldIdentity(entry.first, value.epoch)
                : "proc_starttime:" + std::to_string(entry.first) + ":" + std::to_string(value.epoch);
            cgroupHeld.emplace(entry.first, cgroup_watch::Held{value.pidfd, value.start, identity, value.startKnown});
        }
        cgroup_watch::Result cgroupScan = cgroupScanner.run(excluded, cgroupHeld, sample, !diagnostics);
        std::set<int> currentCgroupCandidates;
        std::map<int, size_t> rowIndex;
        for (size_t i = 0; i < rows.size(); ++i) rowIndex[rows[i].pid] = i;
        for (auto& entry : cgroupScan.processes) {
            const int pid = entry.first;
            auto& evidence = entry.second;
            const bool missing = evidence.check.state == "MISSING";
            const bool retain = missing || previousCgroupCandidates.count(pid);
            if (missing) currentCgroupCandidates.insert(pid);
            auto row = rowIndex.find(pid);
            if (row == rowIndex.end() && !retain) continue;
            if (row == rowIndex.end()) {
                Process added; added.pid = pid; added.probeState = "cgroup_named_path_observation";
                const auto signal = signalReadings.find(pid);
                if (signal != signalReadings.end()) {
                    added.cpu = signal->second.cpu; added.cpuWindowStartNs = signal->second.beginNs;
                    added.cpuWindowEndNs = signal->second.endNs;
                    added.identityVerified = signal->second.identityVerified; added.identityToken = signal->second.identityToken;
                } else {
                    const auto observation = previous.find(pid);
                    if (observation != previous.end()) {
                        added.identitySource = observation->second.pidfd >= 0 ? "held_pidfd" : "proc_starttime";
                        added.identityToken = added.identitySource + ":" + std::to_string(pid) + ":" + std::to_string(observation->second.epoch);
                        added.identityVerified = observation->second.pidfd >= 0;
                    }
                }
                rowIndex[pid] = rows.size(); rows.push_back(std::move(added)); row = rowIndex.find(pid);
            }
            Process& p = rows[row->second];
            p.cgroupCheck = evidence.check;
            auto priorObservation = previous.find(pid);
            if (priorObservation != previous.end() && priorObservation->second.pidfd < 0
                && priorObservation->second.startKnown && evidence.before.parsed && evidence.after.parsed
                && evidence.before.start == evidence.after.start && priorObservation->second.start != evidence.after.start) {
                priorObservation->second.start = evidence.after.start; priorObservation->second.epoch = ++epoch;
                priorObservation->second.hasCpuBaseline = false; p.cpu = -1; signalReadings.erase(pid);
                p.identitySource = "proc_starttime";
                p.identityToken = p.identitySource + ":" + std::to_string(pid) + ":" + std::to_string(priorObservation->second.epoch);
                p.cgroupCheck.state = "UNKNOWN"; p.cgroupCheck.stableIdentity = false;
                p.cgroupCheck.reason = "proc_identity_replaced"; p.cgroupCheck.identityToken = p.identityToken;
                currentCgroupCandidates.erase(pid);
                continue;
            }
            if (evidence.check.stableIdentity && evidence.check.nonZombie) {
                auto observation = previous.find(pid);
                if (observation == previous.end() || observation->second.pidfd < 0
                    || evidence.check.identityToken != heldIdentity(pid, observation->second.epoch)) {
                    p.cgroupCheck.state = "UNKNOWN"; p.cgroupCheck.stableIdentity = false;
                    p.cgroupCheck.reason = "held_identity_changed";
                    currentCgroupCandidates.erase(pid); continue;
                }
                if (evidence.after.parsed) {
                    if (observation->second.startKnown && observation->second.start != evidence.after.start) {
                        p.cgroupCheck.state = "UNKNOWN"; p.cgroupCheck.stableIdentity = false;
                        p.cgroupCheck.reason = "held_identity_starttime_changed";
                        currentCgroupCandidates.erase(pid); continue;
                    }
                    observation->second.start = evidence.after.start; observation->second.startKnown = true;
                    p.start = evidence.after.start; p.procReadable = true; p.name = evidence.after.name;
                }
                p.identityVerified = true; p.identitySource = "held_pidfd";
                p.identityToken = heldIdentity(pid, observation->second.epoch);
                if (evidence.after.uid >= 0 && p.uid < 0) {
                    p.uid = evidence.after.uid; p.uidSource = "proc_pid_directory_owner_effective_uid";
                }
                if (signalReadings.count(pid)) signalReadings[pid] = cpuSample(p);
                if (p.uid == int(geteuid())) signalReadings.erase(pid);
            }
            p.cgroupCheck.identityToken = p.identityToken;
        }
        // Keep current CPU first when the bounded evidence output is full. Java evaluates
        // all evidence rows before applying its separate display capacity.
        std::sort(rows.begin(), rows.end(), cpuOrder);
        const size_t matched = rows.size();
        if (rows.size() > candidateLimit) rows.resize(candidateLimit);
        environmentObservations.erase(std::remove_if(environmentObservations.begin(), environmentObservations.end(),
            [&](const EnvironmentObservation& p) {
                const auto found = previous.find(p.pid);
                return p.pidfdOpen && (found == previous.end() || found->second.pidfd < 0 || !pidfdLive(found->second.pidfd));
            }), environmentObservations.end());
        environment.update(sample, environmentObservations);
        for (auto& p : rows) {
            p.pidfdProcMismatchConsecutive = environment.consecutive(p.pid, p.identityToken);
            p.pidfdProcMismatch = p.pidfdProcMismatchConsecutive >= 2;
            p.cgroupCheck.sampleIndex = sample;
            const auto sampled = cgroupScan.processes.find(p.pid);
            const auto held = previous.find(p.pid);
            if (p.cgroupCheck.stableIdentity && (sampled == cgroupScan.processes.end()
                || !p.identityVerified || held == previous.end() || held->second.pidfd < 0
                || !pidfdLive(held->second.pidfd) || p.identityToken != sampled->second.check.identityToken
                || (p.procReadable && sampled->second.after.parsed && p.start != sampled->second.after.start))) {
                p.cgroupCheck.state = "UNKNOWN"; p.cgroupCheck.stableIdentity = false;
                p.cgroupCheck.reason = "identity_changed_after_cgroup_scan";
            }
            p.cgroupCheck.identityToken = p.identityToken;
            if (p.cgroupCheck.state == "UNKNOWN" && p.cgroupCheck.reason == "not_observed")
                p.cgroupCheck.reason = cgroupScan.complete ? "not_in_held_pid_snapshot" : "cgroup_path_scan_incomplete";
        }
        rows.erase(std::remove_if(rows.begin(), rows.end(), [&](const Process& p) {
            const auto found = previous.find(p.pid);
            return p.uid == int(geteuid()) || found == previous.end()
                || (found->second.pidfd >= 0 && !pidfdLive(found->second.pidfd));
        }), rows.end());
        // Drop exits and unavailable epochs after metadata work; never turn their absence into zero.
        for (auto it = signalReadings.begin(); it != signalReadings.end();) {
            const auto found = previous.find(it->first);
            if (excluded.count(it->first) || found == previous.end()
                || (found->second.pidfd >= 0 && !pidfdLive(found->second.pidfd))) it = signalReadings.erase(it);
            else ++it;
        }
        std::set<int> retainedCgroupCandidates;
        for (const auto& p : rows) if (p.cgroupCheck.state == "MISSING") retainedCgroupCandidates.insert(p.pid);
        cpuSignals.update(signalReadings, retainedCgroupCandidates);
        previousCgroupCandidates = std::move(retainedCgroupCandidates);
        std::sort(rows.begin(), rows.end(), cpuOrder);
        unsigned unknownUid = 0; for (const auto& p : rows) if (p.uid < 0) ++unknownUid;
        std::ostringstream out; out << std::boolalpha << std::fixed << std::setprecision(3);
        out << "{\"schema\":1,\"mode\":\"unprivileged\",\"collectorUid\":" << geteuid() << ",\"root\":" << (geteuid() == 0)
            << ",\"collectorPid\":" << getpid() << ",\"timestampEpochMs\":" << nowNs(CLOCK_REALTIME) / 1000000ULL
            << ",\"elapsedMs\":" << (begin - session) / 1000000ULL << ",\"intervalMs\":" << interval << ",\"sampleIndex\":" << sample
            << ",\"collectionMs\":" << (nowNs() - begin) / 1000000ULL << ",\"cpuCores\":" << std::max(1L, sysconf(_SC_NPROCESSORS_ONLN))
            << ",\"scannedProcesses\":" << scanned << ",\"liveClockProcesses\":" << clocks.size() << ",\"deniedProcesses\":" << unknownUid
            << ",\"scanComplete\":" << (complete && !diagnostics && caps.pidMaxReadable && limit >= caps.pidMax && matched <= candidateLimit)
            << ",\"capabilities\":{\"selfProcessCpuClock\":" << caps.selfClock << ",\"selfProcessCpuClockErrno\":" << caps.selfClockErrno
            << ",\"externalProcessCpuClock\":" << caps.externalClock << ",\"externalProcessCpuClockErrno\":" << caps.externalClockErrno
            << ",\"pidfdOpen\":" << caps.pidfd << ",\"pidfdOpenErrno\":" << caps.pidfdErrno
            << ",\"pidfdCredentials\":" << caps.pidfdUid << ",\"pidfdCredentialsErrno\":" << caps.pidfdInfoErrno
            << ",\"collectorSelinux\":" << q(caps.selinux) << ",\"pidMax\":" << (caps.pidMaxReadable ? std::to_string(caps.pidMax) : "null")
            << ",\"pidMaxReadable\":" << caps.pidMaxReadable << ",\"pidMaxErrno\":" << caps.pidMaxErrno << ",\"pidUpperBound\":" << limit
            << ",\"globalGpuMemstore\":" << globalGpu.supported()
            << ",\"metadataProbeLimit\":8,\"metadataProbeOrder\":\"descending_process_cpu\",\"metadataProbeCount\":" << metadataProbes
            << ",\"uidAttribution\":\"readable status, exact proc PID directory owner, or PIDFD_GET_INFO; otherwise unknown\""
            << ",\"gpuAttribution\":\"only readable target GPU descriptors; global activity is never assigned to a PID\"}"
            << ",\"matchedCandidates\":" << matched << ",\"returnedCandidates\":" << rows.size() << ",\"candidateLimit\":" << candidateLimit << ",\"candidatesTruncated\":" << (matched > candidateLimit)
            << ",\"cpuSampleCount\":" << cpuSignals.samples.size() << ",\"cpuSamplesTruncated\":" << cpuSignals.truncated
            << ",\"cpuSampleEligibleCount\":" << cpuSignals.eligibleCount << ",\"cpuSampleCapacityOmissions\":" << cpuSignals.capacityOmissions
            << ",\"cpuSampleCapacityEvictions\":" << cpuSignals.capacityEvictions << ",\"cpuSampleCapacity\":" << CpuSignalCache::capacity
            << ",\"cpuSampleIdleRetentionMs\":" << CpuSignalCache::retentionNs / 1000000ULL
            << ",\"cpuSampleCoverage\":\"bounded observed-active non-self PIDs; measured zero retained for 120 seconds after activity unless capacity-evicted; missing/invalid clocks, exits and identity changes are removed, never zero-filled; current CPU and discounted recent peaks determine admission\""
            << ",\"environmentAnomaly\":" << environment.anomaly << ",\"environmentCheckSupported\":" << caps.pidfd
            << ",\"environmentCheckedPidCount\":" << environment.attempted << ",\"environmentLivePidfdCheckCount\":" << environment.livePidfdChecks
            << ",\"environmentCheckCoverage\":\"Reuses at most 8 highest-CPU metadata probes per sample; no additional proc accesses; idle and unselected PIDs are not covered; no observed conflict is not a clean-environment guarantee\""
            << ",\"environmentCheckCondition\":\"Only a held pidfd alive before and after stat(/proc/PID), with ENOENT or ESRCH in at least 2 consecutive samples of the same identityToken, confirms an existence-view inconsistency. EACCES/EPERM, exit, unsupported pidfd, recovery, identity changes and skipped samples do not confirm it. CPU-clock success is never substituted for pidfd evidence\""
            << ",\"processEventCount\":" << processEvents.size() << ",\"processEventsTruncated\":" << processEvents.truncated
            << ",\"processEventLimit\":" << ProcessEventBatch::capacity << ",\"processEventPreviousRangeComplete\":" << previousRangeComplete
            << ",\"processEventCurrentRangeComplete\":" << eventRangeComplete
            << ",\"processEventCoverage\":\"APPEARED is a newly observed live pidfd after baseline and two complete requested-range scans, not proof of creation time; previously observed PIDs are not re-announced after uncertain gaps. EXITED requires actual pidfd POLLIN/HUP, never a missing CPU clock or poll error. No root filter is applied to events\""
            << ",\"errors\":[]"
            << ",\"environmentChecks\":";
        environment.json(out);
        out << ",\"cgroupScan\":"; cgroupScan.json(out);
        out << ",\"processEvents\":";
        processEvents.json(out);
        out << ",\"cpuSamples\":";
        cpuSignals.json(out);
        out << ",\"globalGpu\":";
        globalGpu.json(out);
        out << ",\"processes\":[";
        for (size_t i = 0; i < rows.size(); ++i) { if (i) out << ','; processJson(out, rows[i]); } out << "]}";
        std::string json = out.str();
        previousRangeComplete = eventRangeComplete;
        if (fwrite(json.data(), 1, json.size(), stdout) != json.size() || fputc('\n', stdout) == EOF || fflush(stdout)) break;
        if (samples && sample + 1 >= samples) break;
        nextAt += uint64_t(interval) * 1000000ULL;
        if (nextAt < nowNs()) nextAt = nowNs() + uint64_t(interval) * 1000000ULL;
        sleepUntil(nextAt);
    }
    for (const auto& entry : previous) if (entry.second.pidfd >= 0) close(entry.second.pidfd);
    return 0;
}

