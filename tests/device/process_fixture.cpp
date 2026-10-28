// External, bounded test workload. Not linked into the product APK.
#include <sys/prctl.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace {
volatile sig_atomic_t stopped = 0;
volatile uint64_t work = 1;
void stop(int) { stopped = 1; }
uint64_t ns(clockid_t clock = CLOCK_MONOTONIC) {
    timespec t{}; clock_gettime(clock, &t);
    return uint64_t(t.tv_sec) * 1000000000ULL + uint64_t(t.tv_nsec);
}
std::string read(const std::string& path) {
    std::ifstream file(path); std::ostringstream out; out << file.rdbuf(); return out.str();
}
std::string quote(const std::string& s) {
    std::string out = "\"";
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') { out += '\\'; out += char(c); }
        else if (c >= 32 && c < 127) out += char(c);
        else { char b[7]; std::snprintf(b, sizeof(b), "\\u%04x", unsigned(c)); out += b; }
    }
    return out + '"';
}
void sleepTo(uint64_t until) {
    while (!stopped && ns() < until) {
        uint64_t delay = std::min<uint64_t>(until - ns(), 10000000ULL);
        timespec t{0, long(delay)}; nanosleep(&t, nullptr);
    }
}
std::string membership() {
    std::ostringstream out; out << '['; bool first = true;
    for (const char* mount : {"/sys/fs/cgroup", "/dev/blkio", "/dev/cpuctl", "/dev/cpuset", "/dev/memcg", "/dev/freezer"}) {
        // These normal fixtures inherit their shell parent's root groups on this device;
        // record only a direct root-file check, never claim complete tree coverage here.
        const std::string path = std::string(mount) + "/cgroup.procs";
        std::ifstream file(path); int pid = 0; bool contains = false;
        const bool opened = file.good();
        while (file >> pid) contains = contains || pid == getpid();
        if (!first) out << ','; first = false;
        out << "{\"path\":" << quote(path) << ",\"readable\":" << (opened ? "true" : "false")
            << ",\"containsSelf\":" << (contains ? "true" : "false") << '}';
    }
    return out.str() + ']';
}
void emit(const char* event, int phase, int demand) {
    std::printf("{\"event\":%s,\"pid\":%d,\"uid\":%d,\"euid\":%d,\"phase\":%d,\"demandPercent\":%d,"
                "\"monotonicNs\":%llu,\"cpuNs\":%llu,\"stat\":%s,\"selinux\":%s,\"cgroup\":%s,\"rootFileMembership\":%s}\n",
                quote(event).c_str(), int(getpid()), int(getuid()), int(geteuid()), phase, demand,
                static_cast<unsigned long long>(ns()), static_cast<unsigned long long>(ns(CLOCK_PROCESS_CPUTIME_ID)),
                quote(read("/proc/self/stat")).c_str(), quote(read("/proc/self/attr/current")).c_str(),
                quote(read("/proc/self/cgroup")).c_str(), membership().c_str());
    std::fflush(stdout);
}
}

int main(int argc, char** argv) {
    const bool low = argc > 1 && std::string(argv[1]) == "low";
    prctl(PR_SET_NAME, low ? "gpu_test_low" : "gpu_test_high", 0, 0, 0);
    signal(SIGTERM, stop); signal(SIGINT, stop);
    const std::vector<int> seconds = low ? std::vector<int>{36} : std::vector<int>{12, 10, 10};
    const std::vector<int> demand = low ? std::vector<int>{12} : std::vector<int>{60, 0, 35};
    emit("started", -1, 0);
    for (size_t phase = 0; phase < seconds.size() && !stopped; ++phase) {
        emit("phase", int(phase), demand[phase]);
        const uint64_t end = ns() + uint64_t(seconds[phase]) * 1000000000ULL;
        if (demand[phase] == 0) {
            // One blocking sleep produces a measured-zero window; polling would itself use CPU.
            timespec deadline{time_t(end / 1000000000ULL), long(end % 1000000000ULL)};
            while (!stopped && clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, nullptr) == EINTR) {}
            continue;
        }
        while (!stopped && ns() < end) {
            const uint64_t began = ns(), period = 50000000ULL;
            const uint64_t busyUntil = began + period * unsigned(demand[phase]) / 100;
            while (!stopped && ns() < busyUntil) work = work * 6364136223846793005ULL + 1;
            sleepTo(std::min(end, began + period));
        }
    }
    emit("exiting", int(seconds.size()), 0);
    return 0;
}
