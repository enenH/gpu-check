// Query only KGSL file descriptions already held by this App process.
#include <jni.h>
#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <vector>

namespace {
constexpr const char* kDevice = "/dev/kgsl-3d0";
constexpr unsigned long kReadTimestamp = 0xc00c0916UL;
constexpr uint64_t kBudgetNs = 100000000ULL;
constexpr size_t kMaxDescriptors = 4096, kMaxGpuDescriptors = 64;
struct ReadTimestamp { uint32_t context, type, timestamp; };
static_assert(sizeof(ReadTimestamp) == 12);

uint64_t nowNs() {
    timespec value{};
    return clock_gettime(CLOCK_MONOTONIC, &value) == 0
        ? uint64_t(value.tv_sec) * 1000000000ULL + uint64_t(value.tv_nsec) : 0;
}
bool kgslPath(int fd) {
    char path[64], target[PATH_MAX];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    const ssize_t length = readlink(path, target, sizeof(target) - 1);
    if (length < 0) return false;
    target[length] = '\0';
    return std::strcmp(target, kDevice) == 0;
}
struct HeldFd {
    int fd, original;
    HeldFd(int fd, int original) : fd(fd), original(original) {}
    HeldFd(const HeldFd&) = delete;
    HeldFd& operator=(const HeldFd&) = delete;
    HeldFd(HeldFd&& other) noexcept : fd(other.fd), original(other.original) { other.fd = -1; }
    ~HeldFd() { if (fd >= 0) close(fd); }
};
struct Ownership { int fd; uint32_t timestamp; };

std::string inspect(int first, int end) {
    const uint64_t started = nowNs();
    bool scanComplete = true, queryComplete = true, timedOut = false;
    int scanRaces = 0, rejected = 0, queryErrors = 0, queryCount = 0;
    std::set<int> errors;
    std::vector<int> descriptors;
    std::vector<HeldFd> handles;
    descriptors.reserve(kMaxDescriptors);
    handles.reserve(kMaxGpuDescriptors);
    std::map<int, Ownership> owned;
    const bool validRange = first >= 1 && end > first && end <= 4096;
    const auto expired = [&]() {
        const uint64_t now = nowNs();
        return started == 0 || now == 0 || now < started || now - started >= kBudgetNs;
    };
    struct stat device{};
    if (!validRange || stat(kDevice, &device) != 0 || !S_ISCHR(device.st_mode)) {
        scanComplete = false;
        errors.insert(validRange ? errno : EINVAL);
    } else {
        std::unique_ptr<DIR, int(*)(DIR*)> directory(opendir("/proc/self/fd"), closedir);
        if (!directory) { scanComplete = false; errors.insert(errno); }
        else {
            for (;;) {
                if (expired()) { timedOut = true; scanComplete = false; break; }
                errno = 0;
                dirent* entry = readdir(directory.get());
                if (!entry) {
                    if (errno) { scanComplete = false; errors.insert(errno); }
                    break;
                }
                if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;
                char* tail = nullptr;
                const long value = strtol(entry->d_name, &tail, 10);
                if (!tail || *tail || value < 0 || value > INT_MAX || value == dirfd(directory.get())) continue;
                if (descriptors.size() >= kMaxDescriptors) { scanComplete = false; errors.insert(EOVERFLOW); break; }
                descriptors.push_back(int(value));
            }
            directory.reset();
        }
        // Duplicate after enumeration so our temporary descriptors cannot enter the enumeration itself.
        for (int fd : descriptors) {
            // A duplicate can reuse the number of a descriptor closed since enumeration.
            if (std::any_of(handles.begin(), handles.end(), [fd](const HeldFd& held) { return held.fd == fd; })) continue;
            if (expired()) { timedOut = true; scanComplete = false; break; }
            errno = 0;
            if (!kgslPath(fd)) {
                if (errno) { ++scanRaces; scanComplete = false; errors.insert(errno); }
                continue;
            }
            if (handles.size() >= kMaxGpuDescriptors) { scanComplete = false; errors.insert(EOVERFLOW); break; }
            const int duplicate = fcntl(fd, F_DUPFD_CLOEXEC, 0);
            if (duplicate < 0) { scanComplete = false; errors.insert(errno); continue; }
            // Never reopen /proc/self/fd/N: that would create a different KGSL file-private owner.
            struct stat held{};
            if (!kgslPath(duplicate) || fstat(duplicate, &held) != 0
                    || !S_ISCHR(held.st_mode) || held.st_rdev != device.st_rdev) {
                close(duplicate); scanComplete = false; ++scanRaces; errors.insert(EBADF); continue;
            }
            handles.emplace_back(duplicate, fd);
        }
        // Different file descriptions for the same device inode must all be queried.
        for (int slot = first; slot < end && !timedOut; ++slot) {
            for (const HeldFd& handle : handles) {
                if (expired()) { timedOut = true; queryComplete = false; break; }
                ReadTimestamp request{uint32_t(slot), 2, 0};
                int result = -1, error = 0;
                for (int retry = 0; retry < 3; ++retry) {
                    errno = 0;
                    result = ioctl(handle.fd, kReadTimestamp, &request);
                    error = errno;
                    ++queryCount;
                    if (result == 0 || error != EINTR || expired()) break;
                }
                if (result == 0) {
                    // Timestamp zero is a valid success; ownership comes from the ioctl result.
                    owned.emplace(slot, Ownership{handle.original, request.timestamp});
                } else if (result < 0 && error == EINVAL) {
                    // Includes absent, detached and non-owner contexts; never label an owner PID from this.
                    ++rejected;
                } else {
                    queryComplete = false; ++queryErrors; errors.insert(error ? error : EIO);
                }
            }
        }
    }
    const uint64_t finished = nowNs();
    if (started == 0 || finished < started || finished - started >= kBudgetNs) {
        timedOut = true;
        queryComplete = false;
    }
    // With open GPU handles but no positive control, unsupported vendor ioctls cannot silently pass as a filter.
    const bool ownerCheckVerified = handles.empty() || !owned.empty();
    const bool complete = validRange && started > 0 && finished >= started
        && scanComplete && queryComplete && !timedOut && ownerCheckVerified;
    std::ostringstream out;
    out << std::boolalpha << "{\"method\":\"app_existing_fd_readtimestamp\",\"complete\":" << complete
        << ",\"pid\":" << getpid() << ",\"uid\":" << geteuid()
        << ",\"firstSlot\":" << first << ",\"endExclusive\":" << end
        << ",\"queryStartedMonotonicNs\":" << started << ",\"queryFinishedMonotonicNs\":" << finished
        << ",\"gpuFdCount\":" << handles.size() << ",\"queryCount\":" << queryCount
        << ",\"rejectedQueryCount\":" << rejected << ",\"queryErrorCount\":" << queryErrors
        << ",\"fdScanComplete\":" << scanComplete << ",\"queryComplete\":" << queryComplete
        << ",\"ownerCheckVerified\":" << ownerCheckVerified << ",\"scanRaceCount\":" << scanRaces
        << ",\"timedOut\":" << timedOut << ",\"slots\":[";
    bool comma = false;
    for (const auto& entry : owned) { if (comma) out << ','; comma = true; out << entry.first; }
    out << "],\"ownershipEvidence\":[";
    comma = false;
    for (const auto& entry : owned) {
        if (comma) out << ',';
        comma = true;
        out << "{\"slot\":" << entry.first << ",\"fd\":" << entry.second.fd
            << ",\"timestamp\":" << entry.second.timestamp << '}';
    }
    out << "],\"errnoValues\":[";
    comma = false;
    for (int error : errors) { if (comma) out << ','; comma = true; out << error; }
    out << "]}";
    return out.str();
}
} // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_gpucheck_app_SelfGpuSlots_nativeInspect(JNIEnv* env, jclass, jint first, jint end) {
    try {
        const std::string result = inspect(first, end);
        return env->NewStringUTF(result.c_str());
    } catch (...) {
        return env->NewStringUTF("{\"complete\":false,\"slots\":[],\"error\":\"native_owner_query_failed\"}");
    }
}
