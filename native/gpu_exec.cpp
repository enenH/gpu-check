#include "gpu_exec_core.h"
#include <jni.h>
#include <atomic>
#include <cerrno>
#include <condition_variable>
#include <fcntl.h>
#include <iomanip>
#include <mutex>
#include <pthread.h>
#include <set>
#include <sstream>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <thread>
#include <time.h>
#include <unistd.h>

namespace {
std::atomic<uint64_t> nextSession{1}, currentSession{0};
std::mutex measurementLock;
std::mutex frequencyLock;
uint64_t clockNs(clockid_t clock = CLOCK_MONOTONIC) {
    timespec value{};
    return clock_gettime(clock, &value) == 0
        ? uint64_t(value.tv_sec) * 1000000000ULL + uint64_t(value.tv_nsec) : 0;
}
struct Runtime {
    uint64_t session;
    uint64_t now() { return clockNs(); }
    bool cancelled() { return currentSession.load(std::memory_order_acquire) != session; }
    void sleep(uint64_t ns) {
        timespec delay{0, long(ns)};
        // EINTR returns to the sampling loop, which rechecks cancellation and the deadline.
        nanosleep(&delay, nullptr);
    }
};
struct Reader {
    volatile const uint8_t* data;
    gpu_exec::Counters read() {
        return {*reinterpret_cast<volatile const uint32_t*>(data),
                *reinterpret_cast<volatile const uint32_t*>(data + 8)};
    }
};
struct FrequencyReader {
    volatile const uint8_t* data;
    gpu_exec::Counters read(int slot) {
        Reader reader{data + size_t(slot) * 40};
        return reader.read();
    }
};
struct Mapping {
    int fd = -1;
    void* address = MAP_FAILED;
    size_t bytes = 0;
    ~Mapping() { if (address != MAP_FAILED) munmap(address, bytes); if (fd >= 0) close(fd); }
    bool open(int expectedCount, const char*& stage, int& error) {
        stage = "kgsl_open";
        fd = ::open("/dev/kgsl-3d0", O_RDWR | O_CLOEXEC);
        if (fd < 0) { error = errno; return false; }
        struct stat st{};
        stage = "kgsl_device";
        if (fstat(fd, &st)) { error = errno; return false; }
        if (!S_ISCHR(st.st_mode)) { error = ENODEV; return false; }
        struct Shadow { uint64_t offset, size; uint32_t flags, pad; } shadow{};
        struct Property { uint32_t type, pad; uint64_t value, size; };
        static_assert(sizeof(Shadow) == 24 && sizeof(Property) == 24);
        Property property{2, 0, uint64_t(uintptr_t(&shadow)), sizeof(shadow)};
        stage = "kgsl_shadow";
        if (ioctl(fd, 0xc0180902UL, &property)) { error = errno; return false; }
        stage = "layout_mismatch";
        if (shadow.size < 360 || shadow.size > 16 * 1024 * 1024ULL || shadow.offset > INT64_MAX
                || std::min<uint64_t>(shadow.size / 40, 4096) != uint64_t(expectedCount)) {
            error = EINVAL; return false;
        }
        bytes = size_t(shadow.size);
        stage = "kgsl_map";
        address = mmap(nullptr, bytes, PROT_READ, MAP_SHARED, fd, off_t(shadow.offset));
        if (address == MAP_FAILED) { error = errno; return false; }
        return true;
    }
};
std::string failure(const char* reason, int error = 0, const char* method = "gpuexec_multi") {
    std::ostringstream out;
    out << "{\"method\":\"" << method << "\",\"status\":\"unavailable\",\"reason\":\"" << reason
        << "\",\"errno\":" << error << ",\"slots\":[],\"scope\":\"device_global_unattributed\"}";
    return out.str();
}
std::string measure(uint64_t session, const std::vector<int>& slots, unsigned requested, unsigned window, int count) {
    if (!session || session != currentSession.load()) return failure("cancelled");
    if (slots.empty() || slots.size() > 16 || requested < 1 || requested > 1024 || window < 100
            || window > 10000 || count < 9 || count > 4096) return failure("invalid_arguments", EINVAL);
    std::set<int> seen;
    for (int id : slots) if (id < 1 || id >= std::min(count - 7, 256) || !seen.insert(id).second)
        return failure("invalid_slots", EINVAL);
    std::unique_lock<std::mutex> exclusive(measurementLock, std::try_to_lock);
    if (!exclusive.owns_lock()) return failure("sampler_busy");
    Mapping map; const char* stage = ""; int error = 0;
    if (!map.open(count, stage, error)) return failure(stage, error);
    std::vector<gpu_exec::Result> results(slots.size());
    std::vector<std::thread> threads;
    threads.reserve(slots.size());
    std::mutex gateMutex; std::condition_variable gate;
    bool ready = false;
    uint64_t started = 0, deadline = 0;
    for (size_t i = 0; i < slots.size(); ++i) {
        results[i].slot = slots[i];
        try {
            threads.emplace_back([&, i]() {
                pthread_setname_np(pthread_self(), "gpu-exec-slot");
                std::unique_lock<std::mutex> lock(gateMutex);
                gate.wait(lock, [&] { return ready; });
                lock.unlock();
                const uint64_t cpu = clockNs(CLOCK_THREAD_CPUTIME_ID);
                try {
                    Runtime runtime{session};
                    Reader reader{static_cast<volatile const uint8_t*>(map.address) + size_t(slots[i]) * 40};
                    results[i] = gpu_exec::measure(slots[i], requested, deadline, reader, runtime);
                } catch (...) { results[i].valid = false; results[i].reason = "worker_failed"; }
                const uint64_t finished = clockNs(CLOCK_THREAD_CPUTIME_ID);
                results[i].cpuNs = finished >= cpu ? finished - cpu : 0;
            });
        } catch (...) { results[i].valid = false; results[i].reason = "thread_failed"; }
    }
    {
        std::lock_guard<std::mutex> lock(gateMutex);
        started = clockNs(); deadline = started + uint64_t(window) * 1000000ULL; ready = true;
    }
    gate.notify_all();
    for (auto& thread : threads) thread.join();
    const uint64_t finished = clockNs();
    std::ostringstream out;
    out << std::boolalpha << std::fixed << std::setprecision(3)
        << "{\"method\":\"gpuexec_multi\",\"schema\":1,\"status\":\""
        << (session == currentSession.load() ? "complete" : "cancelled")
        << "\",\"scope\":\"device_global_unattributed\",\"pid\":" << getpid() << ",\"uid\":" << geteuid()
        << ",\"requestedSamples\":" << requested << ",\"windowMs\":" << window
        << ",\"slotCount\":" << count << ",\"workerCount\":" << threads.size()
        << ",\"startedMonotonicNs\":" << started << ",\"finishedMonotonicNs\":" << finished
        << ",\"pollIntervalUs\":50,\"eventGateUs\":5000,\"completionTimeoutUs\":50000"
        << ",\"measurement\":\"cpu_observed_counter_wait_us\",\"slots\":[";
    for (size_t i = 0; i < results.size(); ++i) {
        if (i) out << ',';
        const auto& r = results[i];
        const uint64_t elapsed = r.finishedNs >= r.startedNs ? r.finishedNs - r.startedNs : 0;
        out << "{\"slot\":" << r.slot << ",\"valid\":" << r.valid << ",\"reason\":\"" << r.reason
            << "\",\"startedMonotonicNs\":" << r.startedNs << ",\"finishedMonotonicNs\":" << r.finishedNs
            << ",\"cpuTimeNs\":" << r.cpuNs << ",\"measuredSamples\":" << r.samples.size()
            << ",\"completedSamples\":" << r.completed << ",\"nonzeroSamples\":" << r.nonzero
            << ",\"timedOutSamples\":" << r.timeouts << ",\"unfinishedSamples\":" << r.unfinished
            << ",\"observationsPerSecond\":" << (elapsed ? double(r.samples.size()) * 1e9 / double(elapsed) : 0)
            << ",\"submittedStart\":" << r.first.submitted << ",\"retiredStart\":" << r.first.retired
            << ",\"submittedEnd\":" << r.last.submitted << ",\"retiredEnd\":" << r.last.retired;
        if (r.nonzero) out << ",\"meanWaitUs\":" << double(r.sumUs) / r.nonzero
            << ",\"minWaitUs\":" << r.minUs << ",\"maxWaitUs\":" << r.maxUs;
        else out << ",\"meanWaitUs\":null,\"minWaitUs\":null,\"maxWaitUs\":null";
        out << ",\"durationsUs\":[";
        for (size_t j = 0; j < r.samples.size(); ++j) { if (j) out << ','; out << r.samples[j].durationUs; }
        out << "],\"sampleCompleted\":[";
        for (size_t j = 0; j < r.samples.size(); ++j) { if (j) out << ','; out << r.samples[j].completed; }
        out << "]}";
    }
    return out.str() + "]}";
}

std::string measureFrequency(uint64_t session, int count, unsigned window) {
    const auto unavailable = [](const char* reason, int error = 0) {
        return failure(reason, error, "gpu_slot_frequency");
    };
    if (!session || session != currentSession.load()) return unavailable("cancelled");
    if (count < 9 || count > 4096 || window < 100 || window > 10000)
        return unavailable("invalid_arguments", EINVAL);
    std::unique_lock<std::mutex> exclusive(frequencyLock, std::try_to_lock);
    if (!exclusive.owns_lock()) return unavailable("sampler_busy");
    Mapping map; const char* stage = ""; int error = 0;
    if (!map.open(count, stage, error)) return unavailable(stage, error);
    Runtime runtime{session};
    FrequencyReader reader{static_cast<volatile const uint8_t*>(map.address)};
    const uint64_t cpuStarted = clockNs(CLOCK_THREAD_CPUTIME_ID);
    const auto result = gpu_exec::measureFrequency(1, count - 7,
            uint64_t(window) * 1000000ULL, reader, runtime);
    const uint64_t cpuFinished = clockNs(CLOCK_THREAD_CPUTIME_ID);
    const uint64_t elapsed = result.finishedNs >= result.startedNs ? result.finishedNs - result.startedNs : 0;
    const bool cancelled = session != currentSession.load();
    const auto isIdle = [&](const gpu_exec::FrequencySlot& slot) {
        return slot.valid && result.fullWindow && !cancelled && slot.transitions == 0;
    };
    const size_t idleCount = size_t(std::count_if(result.slots.begin(), result.slots.end(), isIdle));
    std::ostringstream out;
    out << std::boolalpha << std::fixed << std::setprecision(6)
        << "{\"method\":\"gpu_slot_frequency\",\"schema\":1,\"status\":\""
        << (cancelled ? "cancelled" : result.fullWindow ? "complete" : "unavailable")
        << "\",\"reason\":\"" << result.reason
        << "\",\"scope\":\"device_global_unattributed\",\"pid\":" << getpid() << ",\"uid\":" << geteuid()
        << ",\"slotCount\":" << count << ",\"windowMs\":" << window
        << ",\"sparseSlots\":true,\"observedSlotCount\":" << result.slots.size()
        << ",\"idleSlotCount\":" << idleCount
        << ",\"startedMonotonicNs\":" << result.startedNs << ",\"finishedMonotonicNs\":" << result.finishedNs
        << ",\"fullWindow\":" << (result.fullWindow && !cancelled)
        << ",\"pollIntervalUs\":1000,\"maximumPollGapNs\":" << gpu_exec::kMaxFrequencyPollGapNs
        << ",\"maxPollGapNs\":" << result.maxPollGapNs
        << ",\"cpuTimeNs\":" << (cpuFinished >= cpuStarted ? cpuFinished - cpuStarted : 0)
        << ",\"measurement\":\"cpu_observed_sop_transitions_per_second\",\"slots\":[";
    bool emitted = false;
    for (const auto& slot : result.slots) {
        // An omitted slot was fully observed and stayed quiet. Invalid windows
        // and reset slots retain their rows rather than masquerading as idle.
        if (isIdle(slot)) continue;
        if (emitted) out << ',';
        emitted = true;
        out << "{\"slot\":" << slot.slot << ",\"valid\":" << (slot.valid && result.fullWindow && !cancelled)
            << ",\"reason\":\"" << slot.reason << "\",\"transitions\":" << slot.transitions
            << ",\"observationsPerSecond\":" << (elapsed ? double(slot.transitions) * 1e9 / double(elapsed) : 0)
            << ",\"startedMonotonicNs\":" << result.startedNs << ",\"finishedMonotonicNs\":" << result.finishedNs
            << ",\"submittedStart\":" << slot.first.submitted << ",\"retiredStart\":" << slot.first.retired
            << ",\"submittedEnd\":" << slot.last.submitted << ",\"retiredEnd\":" << slot.last.retired << '}';
    }
    return out.str() + "]}";
}
} // namespace

extern "C" JNIEXPORT jlong JNICALL Java_com_gpucheck_app_GpuExecSampler_nativeOpen(JNIEnv*, jclass) {
    const uint64_t session = nextSession.fetch_add(1);
    currentSession.store(session, std::memory_order_release);
    return jlong(session);
}
extern "C" JNIEXPORT void JNICALL Java_com_gpucheck_app_GpuExecSampler_nativeCancel(JNIEnv*, jclass, jlong id) {
    uint64_t expected = uint64_t(id);
    currentSession.compare_exchange_strong(expected, 0);
}
extern "C" JNIEXPORT jstring JNICALL Java_com_gpucheck_app_GpuExecSampler_nativeMeasure(
        JNIEnv* env, jclass, jlong id, jintArray input, jint requested, jint window, jint count) {
    try {
        if (!input || env->GetArrayLength(input) < 1 || env->GetArrayLength(input) > 16)
            return env->NewStringUTF(failure("invalid_slots", EINVAL).c_str());
        std::vector<jint> values(size_t(env->GetArrayLength(input)));
        env->GetIntArrayRegion(input, 0, jsize(values.size()), values.data());
        if (env->ExceptionCheck()) return nullptr;
        const std::vector<int> slots(values.begin(), values.end());
        return env->NewStringUTF(measure(uint64_t(id), slots, unsigned(requested), unsigned(window), count).c_str());
    } catch (...) { return env->NewStringUTF(failure("native_failed").c_str()); }
}

extern "C" JNIEXPORT jstring JNICALL Java_com_gpucheck_app_GpuExecSampler_nativeMeasureFrequency(
        JNIEnv* env, jclass, jlong id, jint count, jint window) {
    try {
        return env->NewStringUTF(measureFrequency(uint64_t(id), count, unsigned(window)).c_str());
    } catch (...) { return env->NewStringUTF(failure("native_failed", 0, "gpu_slot_frequency").c_str()); }
}
