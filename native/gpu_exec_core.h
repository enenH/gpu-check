#pragma once
#include <algorithm>
#include <cstdint>
#include <vector>

namespace gpu_exec {
constexpr uint64_t kPollNs = 50000, kGateNs = 5000000, kCompletionNs = 50000000;
constexpr uint64_t kIdleNs = 500000000;
constexpr uint64_t kFrequencyPollNs = 1000000;
constexpr uint64_t kMaxFrequencyPollGapNs = 50000000;
constexpr uint32_t kMaxAdvance = 1U << 24;
struct Counters { uint32_t submitted = 0, retired = 0; };
struct Sample { uint32_t durationUs; bool completed; };
struct Result {
    int slot = 0;
    const char* reason = "not_started";
    uint64_t startedNs = 0, finishedNs = 0, cpuNs = 0;
    Counters first{}, last{};
    unsigned completed = 0, nonzero = 0, timeouts = 0, unfinished = 0;
    uint64_t sumUs = 0;
    uint32_t minUs = 0, maxUs = 0;
    bool valid = true;
    std::vector<Sample> samples;
    void add(uint32_t us, bool done) {
        samples.push_back({us, done});
        if (!done) { ++timeouts; return; }
        ++completed;
        if (us) {
            minUs = nonzero ? std::min(minUs, us) : us;
            maxUs = std::max(maxUs, us); sumUs += us; ++nonzero;
        }
    }
};

// A reset/wrap cannot establish context continuity; retain evidence but invalidate this window.
inline bool continuous(Counters before, Counters after) {
    return after.submitted >= before.submitted && after.retired >= before.retired
        && after.submitted - before.submitted <= kMaxAdvance
        && after.retired - before.retired <= kMaxAdvance;
}

struct FrequencySlot {
    int slot = 0;
    bool valid = true;
    const char* reason = "window_complete";
    uint64_t transitions = 0;
    Counters first{}, last{};
};
struct FrequencyWindow {
    uint64_t startedNs = 0, finishedNs = 0, maxPollGapNs = 0;
    bool fullWindow = false;
    const char* reason = "window_complete";
    std::vector<FrequencySlot> slots;
};

// One poll scans every supported user slot, including inactive slots. Count observed
// SOP changes, not the numerical advance of its driver-assigned sequence number.
// Reading the final endpoint includes transitions at the window boundary. Actual
// elapsed time is retained, so a late wakeup cannot inflate the reported rate.
template<class Reader, class Runtime>
FrequencyWindow measureFrequency(int firstSlot, int endSlot, uint64_t durationNs,
        Reader& reader, Runtime& runtime) {
    FrequencyWindow result;
    result.startedNs = runtime.now();
    const uint64_t deadline = result.startedNs + durationNs;
    uint64_t time = result.startedNs;
    bool uninterrupted = true;
    const auto invalidate = [&](const char* reason) {
        uninterrupted = false;
        result.reason = reason;
        for (auto& slot : result.slots) { slot.valid = false; slot.reason = reason; }
    };
    for (int id = firstSlot; id < endSlot; ++id) {
        FrequencySlot slot; slot.slot = id;
        slot.first = slot.last = reader.read(id);
        result.slots.push_back(slot);
    }
    if (!time || deadline <= time || firstSlot < 1 || endSlot <= firstSlot) invalidate("invalid_window");
    else {
        while (time < deadline) {
            if (runtime.cancelled()) { invalidate("cancelled"); break; }
            runtime.sleep(std::min(kFrequencyPollNs, deadline - time));
            const uint64_t next = runtime.now();
            if (!next || next < time) { invalidate("clock_error"); break; }
            result.maxPollGapNs = std::max(result.maxPollGapNs, next - time);
            time = next;
            if (runtime.cancelled()) { invalidate("cancelled"); break; }
            if (result.maxPollGapNs > kMaxFrequencyPollGapNs) { invalidate("sampling_gap"); break; }
            for (auto& slot : result.slots) {
                const Counters value = reader.read(slot.slot);
                if (!continuous(slot.last, value)) {
                    slot.valid = false; slot.reason = "counter_reset_or_wrap";
                }
                if (value.submitted != slot.last.submitted) ++slot.transitions;
                slot.last = value;
            }
        }
        result.fullWindow = uninterrupted && time >= deadline && !runtime.cancelled();
    }
    result.finishedNs = runtime.now();
    if (!result.finishedNs || result.finishedNs < time) {
        invalidate("clock_error"); result.fullWindow = false;
    }
    if (runtime.cancelled()) { invalidate("cancelled"); result.fullWindow = false; }
    return result;
}

// Reader supplies one slot. Runtime supplies monotonic time, cancellation and bounded sleeps.
// Keeping these inputs explicit permits deterministic tests of races, timeout and reset paths.
template<class Reader, class Runtime>
Result measure(int slot, unsigned requested, uint64_t deadline, Reader& reader, Runtime& runtime) {
    Result result; result.slot = slot; result.samples.reserve(requested);
    result.startedNs = runtime.now();
    result.first = result.last = reader.read();
    uint64_t previousTime = result.startedNs;
    const auto now = [&]() {
        const uint64_t value = runtime.now();
        if (!value || value < previousTime) { result.valid = false; result.reason = "clock_error"; }
        previousTime = value;
        return value;
    };
    const auto read = [&]() {
        const Counters value = reader.read();
        if (!continuous(result.last, value)) { result.valid = false; result.reason = "counter_reset_or_wrap"; }
        result.last = value;
        return value;
    };
    if (!result.startedNs) { result.valid = false; result.reason = "clock_error"; }
    else if (runtime.cancelled()) { result.valid = false; result.reason = "cancelled"; }
    else if (result.first.submitted < 100) result.reason = "inactive";
    else {
        uint32_t observedSubmitted = result.first.submitted;
        uint64_t nextEligible = result.startedNs, idleDeadline = result.startedNs + kIdleNs;
        result.reason = "window_complete";
        while (result.valid && result.samples.size() < requested) {
            if (runtime.cancelled()) { result.valid = false; result.reason = "cancelled"; break; }
            uint64_t time = now();
            if (!result.valid || time >= deadline) break;
            if (time >= idleDeadline) { result.reason = "activity_timeout"; break; }
            const Counters value = read();
            if (!result.valid) break;
            if (time < nextEligible || value.submitted == observedSubmitted) {
                runtime.sleep(std::min(kPollNs, deadline - time)); continue;
            }
            observedSubmitted = value.submitted;
            const uint32_t target = value.submitted;
            const uint64_t start = time, completionDeadline = start + kCompletionNs;
            nextEligible = start + kGateNs;
            bool done = value.retired >= target;
            while (!done && result.valid) {
                if (runtime.cancelled()) { result.valid = false; result.reason = "cancelled"; break; }
                time = now();
                if (!result.valid || time >= deadline || time >= completionDeadline) break;
                runtime.sleep(std::min(kPollNs, std::min(deadline, completionDeadline) - time));
                const Counters current = read();
                time = now();
                done = current.retired >= target;
            }
            if (!result.valid) break;
            time = now();
            if (!result.valid) break;
            if (time >= deadline && time < completionDeadline) { ++result.unfinished; break; }
            if (time >= completionDeadline) result.add(0, false);
            else if (done) result.add(uint32_t((time - start) / 1000), true);
            else { ++result.unfinished; break; }
            idleDeadline = time + kIdleNs;
        }
        if (result.valid && result.samples.size() == requested) result.reason = "sample_limit";
    }
    result.finishedNs = runtime.now();
    if (!result.finishedNs || result.finishedNs < previousTime) {
        result.valid = false; result.reason = "clock_error";
    }
    return result;
}
} // namespace gpu_exec
