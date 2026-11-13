#pragma once
#include <algorithm>
#include <cstdint>
#include <vector>

namespace gpu_sample {
// These are conservative data-quality bounds, not a measured GPU throughput limit.
// A plausible uint32 wrap requires both values to lie within the current allowed
// increment of the rollover boundary. Even that cannot prove a slot was not reused.
constexpr uint64_t kSlotMaxRatePerSecond = 1000000ULL;
constexpr uint64_t kSlotMaxIncrement = 1ULL << 24;
constexpr uint64_t kSlotMinAllowance = 1024ULL;
constexpr uint64_t kSlotMaxIntervalNs = 60000000000ULL;
inline uint64_t slotDeltaAllowance(uint64_t intervalNs) {
    if (!intervalNs || intervalNs > kSlotMaxIntervalNs) return 0;
    const uint64_t rateAllowance = (intervalNs * kSlotMaxRatePerSecond + 999999999ULL) / 1000000000ULL;
    return std::min(kSlotMaxIncrement, std::max(kSlotMinAllowance, rateAllowance));
}
inline int64_t comparableSlotDelta(uint32_t before, uint32_t after, bool previouslyPresent,
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

// Derive both the display and risk input from the same validated measurements.
struct Activity {
    unsigned comparableSlots = 0;
    unsigned advancedSlots = 0;
    bool known() const { return comparableSlots > 0; }
    bool active() const { return advancedSlots > 0; }
};
inline Activity summarize(const std::vector<int64_t>& deltas) {
    Activity result;
    for (int64_t delta : deltas) {
        if (delta >= 0) ++result.comparableSlots;
        if (delta > 0) ++result.advancedSlots;
    }
    return result;
}
} // namespace gpu_sample
