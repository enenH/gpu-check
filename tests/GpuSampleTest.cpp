#include "../native/gpu_sample.h"
#include <cassert>
#include <iostream>

int main() {
    using namespace gpu_sample;
    constexpr uint64_t interval = 2000000000ULL;
    bool wrapped = false;
    // A newly visible, already busy context used to count as global advancement.
    auto appeared = comparableSlotDelta(0, 500, false, true, interval, wrapped);
    assert(appeared == -1 && !summarize({appeared}).active());
    // A forward discontinuity used to pass the independent unsigned subtraction.
    auto jump = comparableSlotDelta(100, 2000101, true, true, interval, wrapped);
    assert(jump == -1 && !summarize({jump}).active());
    auto reset = comparableSlotDelta(0x80000000U, 5, true, true, interval, wrapped);
    assert(reset == -1 && !wrapped && !summarize({reset}).active());
    auto expired = comparableSlotDelta(10, 20, true, true, kSlotMaxIntervalNs + 1, wrapped);
    assert(expired == -1 && !summarize({expired}).known());
    auto noTime = comparableSlotDelta(10, 20, true, true, 0, wrapped);
    assert(noTime == -1 && !summarize({noTime}).active());
    auto rollover = comparableSlotDelta(UINT32_MAX - 4, 3, true, true, interval, wrapped);
    assert(rollover == 8 && wrapped && summarize({rollover}).active());
    auto normal = comparableSlotDelta(10, 35, true, true, interval, wrapped);
    assert(normal == 25 && !wrapped);
    auto mixed = summarize({appeared, jump, reset, 0, normal});
    assert(mixed.known() && mixed.active() && mixed.comparableSlots == 2 && mixed.advancedSlots == 1);
    assert(!summarize({}).known() && !summarize({-1, -1}).known());
    assert(summarize({0, 0}).known() && !summarize({0, 0}).active());
    std::cout << "GpuSample: 10 regression scenarios passed.\n";
}
