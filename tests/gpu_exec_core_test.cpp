#include "../native/gpu_exec_core.h"
#include <cassert>
#include <cstring>
#include <functional>
#include <iostream>

struct Clock {
    uint64_t time = 1000000000, cancelAt = UINT64_MAX;
    uint64_t now() { return time; }
    bool cancelled() { return time >= cancelAt; }
    void sleep(uint64_t ns) { time += ns; }
};
struct Reader {
    Clock& clock;
    std::function<gpu_exec::Counters(uint64_t)> source;
    gpu_exec::Counters read() { return source(clock.time - 1000000000); }
};
struct FrequencyReader {
    Clock& clock;
    std::function<gpu_exec::Counters(int, uint64_t)> source;
    gpu_exec::Counters read(int slot) { return source(slot, clock.time - 1000000000); }
};
int main() {
    unsigned checks = 0;
    const auto periodic = [](uint64_t t) {
        return gpu_exec::Counters{100 + uint32_t(t / 10000000),
            100 + uint32_t(t < 200000 ? 0 : (t - 200000) / 10000000)};
    };
    {
        Clock clock; Reader reader{clock, periodic};
        auto r = gpu_exec::measure(1, 5, clock.time + 100000000, reader, clock);
        assert(r.valid && r.samples.size() == 5 && r.completed == 5 && r.nonzero == 5);
        assert(r.minUs == 200 && r.maxUs == 200 && r.sumUs == 1000); checks += 2;
    }
    {
        Clock clock; Reader reader{clock, [](uint64_t t) {
            uint32_t value = 100 + uint32_t(t / 10000000); return gpu_exec::Counters{value, value}; }};
        auto r = gpu_exec::measure(1, 5, clock.time + 100000000, reader, clock);
        assert(r.valid && r.completed == 5 && r.nonzero == 0 && r.sumUs == 0); ++checks;
    }
    {
        Clock clock; Reader reader{clock, [](uint64_t t) { return gpu_exec::Counters{100 + uint32_t(t / 1000000), 100}; }};
        auto r = gpu_exec::measure(1, 30, clock.time + 120000000, reader, clock);
        assert(r.valid && r.timeouts == 2 && r.samples.size() == 2 && r.unfinished == 1 && !r.completed); ++checks;
    }
    {
        Clock clock; Reader reader{clock, [](uint64_t) { return gpu_exec::Counters{100, 100}; }};
        auto r = gpu_exec::measure(1, 30, clock.time + 1000000000, reader, clock);
        assert(r.valid && r.samples.empty() && std::strcmp(r.reason, "activity_timeout") == 0);
        assert(r.finishedNs - r.startedNs == gpu_exec::kIdleNs); checks += 2;
    }
    {
        Clock clock; Reader reader{clock, [](uint64_t) { return gpu_exec::Counters{99, 99}; }};
        auto r = gpu_exec::measure(1, 30, clock.time + 100000000, reader, clock);
        assert(r.valid && std::strcmp(r.reason, "inactive") == 0 && r.samples.empty()); ++checks;
    }
    {
        Clock clock; Reader reader{clock, [periodic](uint64_t t) {
            return t < 20000000 ? periodic(t) : gpu_exec::Counters{0, 0}; }};
        auto r = gpu_exec::measure(1, 30, clock.time + 100000000, reader, clock);
        assert(!r.valid && std::strcmp(r.reason, "counter_reset_or_wrap") == 0); ++checks;
    }
    {
        Clock clock; Reader reader{clock, [](uint64_t t) {
            uint32_t value = UINT32_MAX - 2 + uint32_t(t / 1000000); return gpu_exec::Counters{value, value}; }};
        auto r = gpu_exec::measure(1, 30, clock.time + 100000000, reader, clock);
        assert(!r.valid && std::strcmp(r.reason, "counter_reset_or_wrap") == 0); ++checks;
    }
    {
        Clock clock; clock.cancelAt = clock.time + 10000000; Reader reader{clock, periodic};
        auto r = gpu_exec::measure(1, 30, clock.time + 10000000000ULL, reader, clock);
        assert(!r.valid && std::strcmp(r.reason, "cancelled") == 0 && r.finishedNs <= clock.cancelAt + gpu_exec::kPollNs); ++checks;
    }
    {
        Clock clock; Reader reader{clock, periodic};
        auto r = gpu_exec::measure(1, 30, clock.time + 10100000, reader, clock);
        assert(r.valid && r.unfinished == 1 && r.samples.empty()); ++checks;
    }
    assert(!gpu_exec::continuous({100, 100}, {100 + gpu_exec::kMaxAdvance + 1, 100})); ++checks;

    const auto frequencySource = [](int slot, uint64_t t) {
        const uint64_t rate = slot == 1 ? 90 : slot == 2 ? 120 : 0;
        const uint32_t value = 100 + uint32_t(t * rate / 1000000000ULL) * 4096;
        return gpu_exec::Counters{value, value};
    };
    {
        Clock clock; FrequencyReader reader{clock, frequencySource};
        const auto r = gpu_exec::measureFrequency(1, 4, 500000000, reader, clock);
        assert(r.fullWindow && r.finishedNs - r.startedNs == 500000000 && r.slots.size() == 3);
        assert(r.slots[0].valid && r.slots[0].transitions == 45);
        assert(r.slots[1].valid && r.slots[1].transitions == 60);
        assert(r.slots[2].valid && r.slots[2].transitions == 0);
        assert(r.slots[1].last.submitted - r.slots[1].first.submitted == 60 * 4096);
        assert(r.maxPollGapNs == gpu_exec::kFrequencyPollNs); checks += 6;
    }
    {
        Clock clock; FrequencyReader reader{clock, [frequencySource](int slot, uint64_t t) {
            return slot == 1 && t >= 250000000 ? gpu_exec::Counters{0, 0} : frequencySource(slot, t); }};
        const auto r = gpu_exec::measureFrequency(1, 3, 500000000, reader, clock);
        assert(r.fullWindow && !r.slots[0].valid
                && std::strcmp(r.slots[0].reason, "counter_reset_or_wrap") == 0);
        assert(r.slots[1].valid && r.slots[1].transitions == 60); checks += 2;
    }
    {
        Clock clock; FrequencyReader reader{clock, [](int, uint64_t t) {
            const uint32_t value = UINT32_MAX - 2 + uint32_t(t / 1000000);
            return gpu_exec::Counters{value, value}; }};
        const auto r = gpu_exec::measureFrequency(1, 2, 100000000, reader, clock);
        assert(r.fullWindow && !r.slots[0].valid
                && std::strcmp(r.slots[0].reason, "counter_reset_or_wrap") == 0); ++checks;
    }
    {
        Clock clock; clock.cancelAt = clock.time + 7000000;
        FrequencyReader reader{clock, frequencySource};
        const auto r = gpu_exec::measureFrequency(1, 4, 500000000, reader, clock);
        assert(!r.fullWindow && std::strcmp(r.reason, "cancelled") == 0 && r.finishedNs == clock.cancelAt);
        assert(!r.slots[0].valid && !r.slots[1].valid && !r.slots[2].valid); checks += 2;
    }
    {
        Clock clock; FrequencyReader reader{clock, [](int, uint64_t t) {
            const uint32_t value = uint32_t(t / 10000000);
            return gpu_exec::Counters{value, value}; }};
        const auto r = gpu_exec::measureFrequency(1, 2, 10500000, reader, clock);
        assert(r.fullWindow && r.finishedNs - r.startedNs == 10500000);
        assert(r.slots[0].valid && r.slots[0].transitions == 1); checks += 2;
    }
    {
        struct SlowClock : Clock { void sleep(uint64_t ns) { time += ns + 2000000; } } clock;
        FrequencyReader reader{clock, frequencySource};
        const auto r = gpu_exec::measureFrequency(1, 3, 500000000, reader, clock);
        const double rate = double(r.slots[1].transitions) * 1e9 / double(r.finishedNs - r.startedNs);
        assert(r.fullWindow && r.finishedNs - r.startedNs > 500000000);
        assert(rate <= 120.0 && r.maxPollGapNs == 3000000); checks += 2;
    }
    {
        struct BackwardClock : Clock { void sleep(uint64_t) { --time; } } clock;
        FrequencyReader reader{clock, frequencySource};
        const auto r = gpu_exec::measureFrequency(1, 3, 500000000, reader, clock);
        assert(!r.fullWindow && !r.slots[0].valid && std::strcmp(r.reason, "clock_error") == 0); ++checks;
    }
    {
        struct StalledClock : Clock { void sleep(uint64_t ns) { time += ns + 50000000; } } clock;
        FrequencyReader reader{clock, frequencySource};
        const auto r = gpu_exec::measureFrequency(1, 3, 500000000, reader, clock);
        assert(!r.fullWindow && !r.slots[0].valid && !r.slots[1].valid
                && std::strcmp(r.reason, "sampling_gap") == 0);
        assert(r.maxPollGapNs == 51000000); checks += 2;
    }
    {
        Clock clock; FrequencyReader reader{clock, [](int slot, uint64_t t) {
            const uint32_t value = slot == 800 ? 100 + uint32_t(t * 120 / 1000000000ULL) : 0;
            return gpu_exec::Counters{value, value}; }};
        const auto r = gpu_exec::measureFrequency(1, 812, 500000000, reader, clock);
        assert(r.fullWindow && r.slots.size() == 811 && r.slots[799].slot == 800);
        assert(r.slots[799].valid && r.slots[799].transitions == 60); checks += 2;
    }
    std::cout << "PASS " << checks << " GPU sampling boundary assertions\n";
}
