#include "../native/metadata_schedule.h"
#include <cassert>
#include <iostream>
#include <limits>

using metadata_schedule::Candidate;
using metadata_schedule::Schedule;
int main() {
    Schedule scheduler;
    std::vector<Candidate> input;
    for (int pid = 1; pid <= 40; ++pid) input.push_back({pid, uint64_t(pid), pid <= 8 ? 90.0 : pid % 2 ? -1.0 : 0.0});
    std::set<int> consecutiveCoverage, previous;
    for (int round = 0; round < 20; ++round) {
        const auto selection = scheduler.select(input);
        assert(selection.size() == Schedule::limit);
        std::set<int> unique(selection.begin(), selection.end());
        assert(unique.size() == selection.size());
        // CPU priority is retained even when the rotating group is entirely idle.
        for (int pid = 1; pid <= 4; ++pid) assert(unique.count(pid));
        for (int pid : unique) if (previous.count(pid)) consecutiveCoverage.insert(pid);
        previous = unique;
    }
    assert(consecutiveCoverage.size() == 40); // zero and unknown CPU are both covered twice

    Schedule small;
    assert(small.select({}).empty());
    for (int i = 0; i < 4; ++i) {
        auto selected = small.select({{1, 1, 0}, {1, 1, 0}, {2, 2, std::numeric_limits<double>::quiet_NaN()}});
        assert(selected.size() == 2 && std::set<int>(selected.begin(), selected.end()).size() == 2);
    }
    // An exited cohort cannot introduce a vanished PID; reused IDs use current input.
    Schedule churn;
    churn.select({{1, 1, 0}, {2, 2, 0}, {3, 3, 0}, {4, 4, 0}, {5, 5, 0}});
    auto changed = churn.select({{1, 99, 0}, {5, 5, -1}, {6, 6, 0}});
    assert((std::set<int>(changed.begin(), changed.end()) == std::set<int>{1, 5, 6}));
    assert(churn.select({}).empty());
    std::cout << "MetadataSchedule: stable-set coverage, priority, duplicate, unknown CPU and churn checks passed.\n";
}
