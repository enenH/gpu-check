#pragma once

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <map>
#include <set>
#include <vector>

namespace metadata_schedule {
struct Candidate { int pid; uint64_t epoch; double cpu; };

// Four rotating slots prevent starvation; repeat each cohort in the next
// snapshot so two-observation consistency checks also cover idle processes.
// Remaining slots favour current CPU activity. No extra target queries.
class Schedule {
    int cursor = 0;
    bool repeat = false;
    std::vector<Candidate> cohort;
public:
    static constexpr unsigned limit = 8, fairSlots = 4;
    std::vector<int> select(const std::vector<Candidate>& input) {
        std::map<int, Candidate> candidates;
        for (const auto& c : input) if (c.pid > 0) candidates.emplace(c.pid, c);
        std::vector<Candidate> current;
        std::set<int> selected;
        if (repeat) for (const auto& c : cohort) {
            const auto found = candidates.find(c.pid);
            if (found != candidates.end() && found->second.epoch == c.epoch) {
                current.push_back(found->second); selected.insert(c.pid);
            }
        }
        // Fill gaps caused by exit/reuse without stalling the fair cursor.
        auto next = candidates.upper_bound(cursor);
        for (size_t tried = 0; tried < candidates.size() && current.size() < fairSlots; ++tried) {
            if (next == candidates.end()) next = candidates.begin();
            const auto c = next++->second;
            cursor = c.pid;
            if (selected.insert(c.pid).second) current.push_back(c);
        }
        cohort = current; repeat = !repeat;
        std::vector<int> result;
        for (const auto& c : current) result.push_back(c.pid);
        std::vector<Candidate> priority;
        for (const auto& entry : candidates) priority.push_back(entry.second);
        std::sort(priority.begin(), priority.end(), [](const Candidate& a, const Candidate& b) {
            const double ac = std::isfinite(a.cpu) && a.cpu >= 0 ? a.cpu : -1;
            const double bc = std::isfinite(b.cpu) && b.cpu >= 0 ? b.cpu : -1;
            return ac != bc ? ac > bc : a.pid < b.pid;
        });
        for (const auto& c : priority) {
            if (result.size() >= limit) break;
            if (selected.insert(c.pid).second) result.push_back(c.pid);
        }
        return result;
    }
};
}
