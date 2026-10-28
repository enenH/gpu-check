#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace {
struct Text { int error = 0; std::string value; };
Text read_text(const std::string& path) {
    Text result;
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) { result.error = errno; return result; }
    char buffer[8192];
    for (;;) {
        ssize_t count = read(fd, buffer, sizeof(buffer));
        if (count > 0) result.value.append(buffer, static_cast<size_t>(count));
        else if (!count) break;
        else if (errno != EINTR) { result.error = errno; break; }
    }
    close(fd);
    return result;
}
Text read_link(const std::string& path) {
    Text result;
    char buffer[4096];
    ssize_t count = readlink(path.c_str(), buffer, sizeof(buffer));
    if (count < 0) result.error = errno;
    else if (static_cast<size_t>(count) == sizeof(buffer)) result.error = ENAMETOOLONG;
    else result.value.assign(buffer, static_cast<size_t>(count));
    return result;
}
std::string quoted(const std::string& value) {
    static const char hex[] = "0123456789abcdef";
    std::string out = "\"";
    for (unsigned char ch : value) {
        if (ch == '"' || ch == '\\') { out += '\\'; out += static_cast<char>(ch); }
        else if (ch >= 0x20 && ch < 0x7f) out += static_cast<char>(ch);
        else { out += "\\u00"; out += hex[ch >> 4]; out += hex[ch & 15]; }
    }
    return out + '"';
}
uint64_t monotonic_ns() {
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL + static_cast<uint64_t>(ts.tv_nsec);
}
void emit_text(const Text& data) {
    std::cout << "{\"errno\":" << data.error << ",\"text\":" << quoted(data.value) << '}';
}
bool decimal(const std::string& value) {
    return !value.empty() && std::all_of(value.begin(), value.end(), [](char ch) { return ch >= '0' && ch <= '9'; });
}
uint64_t parse_uint(const std::string& value, bool& valid) {
    if (!decimal(value)) { valid = false; return 0; }
    errno = 0;
    char* end = nullptr;
    unsigned long long result = std::strtoull(value.c_str(), &end, 10);
    if (errno || !end || *end) valid = false;
    return static_cast<uint64_t>(result);
}
std::vector<std::string> words(const std::string& line) {
    std::istringstream input(line);
    std::vector<std::string> values;
    std::string value;
    while (input >> value) values.push_back(value);
    return values;
}
struct Probe { std::string path; int error = 0; uint64_t mode = 0; };
Probe probe(const std::string& path) {
    Probe result;
    result.path = path;
    struct stat info{};
    if (lstat(path.c_str(), &info) < 0) result.error = errno;
    else result.mode = info.st_mode;
    return result;
}
struct Process {
    int pid = 0;
    Text stat, status, cgroup;
    int stat_parse_errno = 0, status_parse_errno = 0;
    std::string comm, state;
    int ppid = -1, tgid = -1;
    int64_t uid = -1;
    uint64_t flags = 0, starttime = 0, begin_ns = 0, end_ns = 0;
    std::vector<Probe> probes;
};
Process process(int pid, bool add_probes, int64_t fallback_uid = -1) {
    Process result;
    result.pid = pid;
    result.begin_ns = monotonic_ns();
    const std::string prefix = "/proc/" + std::to_string(pid) + '/';
    result.stat = read_text(prefix + "stat");
    if (!result.stat.error) {
        size_t left = result.stat.value.find('('), right = result.stat.value.rfind(')');
        if (left == std::string::npos || right == std::string::npos || right <= left) result.stat_parse_errno = EINVAL;
        else {
            result.comm = result.stat.value.substr(left + 1, right - left - 1);
            auto fields = words(result.stat.value.substr(right + 1));
            if (fields.size() < 20) result.stat_parse_errno = EINVAL;
            else {
                bool valid = true;
                result.state = fields[0];
                result.ppid = static_cast<int>(parse_uint(fields[1], valid));
                result.flags = parse_uint(fields[6], valid);
                result.starttime = parse_uint(fields[19], valid);
                if (!valid || result.state.size() != 1) result.stat_parse_errno = EINVAL;
            }
        }
    }
    result.status = read_text(prefix + "status");
    if (!result.status.error) {
        std::istringstream lines(result.status.value);
        std::string line;
        while (std::getline(lines, line)) {
            auto fields = words(line);
            if (fields.size() < 2) continue;
            bool valid = true;
            if (fields[0] == "Uid:") result.uid = static_cast<int64_t>(parse_uint(fields[1], valid));
            else if (fields[0] == "Tgid:") result.tgid = static_cast<int>(parse_uint(fields[1], valid));
            if (!valid) result.status_parse_errno = EINVAL;
        }
        if (result.uid < 0 || result.tgid < 0) result.status_parse_errno = EINVAL;
    }
    result.cgroup = read_text(prefix + "cgroup");
    const int64_t target_uid = result.uid >= 0 ? result.uid : fallback_uid;
    if (add_probes && target_uid >= 0) {
        const std::string suffix = "/uid_" + std::to_string(target_uid) + "/pid_" + std::to_string(pid);
        for (const char* base : {"/sys/fs/cgroup", "/sys/fs/cgroup/apps", "/sys/fs/cgroup/system", "/acct"})
            result.probes.push_back(probe(std::string(base) + suffix));
        result.probes.push_back(probe("/acct/uid_" + std::to_string(target_uid)));
    }
    result.end_ns = monotonic_ns();
    return result;
}
void emit_process(const Process& data) {
    std::cout << "{\"pid\":" << data.pid << ",\"begin_ns\":" << data.begin_ns << ",\"end_ns\":" << data.end_ns;
    std::cout << ",\"stat\":{\"errno\":" << data.stat.error << ",\"parse_errno\":" << data.stat_parse_errno
        << ",\"raw\":" << quoted(data.stat.value) << ",\"comm\":" << quoted(data.comm)
        << ",\"state\":" << quoted(data.state) << ",\"ppid\":" << data.ppid << ",\"flags\":" << data.flags
        << ",\"starttime\":" << data.starttime << '}';
    std::cout << ",\"status\":{\"errno\":" << data.status.error << ",\"parse_errno\":" << data.status_parse_errno
        << ",\"raw\":" << quoted(data.status.value) << ",\"uid\":" << data.uid << ",\"tgid\":" << data.tgid << '}';
    std::cout << ",\"cgroup\":"; emit_text(data.cgroup);
    std::cout << ",\"directory_probes\":[";
    bool first = true;
    for (const auto& entry : data.probes) {
        if (!first) std::cout << ',';
        first = false;
        std::cout << "{\"path\":" << quoted(entry.path) << ",\"errno\":" << entry.error << ",\"mode\":" << entry.mode << '}';
    }
    std::cout << "]}";
}
struct Snapshot {
    int error = 0;
    uint64_t begin_ns = 0, end_ns = 0;
    std::vector<Process> pids;
    std::vector<std::pair<std::string, int>> entry_errors;
};
Snapshot snapshot(bool probes) {
    Snapshot result;
    result.begin_ns = monotonic_ns();
    DIR* directory = opendir("/proc");
    if (!directory) result.error = errno;
    else {
        std::vector<int> ids;
        for (;;) {
            errno = 0;
            dirent* entry = readdir(directory);
            if (!entry) { result.error = errno; break; }
            std::string name(entry->d_name);
            if (!decimal(name)) continue;
            if (entry->d_type == DT_DIR) {
                ids.push_back(std::atoi(name.c_str()));
                continue;
            }
            if (entry->d_type == DT_LNK) continue;
            struct stat info{};
            if (fstatat(dirfd(directory), name.c_str(), &info, AT_SYMLINK_NOFOLLOW) < 0) {
                result.entry_errors.emplace_back(name, errno);
                // /proc numeric entries identify processes even when metadata is denied.
                ids.push_back(std::atoi(name.c_str()));
            } else if (S_ISDIR(info.st_mode)) ids.push_back(std::atoi(name.c_str()));
        }
        closedir(directory);
        std::sort(ids.begin(), ids.end());
        for (int pid : ids) result.pids.push_back(process(pid, probes));
    }
    result.end_ns = monotonic_ns();
    return result;
}
void emit_snapshot(const Snapshot& data) {
    std::cout << "{\"errno\":" << data.error << ",\"begin_ns\":" << data.begin_ns << ",\"end_ns\":" << data.end_ns << ",\"pids\":[";
    bool first = true;
    for (const auto& entry : data.pids) { if (!first) std::cout << ','; first = false; emit_process(entry); }
    std::cout << "],\"entry_errors\":[";
    first = true;
    for (const auto& error : data.entry_errors) {
        if (!first) std::cout << ',';
        first = false;
        std::cout << "{\"name\":" << quoted(error.first) << ",\"errno\":" << error.second << '}';
    }
    std::cout << "]}";
}
struct Members { Text data; int parse_errno = 0; std::vector<uint64_t> values; };
Members members(const std::string& path) {
    Members result;
    result.data = read_text(path);
    for (const auto& word : words(result.data.value)) {
        bool valid = true;
        uint64_t value = parse_uint(word, valid);
        if (valid) result.values.push_back(value);
        else result.parse_errno = EINVAL;
    }
    return result;
}
void emit_members(const Members& data) {
    std::cout << "{\"errno\":" << data.data.error << ",\"parse_errno\":" << data.parse_errno << ",\"members\":[";
    bool first = true;
    for (uint64_t value : data.values) { if (!first) std::cout << ','; first = false; std::cout << value; }
    std::cout << "]}";
}
struct Group {
    std::string path;
    int scan_errno = 0;
    std::vector<std::pair<std::string, int>> entry_errors;
    uint64_t begin_ns = 0, end_ns = 0;
    Members procs, threads;
    Text type;
};
struct Mount {
    std::string root, mountpoint, super_options, fstype, mount_options;
    int mount_id = 0;
    std::vector<Group> groups;
};
std::string unescape_mount(const std::string& value) {
    std::string out;
    for (size_t i = 0; i < value.size(); ++i) {
        if (value[i] == '\\' && i + 3 < value.size() && value[i + 1] >= '0' && value[i + 1] <= '7'
            && value[i + 2] >= '0' && value[i + 2] <= '7' && value[i + 3] >= '0' && value[i + 3] <= '7') {
            out += static_cast<char>((value[i + 1] - '0') * 64 + (value[i + 2] - '0') * 8 + value[i + 3] - '0');
            i += 3;
        } else out += value[i];
    }
    return out;
}
std::vector<Mount> parse_mounts(const Text& source) {
    std::vector<Mount> mounts;
    std::istringstream lines(source.value);
    std::string line;
    while (std::getline(lines, line)) {
        size_t split = line.find(" - ");
        if (split == std::string::npos) continue;
        auto left = words(line.substr(0, split)), right = words(line.substr(split + 3));
        if (left.size() < 6 || right.size() < 3 || (right[0] != "cgroup" && right[0] != "cgroup2")) continue;
        Mount entry;
        entry.mount_id = std::atoi(left[0].c_str());
        entry.root = unescape_mount(left[3]); entry.mountpoint = unescape_mount(left[4]);
        entry.mount_options = left[5]; entry.fstype = right[0]; entry.super_options = right[2];
        mounts.push_back(std::move(entry));
    }
    return mounts;
}
void walk_groups(Mount& mount, const std::string& path, unsigned depth = 0) {
    Group group;
    group.path = path; group.begin_ns = monotonic_ns();
    group.procs = members(path + "/cgroup.procs");
    group.threads = members(path + (mount.fstype == "cgroup2" ? "/cgroup.threads" : "/tasks"));
    if (mount.fstype == "cgroup2") group.type = read_text(path + "/cgroup.type");
    std::vector<std::string> children;
    if (depth > 256) group.scan_errno = ELOOP;
    else {
        int fd = open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) group.scan_errno = errno;
        else {
            DIR* directory = fdopendir(fd);
            if (!directory) { group.scan_errno = errno; close(fd); }
            else {
                for (;;) {
                    errno = 0;
                    dirent* entry = readdir(directory);
                    if (!entry) { group.scan_errno = errno; break; }
                    std::string name(entry->d_name);
                    if (name == "." || name == "..") continue;
                    struct stat info{};
                    if (fstatat(dirfd(directory), name.c_str(), &info, AT_SYMLINK_NOFOLLOW) < 0)
                        group.entry_errors.emplace_back(name, errno);
                    else if (S_ISDIR(info.st_mode)) children.push_back(path + '/' + name);
                }
                closedir(directory);
            }
        }
    }
    group.end_ns = monotonic_ns();
    mount.groups.push_back(std::move(group));
    std::sort(children.begin(), children.end());
    for (const auto& child : children) walk_groups(mount, child, depth + 1);
}
void emit_mount(const Mount& data) {
    std::cout << "{\"mount_id\":" << data.mount_id << ",\"root\":" << quoted(data.root)
        << ",\"mountpoint\":" << quoted(data.mountpoint) << ",\"super_options\":" << quoted(data.super_options)
        << ",\"mount_options\":" << quoted(data.mount_options) << ",\"fstype\":" << quoted(data.fstype) << ",\"groups\":[";
    bool first = true;
    for (const auto& group : data.groups) {
        if (!first) std::cout << ',';
        first = false;
        std::cout << "{\"path\":" << quoted(group.path) << ",\"scan_errno\":" << group.scan_errno
            << ",\"begin_ns\":" << group.begin_ns << ",\"end_ns\":" << group.end_ns << ",\"procs\":";
        emit_members(group.procs);
        std::cout << (data.fstype == "cgroup2" ? ",\"threads\":" : ",\"tasks\":"); emit_members(group.threads);
        if (data.fstype == "cgroup2") { std::cout << ",\"type\":"; emit_text(group.type); }
        std::cout << ",\"entry_errors\":[";
        bool first_error = true;
        for (const auto& error : group.entry_errors) {
            if (!first_error) std::cout << ',';
            first_error = false;
            std::cout << "{\"name\":" << quoted(error.first) << ",\"errno\":" << error.second << '}';
        }
        std::cout << "]}";
    }
    std::cout << "]}";
}
struct Target { int pid = 0; int64_t uid = -1; uint64_t starttime = 0; Process observation; };
struct Fixtures {
    bool enabled = false, zombie_confirmed = false, cleaned = false;
    pid_t live_pid = -1, zombie_pid = -1;
    int live_fd = -1, setup_errno = 0, live_kill_errno = 0, live_wait_errno = 0, zombie_wait_errno = 0;
    void start() {
        enabled = true;
        int pipefds[2];
        if (pipe2(pipefds, O_CLOEXEC) < 0) { setup_errno = errno; return; }
        live_pid = fork();
        const int fork_error = errno;
        if (!live_pid) {
            close(pipefds[1]);
            char byte;
            while (read(pipefds[0], &byte, 1) < 0 && errno == EINTR) {}
            _exit(0);
        }
        close(pipefds[0]); live_fd = pipefds[1];
        if (live_pid < 0) { setup_errno = fork_error; return; }
        zombie_pid = fork();
        if (!zombie_pid) _exit(0);
        if (zombie_pid < 0) { setup_errno = errno; return; }
        const uint64_t deadline = monotonic_ns() + 500000000ULL;
        do {
            if (process(zombie_pid, false).state == "Z") { zombie_confirmed = true; break; }
            timespec pause{0, 1000000}; nanosleep(&pause, nullptr);
        } while (monotonic_ns() < deadline);
        if (!zombie_confirmed) setup_errno = ETIMEDOUT;
    }
    void cleanup() {
        if (cleaned) return;
        if (live_pid > 0) {
            if (kill(live_pid, SIGKILL) < 0) live_kill_errno = errno;
            int status; pid_t waited;
            do { waited = waitpid(live_pid, &status, 0); } while (waited < 0 && errno == EINTR);
            if (waited < 0) live_wait_errno = errno;
        }
        if (live_fd >= 0) { close(live_fd); live_fd = -1; }
        if (zombie_pid > 0) {
            if (!zombie_confirmed) kill(zombie_pid, SIGKILL);
            int status; pid_t waited;
            do { waited = waitpid(zombie_pid, &status, 0); } while (waited < 0 && errno == EINTR);
            if (waited < 0) zombie_wait_errno = errno;
        }
        cleaned = true;
    }
    ~Fixtures() { cleanup(); }
};
}

int main(int argc, char** argv) {
    const uint64_t begin_ns = monotonic_ns();
    bool with_fixtures = false;
    std::string targets_path;
    for (int index = 1; index < argc; ++index) {
        if (!std::strcmp(argv[index], "--fixtures")) with_fixtures = true;
        else if (!std::strcmp(argv[index], "--targets-file") && index + 1 < argc) targets_path = argv[++index];
        else { std::cout << "{\"error\":\"usage: cgroup_audit [--fixtures] [--targets-file PATH]\"}\n"; return 2; }
    }
    const Text selinux = read_text("/proc/self/attr/current");
    const Text ns_pid = read_link("/proc/self/ns/pid"), ns_mnt = read_link("/proc/self/ns/mnt"), ns_cgroup = read_link("/proc/self/ns/cgroup");
    utsname system{};
    int uname_error = uname(&system) < 0 ? errno : 0;
    Fixtures fixtures;
    if (with_fixtures) fixtures.start();
    const Snapshot before = snapshot(true);
    const Text mountinfo = read_text("/proc/self/mountinfo");
    auto mounts = parse_mounts(mountinfo);
    for (auto& mount : mounts) walk_groups(mount, mount.mountpoint);
    Text target_source;
    int target_parse_errno = 0;
    std::vector<Target> targets;
    if (!targets_path.empty()) {
        target_source = read_text(targets_path);
        std::istringstream lines(target_source.value);
        std::string line;
        while (std::getline(lines, line)) {
            auto fields = words(line);
            if (fields.empty() || fields[0][0] == '#' || fields[0] == "pid") continue;
            if (fields.size() != 3) { target_parse_errno = EINVAL; continue; }
            bool valid = true;
            Target target;
            target.pid = static_cast<int>(parse_uint(fields[0], valid));
            target.uid = static_cast<int64_t>(parse_uint(fields[1], valid));
            target.starttime = parse_uint(fields[2], valid);
            if (!valid || target.pid <= 0 || target.uid < 0) { target_parse_errno = EINVAL; continue; }
            target.observation = process(target.pid, true, target.uid);
            targets.push_back(std::move(target));
        }
    }
    const Snapshot after = snapshot(false);
    fixtures.cleanup();
    const uint64_t end_ns = monotonic_ns();
    std::cout << "{\"schema_version\":1,\"meta\":{\"uid\":" << getuid() << ",\"euid\":" << geteuid()
        << ",\"gid\":" << getgid() << ",\"egid\":" << getegid() << ",\"pid\":" << getpid() << ",\"selinux\":";
    emit_text(selinux);
    std::cout << ",\"uname\":{\"errno\":" << uname_error << ",\"sysname\":" << quoted(system.sysname)
        << ",\"nodename\":" << quoted(system.nodename) << ",\"release\":" << quoted(system.release)
        << ",\"version\":" << quoted(system.version) << ",\"machine\":" << quoted(system.machine) << '}';
    std::cout << ",\"namespaces\":{\"pid\":"; emit_text(ns_pid);
    std::cout << ",\"mnt\":"; emit_text(ns_mnt);
    std::cout << ",\"cgroup\":"; emit_text(ns_cgroup);
    std::cout << "},\"monotonic_start_ns\":" << begin_ns << ",\"monotonic_end_ns\":" << end_ns << '}';
    std::cout << ",\"fixtures\":{\"enabled\":" << (fixtures.enabled ? "true" : "false")
        << ",\"live_pid\":" << fixtures.live_pid << ",\"zombie_pid\":" << fixtures.zombie_pid
        << ",\"zombie_confirmed\":" << (fixtures.zombie_confirmed ? "true" : "false")
        << ",\"setup_errno\":" << fixtures.setup_errno << ",\"cleaned\":" << (fixtures.cleaned ? "true" : "false")
        << ",\"live_kill_errno\":" << fixtures.live_kill_errno << ",\"live_wait_errno\":" << fixtures.live_wait_errno
        << ",\"zombie_wait_errno\":" << fixtures.zombie_wait_errno << '}';
    std::cout << ",\"proc_before\":"; emit_snapshot(before);
    std::cout << ",\"mountinfo\":"; emit_text(mountinfo);
    std::cout << ",\"mounts\":[";
    bool first = true;
    for (const auto& mount : mounts) { if (!first) std::cout << ','; first = false; emit_mount(mount); }
    std::cout << "],\"targets\":{\"path\":" << quoted(targets_path) << ",\"errno\":" << target_source.error
        << ",\"parse_errno\":" << target_parse_errno << ",\"rows\":[";
    first = true;
    for (const auto& target : targets) {
        if (!first) std::cout << ',';
        first = false;
        std::cout << "{\"supplied_pid\":" << target.pid << ",\"supplied_uid\":" << target.uid
            << ",\"supplied_starttime\":" << target.starttime << ",\"observation\":";
        emit_process(target.observation); std::cout << '}';
    }
    std::cout << "]},\"proc_after\":"; emit_snapshot(after);
    std::cout << "}\n";
    return std::cout.good() ? 0 : 1;
}
