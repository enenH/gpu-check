// External read-only identity evidence; guarded TERM only for the exact supplied instance.
#include <sys/syscall.h>
#include <unistd.h>
#include <dirent.h>
#include <poll.h>
#include <signal.h>
#include <time.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

std::string readText(const std::string& path) {
    std::ifstream in(path); std::ostringstream out; out << in.rdbuf(); return out.str();
}
std::string quote(const std::string& s) {
    std::string out = "\"";
    for (unsigned char c : s) {
        if (c == '\\' || c == '"') { out += '\\'; out += char(c); }
        else if (c >= 32 && c < 127) out += char(c);
        else { char b[7]; std::snprintf(b, sizeof(b), "\\u%04x", unsigned(c)); out += b; }
    }
    return out + '"';
}
uint64_t mono() {
    timespec t{}; clock_gettime(CLOCK_MONOTONIC, &t);
    return uint64_t(t.tv_sec) * 1000000000ULL + uint64_t(t.tv_nsec);
}
struct Identity {
    int pid; std::string exe, stat, status, context, cgroup, start;
    explicit Identity(int id) : pid(id) {
        const std::string base = "/proc/" + std::to_string(pid);
        char path[4096]; ssize_t size = readlink((base + "/exe").c_str(), path, sizeof(path));
        if (size > 0 && size < ssize_t(sizeof(path))) exe.assign(path, size_t(size));
        stat = readText(base + "/stat"); status = readText(base + "/status");
        context = readText(base + "/attr/current"); cgroup = readText(base + "/cgroup");
        const size_t right = stat.rfind(')');
        if (right != std::string::npos) {
            std::istringstream fields(stat.substr(right + 1)); std::string field;
            for (int index = 0; index <= 19 && fields >> field; ++index) if (index == 19) start = field;
        }
    }
    void emit(const char* event, bool signalled = false, bool exited = false) const {
        std::printf("{\"event\":%s,\"pid\":%d,\"exe\":%s,\"startTimeTicks\":%s,\"monotonicNs\":%llu,"
                    "\"stat\":%s,\"status\":%s,\"selinux\":%s,\"cgroup\":%s,\"termSent\":%s,\"pidfdExited\":%s}\n",
                    quote(event).c_str(), pid, quote(exe).c_str(), quote(start).c_str(),
                    static_cast<unsigned long long>(mono()), quote(stat).c_str(), quote(status).c_str(),
                    quote(context).c_str(), quote(cgroup).c_str(), signalled ? "true" : "false", exited ? "true" : "false");
    }
};
int main(int argc, char** argv) {
    if (argc == 3 && std::string(argv[1]) == "find") {
        DIR* dir = opendir("/proc"); if (!dir) return 2;
        while (dirent* entry = readdir(dir)) {
            char* end = nullptr; long pid = std::strtol(entry->d_name, &end, 10);
            if (pid <= 0 || !end || *end || pid > 2147483647) continue;
            Identity value{int(pid)};
            if (value.exe == argv[2] && !value.start.empty()) value.emit("found");
        }
        closedir(dir); return 0;
    }
    if (argc != 5) return 2;
    const int pid = std::atoi(argv[2]); if (pid <= 1) return 2;
    const std::string expectedExe = argv[3], expectedStart = argv[4];
    const int fd = int(syscall(SYS_pidfd_open, pid, 0)); if (fd < 0) return 3;
    pollfd live{fd, POLLIN, 0};
    if (poll(&live, 1, 0) != 0) { close(fd); return 4; }
    Identity value(pid);
    if (value.exe != expectedExe || value.start != expectedStart || value.start.empty()) { close(fd); return 5; }
    if (std::string(argv[1]) == "inspect") { value.emit("snapshot"); close(fd); return 0; }
    if (std::string(argv[1]) != "term") { close(fd); return 2; }
    if (syscall(SYS_pidfd_send_signal, fd, SIGTERM, nullptr, 0) != 0) { close(fd); return 6; }
    live.revents = 0;
    const int ready = poll(&live, 1, 5000);
    const bool exited = ready > 0 && (live.revents & (POLLIN | POLLHUP));
    value.emit("terminated", true, exited); close(fd);
    return exited ? 0 : 7;
}
