#include <sys/syscall.h>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <time.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

static unsigned long long now() {
    timespec value{};
    clock_gettime(CLOCK_MONOTONIC, &value);
    return static_cast<unsigned long long>(value.tv_sec) * 1000000000ULL + value.tv_nsec;
}

// Holds the exact launched process; stdin closure also cleans up an interrupted host test.
int main(int argc, char** argv) {
    if (argc != 3 || argv[2][0] != '/') return 2;
    char* tail = nullptr;
    const long pid = strtol(argv[1], &tail, 10);
    if (!tail || *tail || pid <= 1 || pid > 2147483647) return 2;
    const int fd = static_cast<int>(syscall(SYS_pidfd_open, pid, 0));
    if (fd < 0) return 3;
    pollfd alive{fd, POLLIN, 0};
    char procPath[64], executable[4096];
    snprintf(procPath, sizeof(procPath), "/proc/%ld/exe", pid);
    const ssize_t bytes = readlink(procPath, executable, sizeof(executable) - 1);
    if (bytes < 0 || bytes >= static_cast<ssize_t>(sizeof(executable) - 1)) { close(fd); return 4; }
    executable[bytes] = '\0';
    if (strcmp(executable, argv[2]) || poll(&alive, 1, 0) != 0) { close(fd); return 4; }
    printf("{\"event\":\"ready\",\"pid\":%ld,\"executableVerified\":true,\"monotonicNs\":%llu}\n", pid, now());
    fflush(stdout);
    pollfd waiters[2] = {{fd, POLLIN, 0}, {STDIN_FILENO, POLLIN | POLLHUP, 0}};
    const int state = poll(waiters, 2, 120000);
    bool signalled = false;
    if (state <= 0 || !waiters[0].revents)
        signalled = syscall(SYS_pidfd_send_signal, fd, SIGTERM, nullptr, 0) == 0;
    alive.revents = 0;
    const int done = poll(&alive, 1, 5000);
    const bool exited = done > 0 && (alive.revents & (POLLIN | POLLHUP));
    printf("{\"event\":\"finished\",\"pid\":%ld,\"monotonicNs\":%llu,\"termSent\":%s,\"exited\":%s}\n",
            pid, now(), signalled ? "true" : "false", exited ? "true" : "false");
    close(fd);
    return exited ? 0 : 7;
}
