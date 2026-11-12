#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

/* Standalone experiment. Never passed a target-owned address; never blocks on
 * a target futex. procfs is independent ground truth, not part of the probe. */
struct task_info {
    int error;
    unsigned long long flags, starttime;
    char state, comm[256];
};

static void json_string(const char *value) {
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
        if (*p == '"' || *p == '\\') printf("\\%c", *p);
        else if (*p < 32 || *p >= 127) printf("\\u%04x", *p);
        else putchar(*p);
    }
    putchar('"');
}

static struct task_info task_info(int tid) {
    struct task_info result = {0};
    char path[80], buffer[4096];
    snprintf(path, sizeof(path), "/proc/%d/stat", tid);
    FILE *file = fopen(path, "re");
    if (!file) { result.error = errno; return result; }
    if (!fgets(buffer, sizeof(buffer), file)) {
        result.error = ferror(file) ? EIO : ENODATA;
        fclose(file);
        return result;
    }
    fclose(file);
    char *left = strchr(buffer, '('), *right = strrchr(buffer, ')');
    if (!left || !right || right <= left) { result.error = EINVAL; return result; }
    size_t length = (size_t)(right - left - 1);
    if (length >= sizeof(result.comm)) length = sizeof(result.comm) - 1;
    memcpy(result.comm, left + 1, length);
    char *save = NULL, *token = strtok_r(right + 2, " \n", &save);
    int field = 3;
    for (; token; token = strtok_r(NULL, " \n", &save), ++field) {
        if (field == 3) result.state = token[0];
        if (field == 9) result.flags = strtoull(token, NULL, 10);
        if (field == 22) { result.starttime = strtoull(token, NULL, 10); return result; }
    }
    result.error = EINVAL;
    return result;
}

static void print_task(struct task_info info) {
    printf("{\"errno\":%d,\"comm\":", info.error);
    json_string(info.comm);
    printf(",\"state\":\"%c\",\"flags\":%llu,\"pf_kthread\":%s,\"starttime\":%llu}",
           info.state ? info.state : '?', info.flags,
           (info.flags & 0x00200000ULL) ? "true" : "false", info.starttime);
}

static void meta(void) {
    struct utsname name = {0};
    uname(&name);
    printf("{\"type\":\"meta\",\"pid\":%d,\"tid\":%ld,\"uid\":%d,\"euid\":%d,\"kernel\":",
           getpid(), syscall(SYS_gettid), getuid(), geteuid());
    json_string(name.release);
    char context[256] = "", line[512], caps[80] = "unknown";
    int seccomp = -1;
    FILE *file = fopen("/proc/self/attr/current", "re");
    if (file) {
        if (fgets(context, sizeof(context), file)) context[strcspn(context, "\r\n")] = 0;
        fclose(file);
    }
    file = fopen("/proc/self/status", "re");
    if (file) {
        while (fgets(line, sizeof(line), file)) {
            if (!strncmp(line, "CapEff:", 7)) sscanf(line + 7, "%79s", caps);
            if (!strncmp(line, "Seccomp:", 8)) seccomp = atoi(line + 8);
        }
        fclose(file);
    }
    printf(",\"selinux\":"); json_string(context);
    printf(",\"cap_eff\":"); json_string(caps);
    printf(",\"seccomp\":%d}\n", seccomp);
}

static int number(const char *text) {
    if (!*text) return 0;
    for (const char *p = text; *p; ++p) if (*p < '0' || *p > '9') return 0;
    return 1;
}

static int snapshot(void) {
    DIR *proc = opendir("/proc");
    if (!proc) return 2;
    struct dirent *process;
    while ((process = readdir(proc))) {
        if (!number(process->d_name)) continue;
        int tgid = atoi(process->d_name);
        char path[80];
        snprintf(path, sizeof(path), "/proc/%d/task", tgid);
        DIR *tasks = opendir(path);
        if (!tasks) continue;
        struct dirent *thread;
        while ((thread = readdir(tasks))) {
            if (!number(thread->d_name)) continue;
            int tid = atoi(thread->d_name);
            printf("{\"type\":\"task\",\"tgid\":%d,\"tid\":%d,\"stat\":", tgid, tid);
            print_task(task_info(tid));
            puts("}");
        }
        closedir(tasks);
    }
    closedir(proc);
    return 0;
}

static int probe(const char *label, uint32_t tid, int repeat) {
    int failures = 0;
    struct task_info before = task_info((int)tid);
    for (int private_flag = 0; private_flag <= 1; ++private_flag) {
        int flag = private_flag ? FUTEX_PRIVATE_FLAG : 0;
        for (int iteration = 0; iteration < repeat; ++iteration) {
            /* Fresh, aligned, uncontended local word. No WAITERS/OWNER_DIED input. */
            _Alignas(4) uint32_t word = tid;
            errno = 0;
            long result = syscall(SYS_futex, &word, FUTEX_TRYLOCK_PI | flag,
                                  0, NULL, NULL, 0);
            int saved_errno = errno;
            uint32_t after = word;
            long unlock_result = -2;
            int unlock_errno = 0;
            if (result == 0) {
                errno = 0;
                unlock_result = syscall(SYS_futex, &word, FUTEX_UNLOCK_PI | flag,
                                        0, NULL, NULL, 0);
                unlock_errno = errno;
                if (unlock_result != 0) ++failures;
            }
            printf("{\"type\":\"probe\",\"label\":"); json_string(label);
            printf(",\"tid\":%u,\"private\":%s,\"iteration\":%d,\"ret\":%ld,\"errno\":%d,"
                   "\"word_before\":%u,\"word_after\":%u,\"unlock_ret\":%ld,\"unlock_errno\":%d}\n",
                   tid, private_flag ? "true" : "false", iteration, result, saved_errno,
                   tid, after, unlock_result, unlock_errno);
        }
    }
    printf("{\"type\":\"identity\",\"label\":"); json_string(label);
    printf(",\"tid\":%u,\"before\":", tid); print_task(before);
    printf(",\"after\":"); print_task(task_info((int)tid));
    puts("}");
    return failures;
}

static _Atomic int worker_tid;
static int stop_pipe[2];
static void *worker(void *unused) {
    (void)unused;
    atomic_store(&worker_tid, (int)syscall(SYS_gettid));
    char byte;
    while (read(stop_pipe[0], &byte, 1) < 0 && errno == EINTR) {}
    return NULL;
}

int main(int argc, char **argv) {
    /* Bounds the entire standalone experiment, including unexpected kernel waits. */
    alarm(30);
    meta();
    if (argc == 2 && !strcmp(argv[1], "--snapshot")) return snapshot();
    int repeat = 20, first = 1;
    if (argc > 2 && !strcmp(argv[1], "--repeat")) {
        repeat = atoi(argv[2]); first = 3;
        if (repeat < 1 || repeat > 100) return 2;
    }
    for (int i = first; i < argc; ++i) {
        if (!number(argv[i]) || strtoull(argv[i], NULL, 10) > FUTEX_TID_MASK) return 2;
    }
    pid_t zombie = fork();
    if (zombie < 0) { perror("fork"); return 2; }
    if (zombie == 0) _exit(0);
    siginfo_t info = {0};
    if (waitid(P_PID, (id_t)zombie, &info, WEXITED | WNOWAIT) != 0) return 2;
    pthread_t thread;
    if (pipe(stop_pipe) || pthread_create(&thread, NULL, worker, NULL)) return 2;
    while (!atomic_load(&worker_tid)) usleep(1000);
    int failures = 0;
    failures += probe("zero_unlocked", 0, repeat);
    failures += probe("self", (uint32_t)syscall(SYS_gettid), repeat);
    int live_tid = atomic_load(&worker_tid);
    failures += probe("live_same_process_thread", (uint32_t)live_tid, repeat);
    failures += probe("zombie", (uint32_t)zombie, repeat);
    failures += probe("nonexistent", FUTEX_TID_MASK, repeat);
    for (int i = first; i < argc; ++i) failures += probe("external", (uint32_t)strtoul(argv[i], NULL, 10), repeat);
    if (write(stop_pipe[1], "x", 1) != 1) ++failures;
    pthread_join(thread, NULL);
    failures += probe("exited_thread", (uint32_t)live_tid, repeat);
    close(stop_pipe[0]); close(stop_pipe[1]);
    if (waitpid(zombie, NULL, 0) != zombie) ++failures;
    printf("{\"type\":\"end\",\"cleanup_failures\":%d}\n", failures);
    return failures ? 1 : 0;
}
