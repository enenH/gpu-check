#pragma once

#include <atomic>
#include <linux/futex.h>
#include <pthread.h>

// Only a fresh local word is passed to the kernel. No target memory is accessed.
namespace futex_probe {
struct Result {
    long ret = -2, unlockRet = -2;
    int error = 0, unlockError = 0;
    uint32_t wordAfter = 0;
    void json(std::ostream& out) const {
        out << "{\"ret\":" << ret << ",\"errno\":" << error << ",\"wordAfter\":" << wordAfter
            << ",\"unlockRet\":" << unlockRet << ",\"unlockErrno\":" << unlockError << '}';
    }
};

class Probe {
    volatile sig_atomic_t& blocked;
    pthread_t worker{};
    int stopPipe[2]{-1, -1};
    bool started = false;
    std::atomic<int> peerTid{0};
    static void* waitForStop(void* value) {
        auto& self = *static_cast<Probe*>(value);
        self.peerTid.store(int(syscall(SYS_gettid)));
        char byte;
        while (read(self.stopPipe[0], &byte, 1) < 0 && errno == EINTR) {}
        return nullptr;
    }
public:
    bool available = false;
    unsigned sampleIndex = 0;
    Result zero, self, peer, missing;
    explicit Probe(volatile sig_atomic_t& flag) : blocked(flag) {
        if (pipe2(stopPipe, O_CLOEXEC) != 0) return;
        if (pthread_create(&worker, nullptr, waitForStop, this) != 0) {
            close(stopPipe[0]); close(stopPipe[1]); stopPipe[0] = stopPipe[1] = -1; return;
        }
        started = true;
        for (int attempt = 0; attempt < 100 && !peerTid.load(); ++attempt) usleep(1000);
    }
    ~Probe() {
        if (started) {
            // Closing the only writer wakes read() even if startup took longer than expected.
            close(stopPipe[1]);
            pthread_join(worker, nullptr);
            close(stopPipe[0]);
        }
    }
    Result query(uint32_t tid) {
        alignas(4) uint32_t word = tid;
        Result result;
        blocked = 0; errno = 0;
        result.ret = syscall(SYS_futex, &word, FUTEX_TRYLOCK_PI | FUTEX_PRIVATE_FLAG, 0, nullptr, nullptr, 0);
        result.error = blocked ? ENOSYS : (result.ret < 0 ? errno : 0);
        if (blocked) result.ret = -1;
        result.wordAfter = word;
        if (result.ret == 0) {
            blocked = 0; errno = 0;
            result.unlockRet = syscall(SYS_futex, &word, FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG, 0, nullptr, nullptr, 0);
            result.unlockError = blocked ? ENOSYS : (result.unlockRet < 0 ? errno : 0);
            if (blocked) result.unlockRet = -1;
        }
        return result;
    }
    void calibrate(unsigned sample) {
        available = false; sampleIndex = sample;
        zero = self = peer = missing = Result{};
        if (!started || peerTid.load() <= 0) return;
        zero = query(0);
        self = query(uint32_t(syscall(SYS_gettid)));
        peer = query(uint32_t(peerTid.load()));
        missing = query(FUTEX_TID_MASK);
        available = zero.ret == 0 && zero.unlockRet == 0
            && self.ret == -1 && self.error == EDEADLK
            && peer.ret == -1 && peer.error == EAGAIN
            && missing.ret == -1 && missing.error == ESRCH;
    }
    void json(std::ostream& out) const {
        out << "{\"method\":\"futex_trylock_pi\",\"private\":true,\"available\":" << available
            << ",\"sampleIndex\":" << sampleIndex << ",\"controls\":{\"zero\":";
        zero.json(out); out << ",\"self\":"; self.json(out);
        out << ",\"peer\":"; peer.json(out); out << ",\"missing\":"; missing.json(out);
        out << "}}";
    }
};
} // namespace futex_probe
