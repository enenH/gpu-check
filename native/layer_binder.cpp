#include <jni.h>
#include <dlfcn.h>
#include <poll.h>
#include <sys/syscall.h>
#include <unistd.h>

struct AIBinder;
using CheckService = AIBinder* (*)(const char*);
using ToJava = jobject (*)(JNIEnv*, AIBinder*);
using DecStrong = void (*)(AIBinder*);

static jobject lookup(JNIEnv* env, const char* name) {
    void* library = dlopen("libbinder_ndk.so", RTLD_NOW | RTLD_LOCAL);
    if (!library) return nullptr;
    auto check = reinterpret_cast<CheckService>(dlsym(library, "AServiceManager_checkService"));
    auto toJava = reinterpret_cast<ToJava>(dlsym(library, "AIBinder_toJavaBinder"));
    auto release = reinterpret_cast<DecStrong>(dlsym(library, "AIBinder_decStrong"));
    jobject result = nullptr;
    if (check && toJava && release) {
        AIBinder* binder = check(name);
        if (binder) { result = toJava(env, binder); release(binder); }
    }
    dlclose(library);
    return result;
}

extern "C" JNIEXPORT jobject JNICALL
Java_com_gpucheck_app_LayerProbe_lookupSurfaceFlinger(JNIEnv* env, jclass) {
    return lookup(env, "SurfaceFlinger");
}

extern "C" JNIEXPORT jobject JNICALL
Java_com_gpucheck_app_OemProcessSupport_lookupBinder(JNIEnv* env, jclass, jstring name) {
    if (!name || env->GetStringLength(name) > 256) return nullptr;
    const char* value = env->GetStringUTFChars(name, nullptr);
    if (!value) return nullptr;
    jobject binder = lookup(env, value);
    env->ReleaseStringUTFChars(name, value);
    return binder;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_gpucheck_app_OemProcessSupport_openPidfdNative(JNIEnv*, jclass, jint pid) {
    if (pid <= 0) return -1;
    return static_cast<jint>(syscall(__NR_pidfd_open, pid, 0));
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_gpucheck_app_OemProcessSupport_pidfdAliveNative(JNIEnv*, jclass, jint fd) {
    if (fd < 0) return JNI_FALSE;
    pollfd descriptor{fd, POLLIN, 0};
    return poll(&descriptor, 1, 0) == 0 && descriptor.revents == 0 ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT void JNICALL
Java_com_gpucheck_app_OemProcessSupport_closePidfdNative(JNIEnv*, jclass, jint fd) {
    if (fd >= 0) close(fd);
}
