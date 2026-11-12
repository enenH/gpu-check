#include <jni.h>
#include <dlfcn.h>

struct AIBinder;
using CheckService = AIBinder* (*)(const char*);
using ToJava = jobject (*)(JNIEnv*, AIBinder*);
using DecStrong = void (*)(AIBinder*);

extern "C" JNIEXPORT jobject JNICALL
Java_com_gpucheck_app_LayerProbe_lookupSurfaceFlinger(JNIEnv* env, jclass) {
    void* library = dlopen("libbinder_ndk.so", RTLD_NOW | RTLD_LOCAL);
    if (!library) return nullptr;
    auto check = reinterpret_cast<CheckService>(dlsym(library, "AServiceManager_checkService"));
    auto toJava = reinterpret_cast<ToJava>(dlsym(library, "AIBinder_toJavaBinder"));
    auto release = reinterpret_cast<DecStrong>(dlsym(library, "AIBinder_decStrong"));
    jobject result = nullptr;
    if (check && toJava && release) {
        AIBinder* binder = check("SurfaceFlinger");
        if (binder) { result = toJava(env, binder); release(binder); }
    }
    dlclose(library);
    return result;
}
