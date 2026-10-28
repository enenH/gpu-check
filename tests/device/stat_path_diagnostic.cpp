#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <cerrno>
#include <cstdio>
#include <string>
#include <vector>

uint64_t ns() { timespec t{}; clock_gettime(CLOCK_MONOTONIC,&t); return uint64_t(t.tv_sec)*1000000000ULL+t.tv_nsec; }
std::string quoted(const std::string& value) {
    std::string out="\""; for(unsigned char c:value) {
        if(c=='"'||c=='\\'){out+='\\';out+=char(c);} else if(c>=32&&c<127)out+=char(c);
        else {char b[7];snprintf(b,sizeof(b),"\\u%04x",unsigned(c));out+=b;}
    } return out+'"';
}
int probe(const std::string& path) { struct stat st{}; return fstatat(AT_FDCWD,path.c_str(),&st,AT_SYMLINK_NOFOLLOW)==0?0:errno; }
int main() {
    const uint64_t start=ns();
    printf("{\"uid\":%d,\"pid\":%d,\"parentPid\":%d,\"calibration\":[",int(getuid()),int(getpid()),int(getppid()));
    std::vector<std::string> controls={"/proc/self","/proc/1","/proc/2147483647","/proc/pid_","/sys/fs/cgroup","/sys/fs/cgroup/uid_","/sys/fs/cgroup/uid_2147483647","/sys/fs/cgroup/uid_"+std::to_string(getuid()),"/sys/fs/cgroup/uid_"+std::to_string(getuid())+"/pid_"+std::to_string(getppid()),"/sys/fs/cgroup/uid_"+std::to_string(getuid())+"/pid_","/sys/fs/cgroup/uid_"+std::to_string(getuid())+"/pid_2147483647","/sys/fs/cgroup/apps","/sys/fs/cgroup/system","/acct"};
    bool first=true;
    for(const auto& path:controls){if(!first)printf(",");first=false;printf("{\"path\":%s,\"errno\":%d}",quoted(path).c_str(),probe(path));}
    printf("],\"layouts\":[");first=true;
    for(const char* root:{"/sys/fs/cgroup","/sys/fs/cgroup/apps","/sys/fs/cgroup/system"}) {
        int rootError=probe(root);
        if(!first)printf(",");first=false;
        const uint64_t began=ns();std::vector<int> present,denied;size_t count=0;
        if(rootError==0)for(int uid=0;uid<100000;uid++) {
            if(uid==20000)uid=90000;
            const int e=probe(std::string(root)+"/uid_"+std::to_string(uid)); ++count;
            if(e==0)present.push_back(uid);else if(e==EACCES)denied.push_back(uid);
        }
        printf("{\"root\":%s,\"errno\":%d,\"probes\":%zu,\"durationMs\":%.3f,\"presentUids\":[",quoted(root).c_str(),rootError,count,double(ns()-began)/1e6);
        for(size_t i=0;i<present.size();i++){if(i)printf(",");printf("%d",present[i]);}
        printf("],\"deniedCount\":%zu}",denied.size());
    }
    printf("],\"durationMs\":%.3f}\n",double(ns()-start)/1e6);
}
