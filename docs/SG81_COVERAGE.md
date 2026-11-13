# 参考 SG81 的覆盖扩展

## 分析依据与边界

对象与 SHA-256 见 [DETECTION_REVIEW.md](DETECTION_REVIEW.md)。本轮继续阅读 APK 内的
`sample.bin`、Worker 的 ARM64 反汇编，以及 Java 的结果整理与进程详情代码。

| 静态证据 | 能确认的内容 |
| --- | --- |
| sample 偏移 `0x13190` 设置系统调用号 9，`0x131a0` 执行 `svc` | 样本包含 ARM64 `lgetxattr` 调用 |
| sample 偏移 `0x23ba8` / `0x27680` 设置调用号 43 | 样本包含 `statfs` 调用 |
| sample 偏移 `0x24210` / `0x27660` 设置调用号 79 | 样本包含 `newfstatat` 调用 |
| Worker `Runner::interrupt` 的 `0xde338`、`0xde598`、`0xdeaac`、`0xdf230` 调用点 | 分别调用宿主 `clock_gettime`、`ppoll`、`statfs`、`lgetxattr` |
| `ProcessMetadata` 对进程详情读取前后检查 `stat` 启动时间 | 发现 PID 身份变化时清除读取的身份信息 |

这些是存在的调用路径，不是运行命中次数。样本含大量间接分支，尚未完整还原最终谓词、阈值和所有触发条件。
本轮没有执行 SG81 样本，没有复制样本或闭源算法到项目，也不声称复现 SG81 的全部能力。

## 实际实现

### 1. 低负载与未知 CPU 的元数据覆盖

此前元数据预算全给 CPU 最高的进程，普通采集还跳过 CPU < 0.05 的对象。
现在每轮仍最多探测 8 个 PID：先给 4 个按 PID 循环选取的对象，再将剩余名额给 CPU 较高的对象。
循环组在下一轮按同一身份复查，之后才推进；退出、PID 复用或暂时缺席会淘汰旧组成员。

- CPU 为零、CPU 不可读、正在建立基线均可进入循环组；未知 CPU 不会转换成零。
- 组内去重，重复探测不挤占名额；进程选择使用观察 epoch，不能沿用已退出身份。
- 对稳定的 N 个可选对象，从一个完整循环组开始，最多 `2 * ceil(N / 4)` 轮可获得一轮成对覆盖。
  高频创建/退出、权限、不可读取的时钟以及发现范围之外的 PID，仍限制实际覆盖。
- 原有 pidfd 与进程目录存在性矛盾的连续两次确认逻辑不变，因此现在也能检查轮询到的低负载对象。
- `metadataProbeEligible`、`metadataProbeDeferred`、`metadataProbeFairSlots`、
  `metadataProbeCohortSamples` 和现有计数说明每轮覆盖；未选中不等于检查通过。

### 2. 直接 SELinux 标签进入判断

保留 `security.selinux` xattr 与 `/proc/PID/attr/current` 两路原文、错误码，分别读取，
不再只在第一路失败时读取另一路。新增 `statfs` 检查用于直接标签的 procfs 来源校验。
确认直接标签前还要求以下条件：

- 同一 held pidfd 在读取前后仍存活；无 pidfd 时要求标签读取前后启动时间一致；
- 进程身份 token 与证据 token 相同，证据属于当前采样序号；
- 时间窗有序且不超过 30 秒，读取成功，标签满足完整执行域和 MLS 格式；
- 两路成功结果相同，且与当前有效 AVC 不冲突。

一条成功且通过校验的读取路径可以使用，失败路径保持未知。多路查询仍可能受同一个内核、
SELinux 策略、权限及挂载视图影响，不构成独立可信根；`statfs` 也不能证明不存在特权层伪造。

有效的 `su` / `magisk` / `zygisk` / `ksu` 域可以作为原有候选和 CPU/GPU 组合规则的域证据。
不扩大域名列表，不降低 CPU、GPU 或连续采样阈值。已知数值 UID 优先；域字符串不会被写成 UID 0。
普通系统域如 `init`、`system_server` 不因名称进入 root 域候选。

### 3. 冲突处理与结果解释

`DomainEvidence` 统一生成 `VALID` / `UNKNOWN` / `MALFORMED` / `CONFLICT`，记录来源与绑定身份。
成功读取的标签互相冲突时暂停域身份推断，撤销依赖该推断的候选/连续观察；不覆盖独立的数值 UID
或 cgroup 证据。执行域切换也可能造成短暂冲突，所以单次冲突不是恶意或隐藏判定。

界面显示直接读取域或来源冲突，详情和完整 JSON 保留两路原文及错误码。
组合规则为直接域证据新增 `selinux_root_domain_cpu_global_memstore`，保留旧 AVC 路径的 basis。
GPU 仍属于全局观察，不能因此归属给某个 PID。

## 验证与设备验收

可复现的主机检查：

```sh
python3 scripts/test-evidence.py --json-jar /path/to/json.jar
python3 scripts/test-domain-integration.py --android-jar /path/to/android.jar --json-jar /path/to/json.jar
g++ -std=c++17 -Wall -Wextra -Werror -O2 native/probe.cpp -o /tmp/gpu-probe
/tmp/gpu-probe --self-test
```

本轮通过：原有回归测试，36 个新增标签场景及数值 UID 优先级检查，18 项风险引擎/导出集成检查，
循环选择的低负载覆盖、连续复查、预算、优先级、去重和进程变更测试，原生自检。
全部生产 Java 和 instrumentation Java 使用 Android 35 API 编译通过。
集成测试仅模拟本应用 PID/UID，不调用 Android 采集接口；API 编译使用临时资源符号，均不等于完整 APK 或真机测试。

还需在目标手机验收：连续运行至少一个循环周期并查看 deferred 计数、低负载对象的 probe 时间；
在进程退出/重建后检查 token；查看本机 SELinux 读取权限、日志丢失和采样耗时。
本轮未构建 APK、运行 Android lint 或进行真机耗电/性能测试。单轮 PID 上限不变，但双路标签
及文件系统校验会增加少量只读系统调用，需按设备实测调整预算。
