GPU Check — Android 用户态进程风险检测

权限边界
应用及其原生采集器以普通应用 UID 运行，不调用 su，不使用 adb/Shizuku/root 辅助服务，不启动测试目标。
Manifest 不声明任何权限；不申请通知、存储或读取全设备日志权限。
仅在检测界面可见期间采样，离开界面自动停止。无前台服务或通知。

检测方式
1. 使用 Linux 按 PID 的进程 CPU 时钟差分发现高负载候选，绕开对 /proc 枚举结果的依赖。
   现有候选同时接收 cgroup 命名路径差异线索：使用 stat/fstatat 的返回值探测 /proc/PID 和参考 UID/PID 目录，不要求读取 cgroup 目录或成员文件。
   对现代 /sys/fs/cgroup/uid_N/pid_P 及旧式 apps/system 布局执行自身正对照和 uid_/pid_ 不存在对照，自主建立有界 UID 目录编目。
   返回0表示存在；经对照验证可区分不存在时，EACCES仅作为存在性线索；只有明确的ENOENT才计为路径未匹配。
   同一存活进程须有前后有效pidfd身份，本轮已校准范围内的所有候选路径均未匹配，连续3次才纳入监听。
   这些进程沿用同一进程列表、CPU采样与GPU生命周期观察，零CPU也可准入；所有候选统一按CPU降序，未知CPU置末。
   对照无法区分、UID编目或本进程路径覆盖不完整、超时、僵尸、PID复用及采样间断均不能确认差异；路径恢复或退出后清除该候选条件，编目变化重建连续观察。
   根 cgroup 和继承父进程 cgroup 的正常进程也可能没有独立 pid_N 路径；命名路径差异不等于没有内核 cgroup 归属。
   此线索不单独证明有效UID为0、root执行域或该进程使用GPU；原有root身份与高风险规则保持各自证据要求。
   已有root候选的本轮CPU样本即使为0，也可凭仍有效且身份一致的AVC证据留在同一列表；不复用旧UID/GPU信息，不延长30秒证据有效期。
   不借助外部 root 信息指定目标PID或UID，报告公开探测范围、校准对照和逐进程路径返回值；范围外保持未覆盖。
2. 对高 CPU 候选执行 stat(/proc/PID)，以自身 UID 直接从 logd 读取自己的 AVC 拒绝日志，关联目标路径和 tcontext，识别 su/magisk/zygisk/ksu 等 root 执行域。
   不执行 logcat 程序，不申请访问全设备日志。
   关联须通过来源进程、目标PID、探测时间窗口与持续身份验证；日志中的来源pid不作为目标pid。
3. 普通权限读取 KGSL memstore，以相邻窗口的 retired 计数判断全局 GPU 是否持续推进。
   实际 UID、进程元数据和按 PID 的 GPU 证据读不到时保持未知。
4. 默认阈值为单核 CPU 20%，间隔 2 秒，连续 3 次。多线程进程可超过 100%。
5. HIGH：目标的有效 AVC root 执行域证据 + 连续高 CPU + 全局 memstore 连续推进。
   这是组合风险启发式，保留 GPU 为全局观察，不冒充已确认按PID归属。
   SUSPECT（待核实线索）：只有持续高 CPU 且进程元数据不可访问，尚未满足组合规则。
6. 进程生命周期关联：仅比较进程开启、退出事件与 GPU 用户槽出现、停止推进的时序。
   开启事件来自基线后的新 pidfd 观察，退出事件必须有 pidfd 退出证据；保留连续采样、身份一致性与槽复用检查。
   排除槽0与参考KGSL布局尾部7个保留槽；缺失或异常采样重建尚未命中的观察窗口。
   命中时以红色显示“确认使用gpu悬浮窗”；此为界面状态名称，底层证据仍为生命周期时序关联。
   同一 PID 和身份标识的首次开启关联命中保留在本次检测中，不因30秒观察窗口过期、负载下降、槽变化或采样中断回退。
   已确认退出、PID 身份替换、明确的非 root 身份证据或新检测会清除该进程保留的开启关联结果。
   已移除 CPU/GPU 速率滚动相关计算、相关系数及对应展示；生命周期缓冲仅保留在本次检测内存中，停止后清空。
7. GPU 高频观察：同一用户槽的 retired 计数每秒推进至少30次，连续至少10秒且覆盖至少3个有效采样窗口时记录高频状态。
   按用户要求移除总览黄色高频总提示，原始报告继续保留槽位、速率、持续时间和自身槽过滤证据。
   各槽独立累计，不合并不同槽的速率；低于阈值、计数重置/回绕、槽复用、缺失采样或时间不连续会重建对应观察窗口。
   高频判定前在 App 进程内枚举已有的 /dev/kgsl-3d0 文件句柄，用 READTIMESTAMP（0xc00c0916，type=2）查询自身 owner 槽。
   查询覆盖完整用户槽范围，成功返回（包括 timestamp=0）才记为自身；临时 dup 固定原文件对象，查询结束立即关闭。
   排除当前及上一轮成功查询的自身槽，逐轮更新，避免槽号复用后永久屏蔽；查询缺失、不完整或过期时暂停高频提示。
   高频报告包含 selfGpuSlots 查询证据及 selfSlotsExcluded 名单；原始 memstore 数据和进程生命周期关联保持各自语义。
   这是整机槽位活动提示，速率单位是计数增量/秒，不是实测帧率；不分配给具体 PID，也不增加进程高风险数。

界面
开始/停止检测；查看实时候选和进程详情。CPU 使用内部默认阈值。
root候选和确认的cgroup路径异常进程合并在原有监听列表中，统一按CPU从高到低排列；不提供独立的cgroup入口、列表或监听服务。
统一候选列表和生命周期观察最多1024个进程，按CPU排序后截取，报告保留超出数量；列表卡片复用，避免每轮重新创建全部视图。
不提供告警历史、采集能力、保存报告、阈值设置或底部判定依据区域。
不再提供“查看全部 root 候选”开关；移除总览中的 AVC root 执行域说明和固定的英文权限提示。
全局 memstore 状态只在总览展示，进程卡片的 GPU 标签仅反映该 PID 的归属证据。
每张进程卡片的PID只显示一次；隐藏未知GPU归属标签，所有已采集到的AVC域均展示，包括非root域。
进程列表和界面计数排除本轮CPU负载小于0.2%的进程，达到0.2%后自动显示；未知CPU仍置末。
结果仅保存在当前检测的内存中，停止或切后台后清空，不恢复上次结果。
升级时清除旧版本留下的私有报告缓存。本应用、采集器及其他同 UID 进程均从候选中排除。
进程名或 UID 不可读取时，界面不根据测试对象的外部信息补造标签。

构建
JDK 17 或更新版本、Android SDK 35、NDK 29.0.13113456、Gradle 8.10.1。
在 local.properties 配置 sdk.dir，运行：
    .\gradlew.bat assembleDebug lintDebug --no-daemon
APK：app\build\outputs\apk\debug\app-debug.apk
当前原生 ABI：arm64-v8a；最低 Android 8.0（API 26）。

GitHub Actions 自动构建与发布
.github/workflows/build-release.yml 在每次分支或标签 push 后构建，也支持在 Actions 页面手动运行。
删除分支或标签不构建；连续 push 不取消之前的构建。
CI 使用 JDK 17、SDK 35、Build Tools 34.0.0、NDK 29.0.13113456 和仓库自带的 Gradle Wrapper。
执行 assembleDebug、assembleRelease、lintDebug；全部成功后直接发布到 GitHub Releases，不上传 Actions 构建物。
每次运行使用独立的 build-运行ID-重跑次数 标签，指向本次构建的提交，并发布为预发布版本，避免并发或重跑覆盖附件。
Release 附件：
    gpu-check-arm64-v8a-debug.apk：调试签名，可直接安装；不同运行使用临时调试证书，可能需要先卸载旧包再安装。
    gpu-check-arm64-v8a-release-unsigned.apk：未签名的 Release APK，安装前需要使用自己的证书签名。
    SHA256SUMS.txt：两个 APK 的 SHA-256 校验值。
发布使用工作流内置的 GITHUB_TOKEN（contents: write），不需要额外配置发布令牌。
下载地址：https://github.com/enenH/gpu-check/releases

纯 Java 规则测试
    .\scripts\test-policy.ps1
    .\scripts\test-avc.ps1
    .\scripts\test-lifecycle.ps1
    .\scripts\test-root-filter.ps1
    .\scripts\test-gpu-frequency.ps1
    .\scripts\test-self-gpu.ps1
    .\scripts\test-cgroup-watch.ps1
测试产物在 build 下对应的 *-tests 目录，不需要 Android 设备。

cgroup路径候选真机回归（仅测试APK包含模拟数据）
    .\gradlew.bat assembleDebug assembleDebugAndroidTest lintDebug '-PgpuCheckTestRunner=com.gpucheck.app.CgroupWatchInstrumentation' --no-daemon
    adb -s SERIAL install -r app\build\outputs\apk\debug\app-debug.apk
    adb -s SERIAL install -r app\build\outputs\apk\androidTest\debug\app-debug-androidTest.apk
    adb -s SERIAL shell am instrument -w -r com.gpucheck.app.test/com.gpucheck.app.CgroupWatchInstrumentation
    adb -s SERIAL uninstall com.gpucheck.app.test
在实际普通App域运行原生自测与5轮采样，验证stat路径通道可用和实际缺失证据；另用明确标记的模拟JSON验证连续确认、低/零CPU准入、身份更替、恢复和统一CPU排序。
模拟结果仅验证规则与接入，不作为正常真机发现了异常进程的证据。
历史成员扫描版本记录：build\cgroup-feature-device-test；该版本因无法读取成员文件而不可用，不代表新stat路径方法的检测结果。

自身槽过滤真机回归
    .\gradlew.bat assembleDebug assembleDebugAndroidTest lintDebug --no-daemon
    adb install -r app\build\outputs\apk\debug\app-debug.apk
    adb install -r app\build\outputs\apk\androidTest\debug\app-debug-androidTest.apk
    adb shell am instrument -w -r com.gpucheck.app.test/com.gpucheck.app.SelfGpuInstrumentation
    adb uninstall com.gpucheck.app.test
测试在普通 App UID 中创建临时 EGL 负载，验证实际自身高频活动被排除；另外使用模拟外部槽计数验证过滤没有关闭所有检测。
EGL 负载和检测器在测试结束时清理；负载代码仅在独立测试 APK 中，正式 APK 不包含。
2026-10-28：10轮完整查询，识别2个自身槽，单轮最长3ms，自身高频5轮被排除，模拟外部对照5轮命中。
记录：build\self-gpu-device-test\result.txt。

最新界面验收（2026-10-28，1.3.4）
进程列表和界面计数隐藏CPU负载小于0.2%的进程，达到0.2%后自动显示；未知CPU仍置末，空列表提示同步更新。
真机9份Service采样通过，7份UI快照过滤和排序一致，覆盖非零但小于0.2%的负载；停止及后台清理通过。
Debug/Release构建和Lint通过，已安装到CPH2415，回拉安装包与dist/GpuCheck.apk哈希一致；测试组件已清理。
记录：build\cpu-threshold-ui-test\report.txt；当前截图：dist\cpu-threshold-list-evidence.png。

历史界面验收（2026-10-28，1.3.3）
进程列表和界面计数隐藏CPU为0的进程，恢复活动后自动显示；内部身份及生命周期继续观察。
真机有界负载4轮零CPU均在界面隐藏，恢复后4轮重新显示；24份非空界面快照排序一致。
29份Service采样验证通过；Debug/Release构建、Lint和安装包哈希核对通过，测试组件已清理。
记录：build\zero-cpu-ui-test\report.txt；证据：build\live-device-test\zero-ui。

stat路径功能真机验收（2026-10-28，1.3.2）
stat/fstatat路径通道在普通UID10056/untrusted_app中可用；5轮原生自测采样和32组模拟JSON集成对照通过。
真实dfm_plus最终实例PID24961，自主检出16轮，15轮路径异常、14轮HIGH、15轮GPU生命周期开启关联；退出后约1.58秒从报告移除。
最终29轮Service路径通道全部完整可用，最多697个候选，无容量截断；cgroup平均444.67ms，整轮平均484.70ms。
另用两个真实root负载完成忙碌→零CPU→恢复→退出，4轮零CPU全部保留，排序及停止/后台清理通过。
监听与生命周期容量扩展为1024，并复用卡片，修复旧128条上限造成的遗漏及关联暂停。
界面PID去重，展示所有已采集AVC域（含非root）；移除未知GPU归属标签与高频总提示。27份实际UI快照核对通过。
240项Java回归、Debug/Release构建和Lint通过；最终安装包与dist/GpuCheck.apk哈希一致。
完整记录：build\cgroup-path-device-test\report.txt；真实DFM证据：build\live-device-test\stat-dfm-final。
测试实例、测试APK、临时文件及App私有测试结果均已清理。

历史真机验收（2026-10-28，1.3.1）
设备：OnePlus CPH2415，Android 15，arm64。
检测器：UID 10056，untrusted_app，Manifest 零权限；日志通过自身 UID 直连 logdr。
真实 dfm_plus：外部 adb shell su 启动后 PID 16335，独立exe/starttime核验，日志确认GPU初始化、游戏绑定和进入渲染循环。
App未接收目标PID，自主持续检出16轮，CPU约31.97–35.69%；AVC root域与全局GPU组合规则14轮HIGH，生命周期时序关联15轮命中。
身份核验后通过pidfd向本次新实例发送SIGTERM，确认退出；约1.53秒后的首份报告移除目标。此为终止测试，不是DFM菜单优雅退出。
所有GPU归属仍保留直接证据与时序线索的区别；本机cgroup通道权限受限，不能据此声称成员缺失阳性。
另用两个真实root负载进程跑忙碌→零CPU→忙碌→退出：修复前4轮零CPU全部漏出列表，修复后4轮全部保留；实际View与报告CPU排序一致。
同负载正式Service各28轮，cgroup平均91.21ms降至54.75ms，整轮平均134.32ms降至102.43ms；停止、重启及HOME退出清理通过。
原生自测、18组JSON集成对照、构建和Lint通过；服务报告使用真实安装版本，启动基线与快速失败显示已修复。
产物：dist\GpuCheck.apk、dist\dfm_plus-risk-report.json、dist\dfm_plus-evidence.png。
详细证据：build\live-device-test\report.txt，以及baseline-zero、fixed、dfm子目录。

真实目标测试
目标为 D:\WorkDir\clion4\dfm-plus-gongyi\user\cmake-build-debug\dfm_plus。
由测试者通过 adb shell 的 su 启动；该操作不是应用功能。
进程自身 daemon 化并会改变 comm，验收用 PID/实际 exe 路径和采样记录关联。
用于对照的 root shell 信息只保存为测试证据，不传入应用，也不参加应用风险判定。
本机原始测试数据在 build\device-test。
最新完整服务验收使用 app.test/com.gpucheck.app.ServiceDeviceInstrumentation；构建时传入
    '-PgpuCheckTestRunner=com.gpucheck.app.ServiceDeviceInstrumentation'
scripts/test-live-service.py 在正式界面建立基线后启动有界CPU负载；scripts/test-dfm-service.py 启动真实dfm_plus并做精确身份清理。
脚本使用的测试二进制在 build/live-device-test/bin，源码在 tests/device，不随正式APK发布。

资料
自身槽过滤方法依据：C:\Users\ITEK\Downloads\MRPCS\cp\KGSL_ENGINE_DEEP_ANALYSIS.html（当前进程已有fd与READTIMESTAMP owner检查）。
用户提供的两份 SG81 报告用于 CPU 时钟采样与证据边界分析；MRPCS 实验用于 GPU 观察和归属校验。
SG81 材料不提供已证实的通用高风险阈值。仅加载 EGL/GLES 库或观察到全局 GPU 计数不能证明某 PID 使用 GPU。
Android /proc 隐私和驱动策略因机型而异；应用显示能力缺口，未命中不代表安全。
