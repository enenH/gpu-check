GPU Check — Android 用户态进程风险检测

权限边界
应用及其原生采集器以普通应用 UID 运行，不调用 su，不使用 adb/Shizuku/root 辅助服务，不启动测试目标。
Manifest 不声明任何权限；不申请通知、存储或读取全设备日志权限。
仅声明 com.zui.SecretCode 的包可见性查询，不按机型或品牌属性跳过悬浮窗检测路线。
仅在检测界面可见期间采样，离开界面自动停止。无前台服务或通知。

检测方式
1. 使用 Linux 按 PID 的进程 CPU 时钟差分持续监听所有可发现的外部进程，包括普通应用、系统进程及零负载进程。
   排除本应用、原生采集器、同UID的其他进程及这些进程的全部线程；每轮采集前后刷新PID/TID排除集合，清除对应CPU样本、基线和生命周期事件。
   同时通过 FUTEX_TRYLOCK_PI 排除确认的内核线程：每轮在本进程临时字上执行无锁、自身、存活普通线程及无效TID对照。
   校准有效且同一held-pidfd身份在调用前后均存活时，EPERM确认内核线程，EAGAIN确认用户态线程；其余结果保持未知。
   只移除确认的内核线程，未知结果继续保留；CPU列表、样本及监听计数同步过滤，原始报告保留被排除PID及逐次证据。
   AVC目标域严格为kernel，但同一身份的futex结果确认是用户态线程时，总览和对应进程行立即红字显示“环境异常”。
   该异常要求AVC身份匹配且证据未过期；不提升root/高风险计数，证据消失、过期、身份变化或检查未知时清除。
   此检查只使用普通App权限，不读取目标内存，不调用su；临时字每次重新初始化，成功加锁时配对解锁。
   CPU 监听不再要求 root 身份、cgroup 路径异常或最低负载，不再按128/1024个进程截断；页面只显示CPU最高的10个。
   自动使用可读的pid_max作为探测范围；有界扫描超时后下轮从游标继续，已发现及/proc可见PID每轮重新采样。
   不可读取的CPU和新进程基线显示未知，退出进程移除；报告保留本轮扫描是否完整与探测范围，不能发现的进程仍属于能力缺口。
   现有候选同时接收 cgroup 命名路径差异线索：使用 stat/fstatat 的返回值探测 /proc/PID 和参考 UID/PID 目录，不要求读取 cgroup 目录或成员文件。
   对现代 /sys/fs/cgroup/uid_N/pid_P 及旧式 apps/system 布局执行自身正对照和 uid_/pid_ 不存在对照，自主建立有界 UID 目录编目。
   返回0表示存在；经对照验证可区分不存在时，EACCES仅作为存在性线索；只有明确的ENOENT才计为路径未匹配。
   同一存活进程须有前后有效pidfd身份，本轮已校准范围内的所有候选路径均未匹配，连续3次才标记cgroup路径异常。
   这些进程沿用同一进程列表、CPU采样与GPU生命周期观察，零CPU也可准入；所有候选统一按CPU降序，未知CPU置末。
   对照无法区分、UID编目或本进程路径覆盖不完整、超时、僵尸、PID复用及采样间断均不能确认差异；路径恢复或退出后清除该候选条件，编目变化重建连续观察。
   根 cgroup 和继承父进程 cgroup 的正常进程也可能没有独立 pid_N 路径；命名路径差异不等于没有内核 cgroup 归属。
   此线索不单独证明有效UID为0、root执行域或该进程使用GPU；原有root身份与高风险规则保持各自证据要求。
   CPU样本即使为0也持续保留；root身份标记仍要求有效证据，不复用旧UID/GPU信息，不延长30秒AVC证据有效期。
   不借助外部 root 信息指定目标PID或UID，报告公开探测范围、校准对照和逐进程路径返回值；范围外保持未覆盖。
2. 对高 CPU 候选执行 stat(/proc/PID)，以自身 UID 直接从 logd 读取自己的 AVC 拒绝日志，关联目标路径和 tcontext，识别 su/magisk/zygisk/ksu 等 root 执行域。
   不执行 logcat 程序，不申请访问全设备日志。
   关联须通过来源进程、目标PID、探测时间窗口与持续身份验证；日志中的来源pid不作为目标pid。
3. 普通权限读取 KGSL memstore，以相邻窗口的 retired 计数判断全局 GPU 是否持续推进。
   全局 active 与逐槽分析统一使用通过有效性校验的差值；首次出现、异常跳变及无效时间窗口不累计活动。报告包含 activityKnown/comparableSlots；无可比较差值时显示未知。
   实际 UID、进程元数据和按 PID 的 GPU 证据读不到时保持未知。
4. 默认阈值为单核 CPU 20%，间隔 2 秒，连续 3 次。多线程进程可超过 100%。
5. HIGH：目标的有效 AVC root 执行域证据 + 连续高 CPU + 全局 memstore 连续推进。
   这是组合风险启发式，保留 GPU 为全局观察，不冒充已确认按PID归属。
   SUSPECT（待核实线索）：只有持续高 CPU 且进程元数据不可访问，尚未满足组合规则。
6. 进程生命周期关联：仅比较进程开启、退出事件与 GPU 用户槽出现、停止推进的时序。
   开启事件来自基线后的新 pidfd 观察，退出事件必须有 pidfd 退出证据；保留连续采样、身份一致性与槽复用检查。
   排除槽0与参考KGSL布局尾部7个保留槽；缺失或异常采样重建尚未命中的观察窗口。
   命中时以黄色显示“GPU 活动时序吻合 · 归属待核实”；底层证据为生命周期时序关联，不证明 GPU 所有权或悬浮窗行为。
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
8. 悬浮窗名称检测：每次开始检测均实际探测 layerinfo 中的 Oplus（一加/OPPO/realme）、红魔/Nubia、联想/ZUI 三条路线。
   不读取 Build.BRAND、MANUFACTURER、MODEL 或 ROM 属性决定是否调用；机型字段只用于原有设备信息展示。
   Oplus：普通 App JNI 取得 SurfaceFlinger，校验 android.ui.ISurfaceComposer，调用 0x6f696665 查询 String16 名称。
   每轮最多256次名称查询，通用片段及字符搜索不接收外部目标名；有界扩展队列跨轮继续，之前可疑名称每轮重新查询。
   轮换查询数字与非十六进制字母的组合，减少正常窗口随机hash遮住单字符搜索时的漏检；该字符表不含目标名称。
   前后唯一不存在查询必须为空，非空回复必须包含查询子串；严格验证长度、终止符、Unicode及尾余，异常回复不当成名称。
   红魔/Nubia：分别实际尝试交易77和73的 list_layer，按恢复代码写入UTF-8 String8（不是Java writeString）。
   校验String8回复并按行解析名称；不需要改变 select_layer 诊断选择或执行 latency_layer 才能判断名称。
   联想/ZUI：检查真实 BootCompleteReceiver 的可调用性，发送初始化和 collectlog 广播，在本应用独占的外部文件目录接收日志。
   每次最多等待30秒，同一检测会话完成后至少60秒才再次触发，跨会话也有60秒请求冷却；仅解析 SurfaceFlinger 文本，限制2MiB，完成后清理本次临时目录。
   厂商 collectlog 自身还会清理/移动部分诊断文件（/data/misc/*.hprof、iplog、dumpsys临时目录），不是纯只读系统调用；应用不直接操作这些路径。
   停止后不再发布结果；已经提交的厂商日志请求可能继续完成，后台只等待收尾并清理本次目录。
   三条路线各有独立且全App限额的工作线程，同步Binder超时不会阻塞CPU监听或产生无限新线程；旧结果到期后标为不可用。
   名称含可疑绘制关键词，或无法解释为已知系统结构/应用组件格式时，首次命中即在顶部以黄色显示“可疑图层名称 · 待核实”；不将名称线索表述为恶意行为确认。
   仅有#编号、去掉包装后没有实际名称的记录表示名称缺失，不把图层编号当成未知悬浮窗名称；真实的未知名称仍立即标红。
   按用户要求，剥离已有BBQ/leash等包装后，所有VRI-开头的名称均不触发悬浮窗告警，原始名称及过滤原因保留在报告中。
   VRI-过滤不要求包名/Activity格式，也优先于可疑关键词检测；其他名称继续按原规则检测，前缀严格区分大小写。
   展示原始名称与原因，包装图层按规范化名称去重；不是等待CPU/GPU组合条件，也不虚增原有进程高风险数。
   已知名称仅是格式解释，不是经过认证的白名单；名字可伪装，未知名称也可能属于正常软件，结论属于用户指定的名称启发式。
   Oplus/Nubia名称回复不含PID/UID，#后缀不是PID；ZUI仅在同一份dump中用完整名称精确连接明确的pid/uid字段。
   原始报告的overlay.routes保留实际响应状态、查询证据、范围及时间；接口缺失、拒绝、畸形回复、超时和未发现名称分别记录。
   子串枚举与文本解析均有覆盖范围限制；其他路线不可用时不会显示“安全”或当作已扫描全部图层。

界面
开始/停止检测；查看全进程CPU排行和进程详情。风险规则使用内部默认阈值，CPU监听本身不设最低负载。
持续采样所有可发现的外部进程，排除自身后最多显示10个，统一按CPU从高到低排列，同CPU按PID升序，未知CPU置末。
监听总数和风险计数覆盖完整采样结果；前10之外的进程仍持续采样，负载上升后可自动进入排行。
CPU列表无固定数量截断；GPU生命周期观察仍仅针对root/cgroup异常候选，容量1024，超出数量独立报告，不截断CPU数据。列表卡片复用。
不提供告警历史、阈值设置或底部判定依据区域。支持用户主动导出当前完整 JSON 快照，包含榜外进程、接口状态、覆盖范围和原始证据。
打开系统文件选择器前冻结内存中的快照；离开界面仍停止采集。取消保存即丢弃该导出快照，不自动保存报告；进程被系统回收后需重新采样。
不再提供“查看全部 root 候选”开关；移除总览中的 AVC root 执行域说明和固定的英文权限提示。
全局 memstore 状态只在总览展示，进程卡片的 GPU 标签仅反映该 PID 的归属证据。
每张进程卡片的PID只显示一次；隐藏未知GPU归属标签，所有已采集到的AVC域均展示，包括非root域。
不再隐藏CPU低于0.2%的进程；不足10个时也可显示低负载、零CPU和未知CPU进程。
除用户主动导出的文件外，结果仅保存在当前检测的内存中，停止或切后台后清空，不恢复上次结果。
升级时清除旧版本留下的私有报告缓存。本应用、采集器及其他同UID进程与线程不参与CPU监听、排行或总数统计，也不参与root/cgroup风险认定。
进程名或 UID 不可读取时，界面不根据测试对象的外部信息补造标签。

构建
JDK 17–23（推荐17或21）、Android SDK 35、默认NDK 29.0.13113456、Gradle 8.10.1。
可通过 -PgpuCheckNdkVersion=已安装版本 指定本机构建使用的NDK。
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
跨平台证据回归（JDK、C++17 编译器及 org.json 运行时 JAR）：
    python scripts/test-evidence.py --json-jar PATH_TO_ORG_JSON_JAR
此命令不需要 Android 设备；完整 Android 构建和真机验收仍需单独执行。
检测依据、样本分析边界和前一轮修复见 docs/DETECTION_REVIEW.md。
本轮 SG81 参考扩展见 docs/SG81_COVERAGE.md：元数据 4 个轮询名额 + CPU 优先，连续两轮复查；
直接读取的 SELinux 双路标签与 AVC 交叉验证后进入既有组合规则；保留来源、错误码和覆盖计数。
本轮仅完成主机回归及 Java/API 编译，未构建 APK、运行 lint 或进行真机验收；下文已有真机记录为历史基线。

    .\scripts\test-policy.ps1
    .\scripts\test-avc.ps1
    .\scripts\test-lifecycle.ps1
    .\scripts\test-root-filter.ps1
    .\scripts\test-gpu-frequency.ps1
    .\scripts\test-self-gpu.ps1
    .\scripts\test-cgroup-watch.ps1
    .\scripts\test-overlay.ps1
测试产物在 build 下对应的 *-tests 目录，不需要 Android 设备。

联想/ZUI悬浮窗真机回归
    .\gradlew.bat assembleDebug assembleDebugAndroidTest lintDebug '-PgpuCheckTestRunner=com.gpucheck.app.ServiceDeviceInstrumentation' --no-daemon
    python -X utf8 scripts/test-overlay-lenovo.py --serial SERIAL --seconds 110
测试APK创建真实的普通应用附属窗口，并检查：实际ZUI采集命中随机标题、页面红字与标题、移除窗口后下一轮新采集不再返回该标题。
随机标题只用于创建窗口和测试断言，不传给正式检测器；不需要SYSTEM_ALERT_WINDOW。目标窗口与测试APK代码不随正式APK发布。
脚本保存窗口存在/消失时独立ADB SurfaceFlinger记录；当前ZUI禁用run-as，因此主机侧su仅用于取回测试回执和检查临时目录。
App本身保持普通UID、untrusted_app、CapEff=0，无清单权限，不以这些外部记录参与检测。
未开启overlay_fixture参数时，ServiceDeviceInstrumentation沿用普通Service/UI回归，不创建任何测试窗口。

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

VRI前缀统一过滤（2026-11-13，1.5.4）
按用户要求将所有VRI-开头的名称从悬浮窗告警中过滤，保留原始名称及明确过滤原因；不再限定完整组件格式。
115项主机回归、27项Binder协议对照、Debug/Release构建及Lint通过；一加6份真实Service/UI采样，验证问题0。
测试APK及App私有回执已清理，1.5.4已安装到一加，dist\GpuCheck.apk与设备包哈希一致。本次未操作联想。
记录：build\vri-prefix-filter。

VRI图层名称误报修复（2026-11-13，1.5.3）
修复VRI-com.gpucheck.app/com.gpucheck.app.MainActivity#被当成未知悬浮窗的问题；完整VRI组件包装及空#后缀可正常解析。
103项主机回归、25项测试APK Binder协议对照、Debug/Release构建及Lint通过；一加真实Service/UI共9份采样、0验证问题。
精确VRI名称由明确标记的Binder对照验证，本轮真实采集未返回该条目；未知名称、畸形后缀及可疑关键词检测保留。
测试组件与私有回执已清理，1.5.3已安装到一加，dist\GpuCheck.apk与设备包哈希一致。本次未操作联想。
记录：build\vri-overlay-fix。

内核线程过滤与AVC kernel域校验（2026-11-13，1.5.2）
一加CPH2415、Android15、5.10.209内核：普通App UID10056/untrusted_app/CapEff=0。
正式Service/UI验证13份真实采样，每轮排除681–683个futex确认的内核线程，保留304个用户态进程。
校准、同一held-pidfd前后存活、CPU样本与列表过滤、监听计数、停止/重启/后台清理均通过。
另有3轮普通App原生采集，每轮排除673个内核线程；主机独立/proc前后核验覆盖每轮656个内核及301个用户态PID，零冲突。
56项明确标记的模拟规则检查通过：kernel域与用户态结果冲突、过期AVC、身份更换、退出、未知错误、校准失败及CPU-only合并等。
实际View检查确认总览及进程行红字“环境异常”、冲突AVC红字和恢复后复用行清除；这些阳性是测试输入，不代表真机发现该异常。
Debug/Release构建、Lint及现有规则回归通过；测试APK已卸载，完整证据保留在build\kernel-thread-feature-test。
复现：使用ServiceDeviceInstrumentation运行完整界面验收；-e kernel_checks_only true可在锁屏下执行规则与原生采集验收。
本次修改与验收仅操作一加，不操作联想设备。安装包：dist\GpuCheck.apk。

联想/ZUI真机验收（2026-11-12，1.5.1）
TB322FC、Android16：正式检测器以UID10274/untrusted_app/CapEff=0完成真实ZUI采集；三条ROM路线仍全部实际探测。
首轮54份采样通过，两次ZUI采集各14个图层、约15秒完成且临时文件清理成功；修复只有#55编号、无实际名称的系统容器误报。
修正版59份采样和真实窗口生命周期验证通过：测试APK创建gpc_fixture_d9699138b268窗口，正式检测器自主命中并红字显示。
同一dump精确解析其PID14067/UID10274；独立SurfaceFlinger记录确认同名窗口，移除后新一轮采集不再返回该标题。
该窗口为实际渲染的应用附属测试窗口，不是DFM实例，也不是向检测器注入模拟JSON或目标名；窗口及测试代码仅在测试APK中。
停止、重启、切后台清理通过；80项主机规则检查、22项协议检查、Debug/Release构建及Lint通过。
当前固件禁用run-as，主机su仅用于回执导出和目录核验，App未增加权限；无线ADB导出曾出现退出码255，App内PASS回执单独保留。
证据：build\overlay-lenovo-device-test\initial及fixture；安装包：dist\GpuCheck.apk。

悬浮窗名称检测验收（2026-11-12，1.5.0）
Oplus、红魔/Nubia、联想/ZUI均已实现实际能力探测；不按品牌、型号或ROM属性跳过。
CPH2415普通App UID10056实测自主命中6frfg88tb3tj#594，顶部红字“外挂悬浮窗”和名称、依据弹窗均核验。
三路真实结果：Oplus可用；红魔77被拒绝、73回复不兼容；ZUI组件不存在。这不是对其他ROM成功调用的真机声明。
最终16份正式Service报告、真实View红字检查、停止/重启/切后台清理通过；Oplus每轮最多256次名称查询，本轮最长264ms。
76项主机规则/解码检查、22项测试APK协议检查及原有Java规则回归通过；协议检查含单字符被正常图层遮挡、组合搜索与目标消失。
原Oplus33个名称回放仅随机目标名命中；原ZUI实机dump回放解析16个名称，悬浮窗及其明确pid/uid精确核对通过，属于离线回放。
Debug/Release构建和Lint通过（0错误，含受控ServiceManager反射回退的兼容性警告）；设备安装包与dist/GpuCheck.apk的SHA-256一致。
原始String16回复另经主机独立解码，与独立ADB SurfaceFlinger记录核对；外部目标名和PID没有传给检测器。
完整记录：build\overlay-device-test\delivery；回归修复前的遮挡记录：build\overlay-device-test\masked-before。
当前安装包：dist\GpuCheck.apk；截图：dist\overlay-evidence.png；验证回执：dist\overlay-verification.json。

自身进程与线程排除验收（2026-11-12，1.4.1）
CPU采集前后动态枚举本应用、采集器、同UID进程及其task/TID，排除样本、基线和生命周期事件；Java处理与UI另按App PID、采集器PID、UID过滤。
排除后从全部外部进程中选择CPU前10，自身不计入监听总数；不固定使用历史PID 6210。
19项规则回归、原生自测和34组JSON集成对照通过；普通App域5轮采样验证额外同UID进程8369持续存活且始终被排除，辅助进程结束后已清理。
正式Service/UI共12份报告和12份非空UI快照，无验证问题；每轮监听955–956个外部进程，排除27–28个自身PID/TID，页面最多10个。
停止、重启和切后台清理通过；Debug构建及Lint通过（0错误）。1.4.1已安装到CPH2415，安装包与dist/GpuCheck.apk哈希一致。
证据：build\self-exclusion-device-test；测试组件与设备测试文件已清理。

历史全进程CPU与前10界面验收（2026-11-12，1.4.0）
移除CPU采集的负载门槛、128/1024行截断和root/cgroup准入限制；本应用和采集器也参与CPU采样。
页面最多显示10个，CPU降序、同值PID升序、未知置末；总览计数覆盖全部监听进程。
240项Java回归、原生自测及33组集成对照通过，包含1200个普通进程、零负载、低负载、身份更替和榜外进程负载升高后进入前10。
CPH2415普通App域5轮原生采样通过；最终正式Service/UI验证14份报告、13份非空UI快照，无验证问题。
正式Service监听998–1000个进程，SurfaceFlinger连续14轮存在；界面最多10张卡片，停止/重启/切后台清理通过。
Debug构建与Lint通过（0错误）；本次使用JDK17.0.21及NDK30.0.14904198，默认NDK版本仍可按构建配置选择。
版本1.4.0已安装到CPH2415，回拉APK与dist/GpuCheck.apk的SHA-256一致；测试组件和设备测试文件已清理。
证据：build\all-process-device-test；当前APK：dist\GpuCheck.apk。

历史界面验收（2026-10-28，1.3.4）
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
悬浮窗协议来源：D:\libDump\12\dfm\mrcps\MRPCS\as\android_probe\layerinfo.md；
同目录 work\dfm-overlay-oneplus-20261112（Oplus实机源码/回复）、work\dfm-overlay-20261112（ZUI实机源码/dump）；
原DEX注释：D:\libDump\12\dfm\mrcps\v4\mrpcs_as_analysis\deep34\evidence\activity\oem_bridge.annotated.txt。
红魔 V.A/V.D/V.s/V.u 对应只读取名的 String8 list_layer 路线，两个固定交易号来自 V.<clinit>。
自身槽过滤方法依据：C:\Users\ITEK\Downloads\MRPCS\cp\KGSL_ENGINE_DEEP_ANALYSIS.html（当前进程已有fd与READTIMESTAMP owner检查）。
用户提供的两份 SG81 报告用于 CPU 时钟采样与证据边界分析；MRPCS 实验用于 GPU 观察和归属校验。
SG81 材料不提供已证实的通用高风险阈值。仅加载 EGL/GLES 库或观察到全局 GPU 计数不能证明某 PID 使用 GPU。
Android /proc 隐私和驱动策略因机型而异；应用显示能力缺口，未命中不代表安全。
