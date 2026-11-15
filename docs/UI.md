# GPU CHECK · 信号指挥舱

1.7.0 重新组织原生 Android 检测界面。所有数字来自本次采样；风险规则与原生采集路径保持原有语义。

## 页面结构

| 页面 | 内容 | 主要操作 |
| --- | --- | --- |
| 总览 | 实时状态、高风险进程数、监听进程 / 按进程 GPU 证据 / 最高 CPU，图层与全局 GPU 通道 | 查看图层、GPU 频率及环境异常依据，进入进程排行 |
| 进程 | CPU 前 10、排名、PID / UID、风险、CPU 分段条、AVC 与生命周期线索 | 打开进程详情，查看可选择复制的原始 JSON |
| 证据 | 会话状态、更新时刻、读取限制、全局 GPU、多槽观察、图层名称探测 | 打开各通道的完整原始依据 |

三个页面属于同一个 Activity，切换不会结束会话。开始 / 停止按钮固定在屏幕底部，各页单独保留滚动位置，屏幕旋转后恢复所选页面。

跨页告警条按图层名称、环境冲突、GPU 频率、高风险进程、采样限制的顺序展示当前最优先的入口。选择入口会打开对应证据或对应页面。详情面板在离开 Activity 时关闭，避免返回时继续显示已经清空的会话。

## 视觉系统

| 用途 | 色值 |
| --- | --- |
| 背景 | `#080C13` |
| 面板 | `#101924` |
| 结构线 | `#263242` |
| 主文字 | `#F3F5F7` |
| 次文字 | `#9BA9BB` |
| 主操作 / 青柠 | `#D6F58B` |
| 仪表 / 冰蓝 | `#80D8EB` |
| 风险告警 | `#FF777D` |
| 受限 / 待观察 | `#F6C879` |

采用系统无衬线字体与等宽数字；数字、状态和证据分层呈现。宽屏内容区限制宽度，窄屏或大字体时隐藏非必要仪表插画。按钮至少提供 48dp 操作区域。证据标题与正文一起滚动，关闭按钮固定，支持长进程名、大段 JSON 与横屏。

`SignalRadarView` 是固定几何的状态插画，无随机数据、健康评分或持续动画；仅在状态改变时重绘。`CpuLoadView` 根据真实单核口径 CPU 百分比绘制 16 段数据条，超过 100% 时条填满而数字保留真实值；未知值保持空轨与 `—`，不会作为零占用处理。

## 状态与生命周期

- 启动前展示待机，建立基线期间展示等待，不把缺失的样本当成安全结论。
- 原有高风险、root 观察、cgroup 异常、环境冲突、图层及 GPU 频率判定保持各自语义。
- 全局 GPU 活动仍明确标记为未归属任何 PID。
- 报告解析异常时清空旧指标、进程与通道状态，展示解析限制。
- 停止、离开界面时清空会话；GPU 频率告警继续独立检查有效期。
- 颜色之外保留文字状态；装饰图形不进入 TalkBack 阅读顺序。

## 构建

```sh
./gradlew --no-daemon :app:assembleDebug :app:assembleRelease :app:lintDebug
```

依赖版本及 SDK / NDK 安装要求见根目录 `README.txt`。

## UI 回归

新增 `DashboardUiInstrumentation` 用明确的 synthetic UI fixture 检查页面与状态，不启动真实采集器，不替代 ARM64 真机采集验收。Fixture 只存在于测试 APK。

```sh
./gradlew --no-daemon :app:assembleDebug :app:assembleDebugAndroidTest \
  -PgpuCheckTestRunner=com.gpucheck.app.DashboardUiInstrumentation
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb install -r app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
adb shell am instrument -w -r \
  com.gpucheck.app.test/com.gpucheck.app.DashboardUiInstrumentation
adb pull /sdcard/Android/data/com.gpucheck.app/files/ui-smoke ./ui-smoke
```

回归涵盖待机、真实字段映射、CPU 排序与自身 / 内核线程排除、页签切换保持会话、进程证据面板、解析错误后清空、无报告后恢复待机。截图文件明确标记 `ui-fixture`，仅用于布局检查。

正式 APK 仍仅包含 `arm64-v8a` 原生库；软件模拟器上的布局测试结果不能用于证明 KGSL、AVC、厂商 Binder 或真实进程探测在设备上可用。
