package com.gpucheck.app;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Name explanations are heuristics, not authenticated owners or a trusted package list. */
final class LayerNamePolicy {
    private static final String PACKAGE = "[A-Za-z_][A-Za-z0-9_]*(?:\\.[A-Za-z_][A-Za-z0-9_]*)+";
    private static final String COMPONENT = PACKAGE + "/\\.?[A-Za-z_$][A-Za-z0-9_.$]*";
    private static final Pattern APP = Pattern.compile("(?:" + COMPONENT + "|" + PACKAGE + ")");
    private static final Pattern LEASH = Pattern.compile("Surface\\(name=(.+)\\)/@0x[0-9a-fA-F]+(?: - (?:animation-leash of [a-z_]+|rotation-leash)|_transition-leash)");
    private static final Pattern SYSTEM = Pattern.compile("(?:StatusBar|NavigationBar(?:_displayId_\\d+)?|NotificationShade|InputMethod(?:Dialog)?|ScreenDecorOverlay(?:Bottom)?|ColorSideGesture(?:Left|Right)_displayId_\\d+|OnScreenFingerprint(?:DimLayer|Icon|PressedIcon)|Wallpaper BBQ wrapper|iconViewSurface|SurfaceControlViewHost|home_task_overlay_container|Dim layer|DefaultTaskDisplayArea|ImeContainer|Display Overlays|Input Overlays|Accessibility Overlays|ShellDropTarget|FlexibleDropTarget|Input Consumer recents_animation_input_consumer)");
    private static final Pattern STRUCTURE = Pattern.compile("(?:Task=\\d+|(?:Leaf|OneHanded|FullscreenMagnification|WindowedMagnification|HideDisplayCutout|ImePlaceholder):\\d+:\\d+|Display \\d+ name=\"[^\"\\r\\n]+\"|WindowToken\\{[0-9a-f]+ type=\\d+ (?:android\\.os\\.Binder(?:Proxy)?|android\\.window\\.WindowTokenClient)@[0-9a-f]+\\}|WallpaperWindowToken\\{[0-9a-f]+ token=android\\.os\\.Binder@[0-9a-f]+ showWhenLocked=(?:true|false)\\}|\\[Gesture Monitor\\] (?:OplusExInputReceiver\\d+|OplusUAHInputChannel|swipe-up|edge-swipe)|\\(\\d+-\\d+\\)-Window\\{[0-9a-f]+ alpha=[0-9.]+ fl=[0-9a-f]*\\})");

    static final class Decision {
        final String name, reason;
        final boolean suspicious;
        Decision(String name, boolean suspicious, String reason) {
            this.name = name; this.suspicious = suspicious; this.reason = reason;
        }
    }

    static Decision classify(String raw) {
        if (raw == null || raw.trim().isEmpty()) return new Decision("", false, "empty");
        if (raw.length() > 8192) return new Decision(raw, true, "名称超出长度限制");
        String name = normalize(raw);
        // User-selected exclusion applies to every VRI- title, not only components.
        if (name.startsWith("VRI-")) return new Decision(name, false, "已过滤 VRI- 前缀图层");
        if (raw.codePoints().anyMatch(c -> Character.isISOControl(c)
                || Character.getType(c) == Character.FORMAT)) return new Decision(raw, true, "名称包含异常控制字符");
        if (name.isEmpty()) return new Decision("", false, "仅图层编号，未提供可判断的名称");
        String lower = name.toLowerCase(Locale.ROOT);
        if (lower.contains("imgui") || lower.contains("dfm_plus") || lower.contains("aimbot")
                || lower.contains("wallhack") || lower.matches(".*(?:^|[ _-])(?:esp|cheat)(?:[ _-].*|$)")
                || name.contains("外挂") || name.contains("自瞄") || name.contains("透视"))
            return new Decision(name, true, "名称含可疑绘制或外挂关键词");
        if (APP.matcher(name).matches()) return new Decision(name, false, "应用包名或组件格式（未验证归属）");
        if (SYSTEM.matcher(name).matches() || STRUCTURE.matcher(name).matches()
                || name.matches("(?:Taskbar|ScreenDecorHwcOverlay|Split Background Layer|Caption of Task=\\d+|Handle Input Layer of task \\d+)"))
            return new Decision(name, false, "已知系统图层名称格式（未验证归属）");
        if (name.matches("ActivityRecord\\{[0-9a-f]+ u\\d+ " + COMPONENT + " t\\d+(?: d\\d+)?\\}"))
            return new Decision(name, false, "ActivityRecord 容器格式");
        return new Decision(name, true, "无法解释的图层名称");
    }

    static String normalize(String raw) {
        String value = raw.trim();
        for (int i = 0; i < 8; i++) {
            String before = value;
            value = value.replaceFirst("(?:#\\d+)+$", "").replaceFirst("^[0-9a-fA-F]{1,8} ", "");
            if (value.startsWith("bbq-wrapper ")) value = value.substring(12);
            else if (value.startsWith("[BBQ] ")) value = value.substring(6);
            else if (value.startsWith("ActivityRecordInputSink ")) value = value.substring(24);
            else if (value.startsWith("Splash Screen ")) value = value.substring(14);
            else {
                Matcher leash = LEASH.matcher(value);
                if (leash.matches()) value = leash.group(1);
                else if (value.matches("SurfaceView\\[" + COMPONENT + "\\](?:\\(BLAST\\))?"))
                    value = value.substring(12, value.indexOf(']'));
                else if (value.matches("SurfaceView - " + COMPONENT)) value = value.substring(14);
            }
            value = value.trim();
            if (value.equals(before)) break;
        }
        return value;
    }
}
