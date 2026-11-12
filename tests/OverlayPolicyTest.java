package com.gpucheck.app;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

public final class OverlayPolicyTest {
    private static int checks;
    public static void main(String[] args) throws Exception {
        for (String name : new String[]{"6frfg88tb3tj#594", "bbq-wrapper 6frfg88tb3tj#594#595",
                "[BBQ] aq69gt3janfi#173#174", "ImGui#5", "ESP overlay#8", "dfm_plus#9", "unexplained title#2",
                "StatusBarFake#1", "SurfaceView[random]#1", "SurfaceView#1", "Oplus random overlay#2",
                "bbq-wrapper mystery#4", "Splash Screen random#5", "StatusBar\u202E#1", "abc\nStatusBar#1"})
            check(LayerNamePolicy.classify(name).suspicious, "must flag " + name);
        for (String name : new String[]{"StatusBar#93", "e1208f7 OnScreenFingerprintDimLayer#142",
                "bbq-wrapper iconViewSurface#564#565", "[Gesture Monitor] OplusExInputReceiver1#97",
                "a7b7e87 com.tencent.tmgp.dfm/com.epicgames.ue4.GameActivity#587",
                "ActivityRecord{2e15cf3 u0 com.tencent.tmgp.dfm/com.epicgames.ue4.GameActivity t40}#566",
                "b38cdb0 ActivityRecordInputSink com.tencent.tmgp.dfm/com.epicgames.ue4.GameActivity#570",
                "Surface(name=a7b7e87 com.tencent.tmgp.dfm/com.epicgames.ue4.GameActivity)/@0xce0034c - animation-leash of starting_reveal#588",
                "WindowToken{a385eea type=2315 android.os.BinderProxy@6efe6d5}#148", "FullscreenMagnification:67:99#41",
                "SurfaceView[com.example.game/com.example.game.Main](BLAST)#55", "Splash Screen com.example.app#1",
                "Task=40#550", "NavigationBar_displayId_0#89", "home_task_overlay_container#55",
                "Caption of Task=11#329", "Handle Input Layer of task 11#338", "Taskbar#102", "ScreenDecorHwcOverlay#78", "Split Background Layer#59",
                "#55", "#173#174", "[BBQ] #55", "bbq-wrapper #55"})
            check(!LayerNamePolicy.classify(name).suspicious, "explain " + name);
        check(LayerNamePolicy.normalize("[BBQ] aq69gt3janfi#173#174").equals("aq69gt3janfi"), "wrapper deduplication");
        String ownComponent = "com.gpucheck.app/com.gpucheck.app.MainActivity";
        for (String name : new String[]{"VRI-" + ownComponent + "#", "VRI-" + ownComponent,
                "VRI-" + ownComponent + "#123", "[BBQ] VRI-" + ownComponent + "#123#124",
                "bbq-wrapper VRI-" + ownComponent + "#", "a12bc VRI-" + ownComponent + "#456",
                "Surface(name=VRI-" + ownComponent + ")/@0x1234 - animation-leash of starting_reveal#7"}) {
            check(!LayerNamePolicy.classify(name).suspicious, "filter VRI component " + name);
            check(LayerNamePolicy.normalize(name).startsWith("VRI-"), "retain VRI exclusion prefix " + name);
        }
        check(!LayerNamePolicy.classify("VRI-com.example.app/.MainActivity#").suspicious,
                "VRI exclusion covers other packages");
        for (String name : new String[]{"VRI-random#", "VRI-com.gpucheck.app#", "VRI-" + ownComponent + "#garbage",
                "VRI-" + ownComponent + "#12 extra", "VRI-" + ownComponent + "##", "VRI-" + ownComponent + "\u202e#",
                "VRI-com.example.app/com.example.app.ImGuiActivity#1", "VRI-ImGui#", "VRI-", "VRI-NotificationShade#19",
                "[BBQ] VRI-random#3#4", "bbq-wrapper VRI-ImGui#23", "VRI-外挂#1", "VRI-VRI-random#5"})
            check(!LayerNamePolicy.classify(name).suspicious, "filter every VRI title " + name);
        for (String name : new String[]{"prefix VRI-random#1", "notVRI-random#1", "vri-random#1", "VRI[random]#1", "random#1", "ImGui#1"})
            check(LayerNamePolicy.classify(name).suspicious, "only the exact leading VRI- prefix is excluded " + name);
        for (boolean utf8 : new boolean[]{false, true}) for (boolean header : new boolean[]{false, true}) {
            for (String value : new String[]{null, "", "StatusBar#5", "悬浮窗😀#42"}) {
                byte[] bytes = parcel(value, utf8, header);
                check(java.util.Objects.equals(value, LayerReplyDecoder.decode(bytes, utf8).value), "roundtrip");
            }
            byte[] valid = parcel("Hello#10", utf8, header);
            reject(Arrays.copyOf(valid, valid.length - 4), utf8);
            reject(Arrays.copyOf(valid, valid.length + 4), utf8);
            int offset = header ? 4 : 0;
            int payloadLength = utf8 ? "Hello#10".length() : "Hello#10".length() * 2;
            valid[offset + 4 + payloadLength] = 1;
            reject(valid, utf8);
        }
        reject(new byte[]{0, 0, 0}, false);
        reject(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putInt(-1).putInt(-1).array(), false);
        reject(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(Integer.MAX_VALUE).array(), true);
        byte[] broken = parcel("aa", false, false); broken[4] = 0; broken[5] = (byte) 0xd8; reject(broken, false);
        broken = parcel("aa", true, false); broken[4] = (byte) 0xc0; reject(broken, true);
        check(Arrays.equals(parcel("list_layer", true, false), LayerReplyDecoder.string8("list_layer")), "Nubia String8 command bytes");
        List<LayerTextParser.Row> nubia = LayerTextParser.nubiaList("StatusBar#1\nrandomname#2\nStatusBar#1\n");
        check(nubia.size() == 2 && nubia.get(1).pid == -1, "Nubia list dedup and no inferred PID");
        try { LayerTextParser.nubiaList("Permission denied"); throw new AssertionError("accepted error text"); }
        catch (IllegalArgumentException expected) { checks++; }
        String dump = "  Layer [174] [BBQ] random#173#174\n    visible reason=buffer\n"
                + " └─ [BBQ] random#173#174 pid=10190 uid=0\n  Layer [94] StatusBar#94\n"
                + " └─ StatusBar#94 pid=2770 uid=1000\n";
        List<LayerTextParser.Row> parsed = LayerTextParser.surfaceDump(dump);
        check(parsed.size() == 2 && parsed.get(0).pid == 10190 && parsed.get(0).uid == 0, "ZUI exact dump ownership");
        check(parsed.get(1).pid == 2770, "ZUI distinct owner");
        check(LayerTextParser.surfaceDump("Permission Denial: SurfaceFlinger").isEmpty(), "ZUI permission text is not a layer");
        check(LayerTextParser.surfaceDump("  Layer [55] random#55\n └─ other#55 pid=99 uid=0").get(0).pid == -1, "Never join by layer number alone");
        if (args.length == 1) {
            for (String name : java.nio.file.Files.readAllLines(java.nio.file.Path.of(args[0]))) {
                LayerNamePolicy.Decision decision = LayerNamePolicy.classify(name);
                if (decision.suspicious) System.out.println("CORPUS SUSPECT: " + name + " / " + decision.reason);
            }
        }
        System.out.println("OverlayPolicy: " + checks + " checks passed");
    }

    private static byte[] parcel(String value, boolean utf8, boolean header) {
        int h = header ? 4 : 0;
        if (value == null) return ByteBuffer.allocate(h + 4).order(ByteOrder.LITTLE_ENDIAN).putInt(h, -1).array();
        byte[] payload = value.getBytes(utf8 ? StandardCharsets.UTF_8 : StandardCharsets.UTF_16LE);
        byte[] result = new byte[h + 4 + ((payload.length + (utf8 ? 1 : 2) + 3) & ~3)];
        ByteBuffer.wrap(result).order(ByteOrder.LITTLE_ENDIAN).position(h).putInt(utf8 ? payload.length : value.length()).put(payload);
        return result;
    }

    private static void reject(byte[] bytes, boolean utf8) {
        try { LayerReplyDecoder.decode(bytes, utf8); throw new AssertionError("accepted malformed reply"); }
        catch (IllegalArgumentException expected) { checks++; }
    }
    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
}
