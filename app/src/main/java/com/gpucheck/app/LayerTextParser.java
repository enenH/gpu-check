package com.gpucheck.app;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class LayerTextParser {
    static final int MAX_ROWS = 1024;
    private static final Pattern LAYER = Pattern.compile("^\\s*Layer \\[(\\d+)\\] (.+)$");
    private static final Pattern TREE = Pattern.compile("^[ \\t│├└─]*([^\\r\\n]+?) (?:requestedFrameRate: .* )?pid=(\\d+) uid=(\\d+)(?: .*)?$");
    static final class Row {
        final String name;
        int pid = -1, uid = -1;
        Row(String name) { this.name = name; }
    }

    static List<Row> surfaceDump(String dump) {
        LinkedHashMap<String, Row> rows = new LinkedHashMap<>();
        String[] lines = dump.split("\\r?\\n");
        for (String line : lines) {
            Matcher match = LAYER.matcher(line);
            if (match.matches() && rows.size() < MAX_ROWS && match.group(2).length() <= 8192)
                rows.putIfAbsent(match.group(2), new Row(match.group(2)));
        }
        // Only exact full names connect two records from the same dump. #N is never a PID.
        for (String line : lines) {
            Matcher match = TREE.matcher(line);
            if (!match.matches()) continue;
            Row row = rows.get(match.group(1));
            if (row != null) {
                try { row.pid = Integer.parseInt(match.group(2)); row.uid = Integer.parseInt(match.group(3)); }
                catch (NumberFormatException ignored) { row.pid = -1; row.uid = -1; }
            }
        }
        return new ArrayList<>(rows.values());
    }

    static List<Row> nubiaList(String text) {
        LinkedHashMap<String, Row> rows = new LinkedHashMap<>();
        boolean recognizable = false;
        for (String line : text.split("\\r?\\n")) {
            String name = line.trim();
            if (name.isEmpty()) continue;
            if (name.length() > 8192 || name.toLowerCase(Locale.ROOT).matches("(?:error|permission denied|unknown (?:command|transaction)|unsupported|exception|failed)(?:[ :].*)?"))
                throw new IllegalArgumentException("Not a layer list");
            if (name.matches(".*#\\d+$") || !LayerNamePolicy.classify(name).suspicious) recognizable = true;
            if (rows.size() < MAX_ROWS) rows.putIfAbsent(name, new Row(name));
        }
        if (!rows.isEmpty() && !recognizable) throw new IllegalArgumentException("Unrecognized layer-list reply");
        return new ArrayList<>(rows.values());
    }
}
