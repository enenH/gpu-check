package com.gpucheck.app;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** Reads an exact static-final int from current, readable OEM framework DEX files.
 * No class initialization, hidden-API exemption, guessed transaction, or bytecode execution.
 * Format reference: https://source.android.com/docs/core/runtime/dex-format */
final class OemDexConstants {
    private static final int MAX_DEX_BYTES = 64 * 1024 * 1024;
    private static final int MAX_TOTAL_BYTES = 128 * 1024 * 1024;
    private static final int MAX_FILES = 8, MAX_DEX_ENTRIES = 32, MAX_DEPTH = 16;
    private static final ConcurrentHashMap<String, Integer> RESOLVED = new ConcurrentHashMap<>();

    private OemDexConstants() { }

    static int resolve(String className, String fieldName, String... paths) throws IOException {
        if (className == null || fieldName == null || paths == null || paths.length > MAX_FILES) return -1;
        StringBuilder key = new StringBuilder(className).append('#').append(fieldName);
        for (String path : paths) {
            if (path == null) continue;
            File file = new File(path);
            key.append('|').append(path).append(':').append(file.length()).append(':').append(file.lastModified());
        }
        Integer cached = RESOLVED.get(key.toString());
        if (cached != null) return cached;
        String descriptor = "L" + className.replace('.', '/') + ";";
        int found = -1, files = 0, entries = 0, total = 0;
        for (String path : paths) {
            if (path == null || ++files > MAX_FILES) break;
            File file = new File(path);
            // The caller supplies only built-in ROM paths. Do not load user-writable jars.
            String canonical = file.getCanonicalPath();
            if (!(canonical.startsWith("/system/framework/") || canonical.startsWith("/system_ext/framework/")
                    || canonical.startsWith("/product/framework/") || canonical.startsWith("/vendor/framework/"))) continue;
            if (!file.isFile() || !file.canRead()) continue;
            try (ZipFile zip = new ZipFile(file)) {
                Enumeration<? extends ZipEntry> all = zip.entries();
                int visited = 0;
                while (all.hasMoreElements() && visited++ < 1024) {
                    ZipEntry entry = all.nextElement();
                    if (!entry.getName().matches("classes(?:[2-9]|[1-9][0-9]+)?\\.dex")) continue;
                    if (++entries > MAX_DEX_ENTRIES) throw new IOException("OEM DEX entry budget exceeded");
                    long size = entry.getSize();
                    if (size < 112 || size > MAX_DEX_BYTES || size > MAX_TOTAL_BYTES - total)
                        throw new IOException("OEM DEX size budget exceeded");
                    byte[] data;
                    try (InputStream input = zip.getInputStream(entry)) { data = readBounded(input, (int) size); }
                    total += data.length;
                    int value = fromDex(data, descriptor, fieldName);
                    if (value > 0) {
                        if (found > 0 && found != value) throw new IOException("Conflicting OEM transaction constants");
                        found = value;
                    }
                }
            }
        }
        // Successful constants remain valid while the current ROM files are unchanged.
        // Avoid rereading tens of megabytes of framework DEX on every sampling round.
        if (found > 0 && RESOLVED.size() < 64) RESOLVED.put(key.toString(), found);
        return found;
    }

    private static byte[] readBounded(InputStream input, int expected) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(Math.min(expected, 65536));
        byte[] chunk = new byte[16384];
        int count;
        while ((count = input.read(chunk)) != -1) {
            if (count > expected - out.size()) throw new IOException("OEM DEX expanded beyond declared size");
            out.write(chunk, 0, count);
        }
        if (out.size() != expected) throw new IOException("Truncated OEM DEX");
        return out.toByteArray();
    }

    /** Also used by synthetic parser checks; offsets are never trusted before bounds checking. */
    static int fromDex(byte[] bytes, String descriptor, String fieldName) throws IOException {
        if (bytes == null || bytes.length < 112 || bytes.length > MAX_DEX_BYTES) throw new IOException("Invalid DEX size");
        int header = 0, found = -1, logicalFiles = 0;
        do {
            if (++logicalFiles > 32) throw new IOException("DEX container budget exceeded");
            Dex dex = new Dex(bytes, header);
            int value = dex.find(descriptor, fieldName);
            if (value > 0) {
                if (found > 0 && found != value) throw new IOException("Conflicting DEX constants");
                found = value;
            }
            if (!dex.container) {
                if (header != 0 || dex.fileSize != bytes.length) throw new IOException("Invalid standalone DEX length");
                break;
            }
            header += dex.fileSize;
        } while (header < bytes.length);
        if (header > bytes.length) throw new IOException("Invalid DEX container end");
        return found;
    }

    private static final class Dex {
        final byte[] data;
        final int header, fileSize, strings, stringOffset, types, typeOffset, fields, fieldOffset, classes, classOffset;
        final boolean container;

        Dex(byte[] data, int header) throws IOException {
            this.data = data; this.header = header;
            range(header, 112);
            if (data[header] != 'd' || data[header + 1] != 'e' || data[header + 2] != 'x'
                    || data[header + 3] != '\n' || data[header + 7] != 0) throw new IOException("Unsupported DEX magic");
            String version = new String(data, header + 4, 3, StandardCharsets.US_ASCII);
            if (!(version.equals("035") || version.equals("037") || version.equals("038")
                    || version.equals("039") || version.equals("040") || version.equals("041")))
                throw new IOException("Unsupported DEX version");
            container = version.equals("041");
            fileSize = uint(header + 32);
            int headerSize = uint(header + 36);
            if (headerSize != (container ? 120 : 112) || fileSize < headerSize || uint(header + 40) != 0x12345678)
                throw new IOException("Invalid DEX header");
            range(header, fileSize);
            if (container && (uint(header + 112) != data.length || uint(header + 116) != header))
                throw new IOException("Invalid DEX container header");
            strings = uint(header + 56); stringOffset = uint(header + 60);
            types = uint(header + 64); typeOffset = uint(header + 68);
            fields = uint(header + 80); fieldOffset = uint(header + 84);
            classes = uint(header + 96); classOffset = uint(header + 100);
            table(strings, stringOffset, 4, 2000000); table(types, typeOffset, 4, 65536);
            table(fields, fieldOffset, 8, 65536); table(classes, classOffset, 32, 65536);
        }

        int find(String descriptor, String name) throws IOException {
            int result = -1;
            for (int i = 0; i < classes; i++) {
                int definition = classOffset + i * 32;
                int classIndex = uint(definition);
                if (!descriptor.equals(type(classIndex))) continue;
                int classData = uint(definition + 24), values = uint(definition + 28);
                if (classData == 0 || values == 0) return -1;
                Cursor declarations = new Cursor(classData);
                int staticCount = declarations.uleb();
                if (staticCount > fields) throw new IOException("Invalid DEX static field count");
                declarations.uleb(); declarations.uleb(); declarations.uleb();
                int target = -1, index = 0;
                for (int f = 0; f < staticCount; f++) {
                    int delta = declarations.uleb();
                    if (delta > fields - index || (f > 0 && delta == 0)) throw new IOException("Invalid DEX field delta");
                    index += delta;
                    if (index >= fields) throw new IOException("Invalid DEX field index");
                    int access = declarations.uleb(), field = fieldOffset + index * 8;
                    if (ushort(field) != classIndex) throw new IOException("DEX field class mismatch");
                    if (name.equals(string(uint(field + 4))) && "I".equals(type(ushort(field + 2)))
                            && (access & 0x18) == 0x18) target = f;
                }
                if (target < 0) return -1;
                Cursor encoded = new Cursor(values);
                int count = encoded.uleb();
                if (count > staticCount) throw new IOException("Invalid DEX static value count");
                if (target >= count) return -1; // Unencoded fields have the default zero value.
                for (int v = 0; v <= target; v++) {
                    int value = encoded.value(v == target, 0);
                    if (v == target && value > 0 && value < 0x00ffffff) result = value;
                }
            }
            return result;
        }

        void table(int size, int offset, int width, int limit) throws IOException {
            if (size > limit || (size == 0 && offset != 0) || (size > 0 && offset < header + (container ? 120 : 112)))
                throw new IOException("Invalid DEX table");
            if (size > 0) range(offset, size * width);
        }
        void range(int offset, int count) throws IOException {
            if (offset < 0 || count < 0 || offset > data.length - count) throw new IOException("DEX range outside file");
        }
        int uint(int offset) throws IOException {
            range(offset, 4);
            long value = (data[offset] & 255L) | (data[offset + 1] & 255L) << 8
                    | (data[offset + 2] & 255L) << 16 | (data[offset + 3] & 255L) << 24;
            if (value > Integer.MAX_VALUE) throw new IOException("DEX unsigned value exceeds budget");
            return (int) value;
        }
        int ushort(int offset) throws IOException { range(offset, 2); return (data[offset] & 255) | (data[offset + 1] & 255) << 8; }
        String type(int index) throws IOException {
            if (index < 0 || index >= types) throw new IOException("Invalid DEX type index");
            return string(uint(typeOffset + index * 4));
        }
        String string(int index) throws IOException {
            if (index < 0 || index >= strings) throw new IOException("Invalid DEX string index");
            Cursor cursor = new Cursor(uint(stringOffset + index * 4));
            int length = cursor.uleb();
            if (length > 4096) return ""; // An exact class/field name cannot be this long.
            int begin = cursor.at;
            for (int n = 0; n <= 12288; n++) {
                int b = cursor.next();
                if (b == 0) return new String(data, begin, cursor.at - begin - 1, StandardCharsets.UTF_8);
            }
            throw new IOException("Unterminated DEX identifier");
        }

        final class Cursor {
            int at, valuesRead;
            Cursor(int at) throws IOException { range(at, 1); this.at = at; }
            int next() throws IOException { range(at, 1); return data[at++] & 255; }
            int uleb() throws IOException {
                long value = 0;
                for (int i = 0; i < 5; i++) {
                    int b = next(); value |= (long) (b & 127) << (7 * i);
                    if ((b & 128) == 0) {
                        if (value > Integer.MAX_VALUE) throw new IOException("DEX LEB128 exceeds budget");
                        return (int) value;
                    }
                }
                throw new IOException("Invalid DEX LEB128");
            }
            int value(boolean target, int depth) throws IOException {
                if (depth > MAX_DEPTH || ++valuesRead > 65536) throw new IOException("DEX value budget exceeded");
                int packed = next(), kind = packed & 31, argument = packed >>> 5;
                if (kind == 0x1e || kind == 0x1f) {
                    if (argument > (kind == 0x1f ? 1 : 0)) throw new IOException("Invalid DEX null/boolean");
                    return -1;
                }
                if (kind == 0x1c || kind == 0x1d) {
                    if (argument != 0) throw new IOException("Invalid DEX composite value");
                    if (kind == 0x1d) uleb();
                    int count = uleb();
                    if (count > 65536) throw new IOException("DEX composite value budget exceeded");
                    for (int i = 0; i < count; i++) { if (kind == 0x1d) uleb(); value(false, depth + 1); }
                    return -1;
                }
                int max = kind == 0 ? 0 : (kind == 2 || kind == 3) ? 1 : (kind == 6 || kind == 0x11) ? 7
                        : (kind == 4 || kind == 0x10 || (kind >= 0x15 && kind <= 0x1b)) ? 3 : -1;
                if (argument > max || max < 0) throw new IOException("Invalid DEX encoded value");
                int bytes = argument + 1, bits = 0;
                for (int i = 0; i < bytes; i++) { int b = next(); if (i < 4) bits |= b << (i * 8); }
                if (!target || kind != 4) return -1;
                return bytes == 4 ? bits : bits << (32 - bytes * 8) >> (32 - bytes * 8);
            }
        }
    }
}
