package com.gpucheck.app;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/** Recovered Oplus String16 and Nubia String8 wire formats; never guess a scalar as a name. */
final class LayerReplyDecoder {
    static final int MAX_BYTES = 1024 * 1024;
    static final class Decoded {
        final String value, mode;
        Decoded(String value, String mode) { this.value = value; this.mode = mode; }
    }

    static Decoded decode(byte[] bytes, boolean string8) {
        int limit = string8 ? MAX_BYTES : 65536;
        if (bytes == null || bytes.length < 4 || bytes.length > limit || (bytes.length & 3) != 0)
            throw new IllegalArgumentException("Invalid reply length");
        try { return new Decoded(at(bytes, 0, string8), "raw"); }
        catch (IllegalArgumentException raw) {
            if (integer(bytes, 0) != 0) throw raw;
            return new Decoded(at(bytes, 4, string8), "exception_header");
        }
    }

    private static int integer(byte[] bytes, int offset) {
        if (offset > bytes.length - 4) throw new IllegalArgumentException("Truncated length");
        return ByteBuffer.wrap(bytes, offset, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
    }

    private static String at(byte[] bytes, int offset, boolean string8) {
        int length = integer(bytes, offset);
        if (length == -1 && bytes.length - offset == 4) return null;
        if (length < 0 || length > (string8 ? MAX_BYTES - 8 : 8192))
            throw new IllegalArgumentException("String length out of range");
        int width = string8 ? 1 : 2;
        int payload = length * width;
        int size = 4 + ((payload + width + 3) & ~3);
        if (bytes.length - offset != size) throw new IllegalArgumentException("Truncated string or trailing bytes");
        for (int i = 0; i < width; i++) {
            if (bytes[offset + 4 + payload + i] != 0) throw new IllegalArgumentException("Missing terminator");
        }
        try {
            return (string8 ? StandardCharsets.UTF_8 : StandardCharsets.UTF_16LE).newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes, offset + 4, payload)).toString();
        } catch (CharacterCodingException error) { throw new IllegalArgumentException("Malformed Unicode", error); }
    }

    static byte[] string8(String command) {
        byte[] text = command.getBytes(StandardCharsets.UTF_8);
        byte[] bytes = new byte[(text.length + 8) & ~3];
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putInt(text.length).put(text);
        return bytes;
    }
}
