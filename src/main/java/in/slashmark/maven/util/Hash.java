package in.slashmark.maven.util;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public final class Hash {
    private Hash() {}

    public static String hex(String algorithm, byte[] data) {
        try {
            return toHex(MessageDigest.getInstance(algorithm).digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String sha1Hex(byte[] d) { return hex("SHA-1", d); }
    public static String sha256Hex(byte[] d) { return hex("SHA-256", d); }
    public static String sha512Hex(byte[] d) { return hex("SHA-512", d); }
    public static String md5Hex(byte[] d) { return hex("MD5", d); }

    public static String sha256Hex(InputStream in) throws IOException {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) > 0) md.update(buf, 0, n);
            return toHex(md.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String toHex(byte[] b) {
        StringBuilder s = new StringBuilder(b.length * 2);
        for (byte x : b) s.append(Character.forDigit((x >> 4) & 0xF, 16)).append(Character.forDigit(x & 0xF, 16));
        return s.toString();
    }

    /** Checksum files may contain "hash  filename" or just the hash. */
    public static String parseChecksumFile(String text) {
        if (text == null) return null;
        String t = text.strip();
        int sp = 0;
        while (sp < t.length() && !Character.isWhitespace(t.charAt(sp))) sp++;
        String h = t.substring(0, sp).toLowerCase(java.util.Locale.ROOT);
        return h.matches("[0-9a-f]{32,128}") ? h : null;
    }
}
