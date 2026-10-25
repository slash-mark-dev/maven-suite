package in.slashmark.maven.mock;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * Produces structurally valid OpenPGP v4 signature packets (RFC 4880) for fixture artifacts: creation
 * time, issuer fingerprint and issuer key id are real; the RSA value is filler (tests only read the
 * metadata, they do not verify signatures cryptographically).
 */
public final class Pgp {
    private Pgp() {}

    public static byte[] fingerprint(String keyIdHex) throws Exception {
        byte[] id = hex(keyIdHex);
        byte[] h = MessageDigest.getInstance("SHA-1").digest(keyIdHex.getBytes(StandardCharsets.US_ASCII));
        byte[] fp = new byte[20];
        System.arraycopy(h, 0, fp, 0, 12);
        System.arraycopy(id, 0, fp, 12, 8);
        return fp;
    }

    public static String armoredSignature(String keyIdHex, byte[] data, long timeMillis) {
        try {
            byte[] fp = fingerprint(keyIdHex);
            ByteArrayOutputStream body = new ByteArrayOutputStream();
            body.write(4);      // version
            body.write(0x00);   // binary document signature
            body.write(1);      // RSA
            body.write(8);      // SHA-256
            ByteArrayOutputStream hashed = new ByteArrayOutputStream();
            hashed.write(5);
            hashed.write(2); // creation time
            int t = (int) (timeMillis / 1000);
            hashed.write(t >>> 24);
            hashed.write(t >>> 16);
            hashed.write(t >>> 8);
            hashed.write(t);
            hashed.write(22);
            hashed.write(33); // issuer fingerprint
            hashed.write(4);
            hashed.write(fp);
            byte[] hb = hashed.toByteArray();
            body.write(hb.length >>> 8);
            body.write(hb.length);
            body.write(hb);
            ByteArrayOutputStream unhashed = new ByteArrayOutputStream();
            unhashed.write(9);
            unhashed.write(16); // issuer key id
            unhashed.write(hex(keyIdHex));
            byte[] ub = unhashed.toByteArray();
            body.write(ub.length >>> 8);
            body.write(ub.length);
            body.write(ub);
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
            body.write(digest[0]);
            body.write(digest[1]);
            byte[] mpi = new byte[256];
            System.arraycopy(digest, 0, mpi, 0, digest.length);
            mpi[0] |= (byte) 0x80;
            body.write(2048 >>> 8);
            body.write(2048 & 0xFF);
            body.write(mpi);
            byte[] b = body.toByteArray();
            ByteArrayOutputStream pkt = new ByteArrayOutputStream();
            pkt.write(0xC2); // new format, tag 2
            if (b.length < 192) pkt.write(b.length);
            else {
                int l = b.length - 192;
                pkt.write((l >> 8) + 192);
                pkt.write(l & 0xFF);
            }
            pkt.write(b);
            byte[] packet = pkt.toByteArray();
            String b64 = Base64.getEncoder().encodeToString(packet);
            StringBuilder s = new StringBuilder("-----BEGIN PGP SIGNATURE-----\n\n");
            for (int i = 0; i < b64.length(); i += 64) s.append(b64, i, Math.min(b64.length(), i + 64)).append('\n');
            int crc = crc24(packet);
            byte[] c = {(byte) (crc >> 16), (byte) (crc >> 8), (byte) crc};
            s.append('=').append(Base64.getEncoder().encodeToString(c)).append('\n');
            s.append("-----END PGP SIGNATURE-----\n");
            return s.toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static int crc24(byte[] d) {
        int crc = 0xB704CE;
        for (byte b : d) {
            crc ^= (b & 0xFF) << 16;
            for (int i = 0; i < 8; i++) {
                crc <<= 1;
                if ((crc & 0x1000000) != 0) crc ^= 0x1864CFB;
            }
        }
        return crc & 0xFFFFFF;
    }

    static byte[] hex(String h) {
        byte[] b = new byte[h.length() / 2];
        for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(h.substring(i * 2, i * 2 + 2), 16);
        return b;
    }
}
