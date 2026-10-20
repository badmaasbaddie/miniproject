package passwordsecurity.core;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/** SHA-256, PBKDF2 and hex helpers built on the standard Java security APIs. */
public final class Hashing {

    public static final int PBKDF2_ITERATIONS = 10_000;
    public static final int PBKDF2_KEY_BITS = 256;

    private static final SecureRandom RANDOM = new SecureRandom();

    private Hashing() {}

    public static String sha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return toHex(md.digest(input.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available in this Java runtime", e);
        }
    }

    /** PBKDF2WithHmacSHA256, 10,000 iterations, 256-bit key, returned as hex. */
    public static String pbkdf2(char[] password, byte[] salt) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, PBKDF2_KEY_BITS);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return toHex(factory.generateSecret(spec).getEncoded());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("PBKDF2WithHmacSHA256 failure", e);
        } finally {
            spec.clearPassword();
        }
    }

    public static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }

    /** Constant-time comparison so verification time does not leak how many characters matched. */
    public static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    /** Number of differing bits between two equal-length hex digests (avalanche effect). */
    public static int bitDifference(String hexA, String hexB) {
        byte[] a = fromHex(hexA), b = fromHex(hexB);
        int diff = 0;
        for (int i = 0; i < Math.min(a.length, b.length); i++) {
            diff += Integer.bitCount((a[i] ^ b[i]) & 0xff);
        }
        return diff;
    }

    public static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    public static byte[] fromHex(String s) {
        byte[] data = new byte[s.length() / 2];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) ((Character.digit(s.charAt(2 * i), 16) << 4) + Character.digit(s.charAt(2 * i + 1), 16));
        }
        return data;
    }
}
