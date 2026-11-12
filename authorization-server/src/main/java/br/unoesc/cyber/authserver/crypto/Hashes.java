package br.unoesc.cyber.authserver.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

/** Utilitários criptográficos usados pelos endpoints OAuth. */
public final class Hashes {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    private Hashes() {
    }

    /** Valor aleatório em Base64URL com {@code bytes} de entropia (32 bytes = 256 bits). */
    public static String randomToken(SecureRandom random, int bytes) {
        byte[] buf = new byte[bytes];
        random.nextBytes(buf);
        return B64URL.encodeToString(buf);
    }

    /** SHA-256 em hexadecimal — forma em que codes e refresh tokens ficam no banco. */
    public static String sha256Hex(String value) {
        return HexFormat.of().formatHex(sha256(value));
    }

    /** BASE64URL(SHA256(ASCII(value))) — transformação S256 do PKCE (RFC 7636 §4.2). */
    public static String s256(String value) {
        return B64URL.encodeToString(sha256(value));
    }

    /** Comparação em tempo constante. */
    public static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] sha256(String value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.US_ASCII));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
