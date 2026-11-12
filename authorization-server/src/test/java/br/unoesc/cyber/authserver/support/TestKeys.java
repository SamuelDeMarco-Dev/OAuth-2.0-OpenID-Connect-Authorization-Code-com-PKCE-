package br.unoesc.cyber.authserver.support;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/** Gera chaves RSA de teste em arquivos temporários (nenhuma chave é versionada). */
public final class TestKeys {

    private TestKeys() {
    }

    public static KeyPair generate() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            return gen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static Path writePrivatePem(KeyPair kp) {
        return write("PRIVATE KEY", kp.getPrivate().getEncoded());
    }

    public static Path writePublicPem(KeyPair kp) {
        return write("PUBLIC KEY", kp.getPublic().getEncoded());
    }

    private static Path write(String type, byte[] der) {
        try {
            Path file = Files.createTempFile("test-key-", ".pem");
            file.toFile().deleteOnExit();
            String b64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der);
            Files.writeString(file, "-----BEGIN " + type + "-----\n" + b64 + "\n-----END " + type + "-----\n");
            return file;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
