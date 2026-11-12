package br.unoesc.cyber.authserver.jwk;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/** Leitura de chaves RSA em PEM (PKCS#8 privada / X.509 pública) sem dependências extras. */
final class PemKeys {

    private PemKeys() {
    }

    static RSAPrivateCrtKey readPrivateKey(Path path) {
        byte[] der = decode(path, "PRIVATE KEY");
        try {
            return (RSAPrivateCrtKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (GeneralSecurityException | ClassCastException e) {
            throw new IllegalStateException("Chave privada RSA PKCS#8 inválida em " + path, e);
        }
    }

    static RSAPublicKey readPublicKey(Path path) {
        byte[] der = decode(path, "PUBLIC KEY");
        try {
            return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
        } catch (GeneralSecurityException | ClassCastException e) {
            throw new IllegalStateException("Chave pública RSA inválida em " + path, e);
        }
    }

    static RSAPublicKey publicKeyOf(RSAPrivateCrtKey privateKey) {
        try {
            return (RSAPublicKey) KeyFactory.getInstance("RSA")
                    .generatePublic(new RSAPublicKeySpec(privateKey.getModulus(), privateKey.getPublicExponent()));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] decode(Path path, String type) {
        String pem;
        try {
            pem = Files.readString(path);
        } catch (IOException e) {
            throw new UncheckedIOException("Não foi possível ler a chave em " + path
                    + " (rode scripts/gen-dev-secrets.sh)", e);
        }
        String begin = "-----BEGIN " + type + "-----";
        String end = "-----END " + type + "-----";
        int from = pem.indexOf(begin);
        int to = pem.indexOf(end);
        if (from < 0 || to < 0) {
            throw new IllegalStateException("PEM sem bloco '" + type + "' em " + path);
        }
        return Base64.getMimeDecoder().decode(pem.substring(from + begin.length(), to));
    }
}
