package br.unoesc.cyber.authserver.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.SecureRandom;

import org.junit.jupiter.api.Test;

class HashesTest {

    @Test
    void s256ConfereComVetorDoRfc7636() {
        assertThat(Hashes.s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
                .isEqualTo("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    @Test
    void tokenAleatorioTem256Bits() {
        SecureRandom r = new SecureRandom();
        String a = Hashes.randomToken(r, 32);
        assertThat(a).hasSize(43).matches("[A-Za-z0-9_-]+").isNotEqualTo(Hashes.randomToken(r, 32));
    }

    @Test
    void comparacaoConstante() {
        assertThat(Hashes.constantTimeEquals("abc", "abc")).isTrue();
        assertThat(Hashes.constantTimeEquals("abc", "abd")).isFalse();
        assertThat(Hashes.constantTimeEquals(null, "abc")).isFalse();
    }
}
