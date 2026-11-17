package br.unoesc.cyber.client.token;

import static br.unoesc.cyber.client.support.TestTokens.NONCE;
import static br.unoesc.cyber.client.support.TestTokens.algNone;
import static br.unoesc.cyber.client.support.TestTokens.hs256WithPublicKey;
import static br.unoesc.cyber.client.support.TestTokens.rs256;
import static br.unoesc.cyber.client.support.TestTokens.tamperSignature;
import static br.unoesc.cyber.client.support.TestTokens.validClaims;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.Date;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import br.unoesc.cyber.client.support.MutableClock;
import br.unoesc.cyber.client.support.TestProperties;
import br.unoesc.cyber.client.support.TestTokens;

/**
 * Testes negativos obrigatórios do PDF §5 que dizem respeito ao ID Token (#1–#7 e #12).
 * Cada token parte de um ID Token VÁLIDO e altera um único aspecto; o teste de controle prova que
 * o mesmo token sem a alteração é aceito. Saída usada como evidência no relatório:
 * {@code ./mvnw -pl client-app test -Dtest=NegativeIdTokenTests}.
 */
@DisplayName("PDF §5 — testes negativos do ID Token")
class NegativeIdTokenTests {

    static final Instant NOW = Instant.parse("2026-11-26T12:00:00Z");
    final IdTokenValidator validator = new IdTokenValidator(TestProperties.props(), TestTokens.metadata(),
            TestTokens.jwks(TestTokens.KEY), new MutableClock(NOW));

    void rejected(String token, int checklistItem) {
        assertThatThrownBy(() -> validator.validate(token, NONCE))
                .isInstanceOf(IdTokenValidationException.class)
                .satisfies(e -> assertThat(((IdTokenValidationException) e).checklistItem()).isEqualTo(checklistItem));
    }

    @Test
    @DisplayName("Controle: o ID Token válido de referência é aceito")
    void controle_tokenValido_aceito() {
        assertThat(validator.validate(rs256(validClaims(NOW).build()), NONCE).sub()).isEqualTo(TestTokens.SUB);
    }

    @Test
    @DisplayName("#1 ID Token com alg \"none\" → rejeitado")
    void negativo01_algNone_rejeitado() {
        rejected(algNone(validClaims(NOW).build()), 2);
    }

    @Test
    @DisplayName("#2 ID Token reassinado em HS256 usando a chave pública como segredo → rejeitado")
    void negativo02_hs256ComChavePublica_rejeitado() {
        rejected(hs256WithPublicKey(validClaims(NOW).build()), 2);
    }

    @Test
    @DisplayName("#3 ID Token válido, mas com aud de outro client_id → rejeitado")
    void negativo03_audDeOutroCliente_rejeitado() {
        rejected(rs256(validClaims(NOW).audience("outro-client-id").claim("azp", "outro-client-id").build()), 4);
    }

    @Test
    @DisplayName("#4 ID Token com iss diferente do emissor → rejeitado")
    void negativo04_issDiferente_rejeitado() {
        rejected(rs256(validClaims(NOW).issuer("https://emissor-falso.example").build()), 3);
    }

    @Test
    @DisplayName("#5 ID Token com exp vencido → rejeitado")
    void negativo05_expVencido_rejeitado() {
        rejected(rs256(validClaims(NOW.minusSeconds(3600)).expirationTime(Date.from(NOW.minusSeconds(600))).build()), 6);
    }

    @Test
    @DisplayName("#6 ID Token com iat no futuro → rejeitado")
    void negativo06_iatNoFuturo_rejeitado() {
        rejected(rs256(validClaims(NOW).issueTime(Date.from(NOW.plusSeconds(3600)))
                .expirationTime(Date.from(NOW.plusSeconds(4500))).build()), 7);
    }

    @Test
    @DisplayName("#7 ID Token com nonce diferente do enviado → rejeitado")
    void negativo07_nonceDiferente_rejeitado() {
        rejected(rs256(validClaims(NOW).claim("nonce", "nonce-de-outra-sessao").build()), 8);
    }

    @Test
    @DisplayName("#12 Um byte alterado na assinatura do ID Token → rejeitado")
    void negativo12_byteAlteradoNaAssinatura_rejeitado() {
        rejected(tamperSignature(rs256(validClaims(NOW).build())), 1);
    }
}
