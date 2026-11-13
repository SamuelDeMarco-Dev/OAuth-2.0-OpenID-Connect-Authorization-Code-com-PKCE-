package br.unoesc.cyber.client.token;

import static br.unoesc.cyber.client.support.TestTokens.NONCE;
import static br.unoesc.cyber.client.support.TestTokens.algNone;
import static br.unoesc.cyber.client.support.TestTokens.hs256WithPublicKey;
import static br.unoesc.cyber.client.support.TestTokens.rs256;
import static br.unoesc.cyber.client.support.TestTokens.tamperSignature;
import static br.unoesc.cyber.client.support.TestTokens.validClaims;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.nimbusds.jwt.JWTClaimsSet;

import br.unoesc.cyber.client.support.MutableClock;
import br.unoesc.cyber.client.support.TestProperties;
import br.unoesc.cyber.client.support.TestTokens;

/** Um teste por linha do checklist §4.3 (itens 1–8). Os testes nomeados pelo §5 ficam na issue #19. */
class IdTokenValidatorTest {

    static final Instant NOW = Instant.parse("2026-11-26T12:00:00Z");
    MutableClock clock = new MutableClock(NOW);
    IdTokenValidator validator = new IdTokenValidator(TestProperties.props(), TestTokens.metadata(),
            TestTokens.jwks(TestTokens.KEY), clock);

    void rejected(String token, int item) {
        assertThatThrownBy(() -> validator.validate(token, NONCE))
                .isInstanceOf(IdTokenValidationException.class)
                .satisfies(e -> assertThat(((IdTokenValidationException) e).checklistItem()).isEqualTo(item));
    }

    @Test
    void tokenValidoAprovadoComEvidenciaDeCadaItem() {
        ValidatedIdToken t = validator.validate(rs256(validClaims(NOW).build()), NONCE);
        assertThat(t.sub()).isEqualTo(TestTokens.SUB);
        assertThat(t.issuer()).isEqualTo(TestProperties.ISSUER);
        assertThat(t.role()).isEqualTo("admin");
        assertThat(t.emailVerified()).isTrue();
        assertThat(t.evidence()).hasSize(8).anySatisfy(e -> assertThat(e).startsWith("#1"))
                .anySatisfy(e -> assertThat(e).startsWith("#8"));
    }

    @Test
    void item1_assinaturaAlteradaRejeitada() {
        rejected(tamperSignature(rs256(validClaims(NOW).build())), 1);
    }

    @Test
    void item1_kidDesconhecidoEErro() {
        rejected(rs256(validClaims(NOW).build(), TestTokens.generate("outro-kid")), 1);
    }

    @Test
    void item1_chaveDeOutroEmissorComMesmoKidRejeitada() {
        rejected(rs256(validClaims(NOW).build(), TestTokens.generate(TestTokens.KID)), 1);
    }

    @Test
    void item2_algNoneRejeitado() {
        rejected(algNone(validClaims(NOW).build()), 2);
    }

    @Test
    void item2_hs256ComChavePublicaComoSegredoRejeitado() {
        rejected(hs256WithPublicKey(validClaims(NOW).build()), 2);
    }

    @Test
    void item2_listaDeAlgoritmosSoAceitaRsa() {
        var props = TestProperties.props();
        var hs = new br.unoesc.cyber.client.config.OidcClientProperties(props.issuer(), props.clientId(),
                props.clientSecret(), props.redirectUri(), props.scopes(), List.of("HS256"), props.clockSkew(),
                props.httpTimeout(), null, null, props.session());
        assertThatThrownBy(() -> new IdTokenValidator(hs, TestTokens.metadata(), TestTokens.jwks(), clock))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void item3_issDiferenteRejeitado() {
        rejected(rs256(validClaims(NOW).issuer("https://evil.example").build()), 3);
        rejected(rs256(validClaims(NOW).issuer(TestProperties.ISSUER + "/").build()), 3);
    }

    @Test
    void item4_audDeOutroClienteRejeitado() {
        rejected(rs256(validClaims(NOW).audience("outro-cliente").claim("azp", null).build()), 4);
    }

    @Test
    void item5_audMultiploSemAzpRejeitado() {
        rejected(rs256(validClaims(NOW).audience(List.of(TestProperties.CLIENT_ID, "outro")).claim("azp", null).build()), 5);
    }

    @Test
    void item5_azpDeOutroClienteRejeitado() {
        rejected(rs256(validClaims(NOW).audience(List.of(TestProperties.CLIENT_ID, "outro")).claim("azp", "outro").build()), 5);
    }

    @Test
    void item5_audMultiploComAzpCorretoAceito() {
        assertThat(validator.validate(rs256(validClaims(NOW)
                .audience(List.of(TestProperties.CLIENT_ID, "outro")).build()), NONCE).sub()).isEqualTo(TestTokens.SUB);
    }

    @Test
    void item6_expVencidoRejeitadoRespeitandoTolerancia() {
        JWTClaimsSet c = validClaims(NOW.minusSeconds(1000)).expirationTime(Date.from(NOW.minusSeconds(30))).build();
        assertThat(validator.validate(rs256(c), NONCE)).as("dentro da tolerância de 60 s").isNotNull();
        clock.advance(Duration.ofSeconds(31));
        rejected(rs256(c), 6);
    }

    @Test
    void item7_iatNoFuturoRejeitado() {
        rejected(rs256(validClaims(NOW).issueTime(Date.from(NOW.plusSeconds(300))).build()), 7);
    }

    @Test
    void item8_nonceDiferenteRejeitado() {
        rejected(rs256(validClaims(NOW).claim("nonce", "outro-nonce").build()), 8);
        assertThatThrownBy(() -> validator.validate(rs256(validClaims(NOW).build()), null))
                .isInstanceOf(IdTokenValidationException.class);
    }

    @Test
    void lixoRejeitado() {
        rejected("nao.e.jwt", 1);
        rejected(null, 1);
    }
}
