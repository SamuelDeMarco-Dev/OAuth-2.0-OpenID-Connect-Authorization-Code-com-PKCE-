package br.unoesc.cyber.client.token;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;

import org.junit.jupiter.api.Test;

import br.unoesc.cyber.client.support.TestTokens;

class IdTokenInspectorTest {

    IdTokenInspector inspector = new IdTokenInspector();

    @Test
    void decompoeAsTresPartes() {
        String jwt = TestTokens.rs256(TestTokens.validClaims(Instant.now()).build());
        var d = inspector.decompose(jwt);
        assertThat(d.header()).contains("\"alg\":\"RS256\"").contains("\"kid\":\"" + TestTokens.KID + "\"");
        assertThat(d.payload()).contains("\"sub\":\"" + TestTokens.SUB + "\"").contains("\"nonce\"")
                .contains("\"role\":\"admin\"").contains("\n");
        assertThat(d.signature()).isEqualTo(jwt.substring(jwt.lastIndexOf('.') + 1));
    }

    @Test
    void tokenMalformadoNaoQuebraOFluxo() {
        assertThat(inspector.decompose("abc")).isNull();
        assertThat(inspector.decompose("a.b!.c")).isNull();
        assertThat(inspector.decompose(null)).isNull();
    }
}
