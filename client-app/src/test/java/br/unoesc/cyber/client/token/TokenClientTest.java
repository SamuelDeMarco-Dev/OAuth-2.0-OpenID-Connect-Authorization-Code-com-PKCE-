package br.unoesc.cyber.client.token;

import static br.unoesc.cyber.client.support.TestProperties.CLIENT_ID;
import static br.unoesc.cyber.client.support.TestProperties.CLIENT_SECRET;
import static br.unoesc.cyber.client.support.TestProperties.ISSUER;
import static br.unoesc.cyber.client.support.TestProperties.REDIRECT_URI;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.ExpectedCount.once;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withBadRequest;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withException;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.net.SocketTimeoutException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestClient;

import br.unoesc.cyber.client.support.TestProperties;
import br.unoesc.cyber.client.support.TestTokens;

class TokenClientTest {

    MockRestServiceServer server;
    TokenClient client;

    @BeforeEach
    void setUp() {
        RestClient.Builder builder = RestClient.builder();
        server = MockRestServiceServer.bindTo(builder).build();
        client = new TokenClient(builder.build(), TestTokens.metadata(), TestProperties.props());
    }

    @Test
    void enviaFormularioComClientSecretBasicEDevolveTokens() {
        var form = new LinkedMultiValueMap<String, String>();
        form.add("grant_type", "authorization_code");
        form.add("code", "c0de");
        form.add("redirect_uri", REDIRECT_URI);
        form.add("code_verifier", "v3rifier");
        server.expect(once(), requestTo(ISSUER + "/token"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("Authorization", TokenClient.basic(CLIENT_ID, CLIENT_SECRET)))
                .andExpect(content().formData(form))
                .andRespond(withSuccess("""
                        {"access_token":"at","token_type":"Bearer","expires_in":900,"id_token":"idt","refresh_token":"rt"}
                        """, MediaType.APPLICATION_JSON));
        TokenSet t = client.exchange("c0de", "v3rifier");
        assertThat(t.accessToken()).isEqualTo("at");
        assertThat(t.idToken()).isEqualTo("idt");
        assertThat(t.toString()).doesNotContain("at").doesNotContain("idt");
        server.verify();
    }

    @Test
    void recusaDoProvedorNaoERepetida() {
        server.expect(once(), requestTo(ISSUER + "/token"))
                .andRespond(withBadRequest().body("{\"error\":\"invalid_grant\"}").contentType(MediaType.APPLICATION_JSON));
        assertThatThrownBy(() -> client.exchange("c", "v")).isInstanceOf(TokenExchangeException.class);
        server.verify(); // exatamente uma requisição
    }

    @Test
    void timeoutViraErroControladoSemNovaTentativa() {
        server.expect(once(), requestTo(ISSUER + "/token")).andRespond(withException(new SocketTimeoutException("timeout")));
        assertThatThrownBy(() -> client.exchange("c", "v")).isInstanceOf(TokenExchangeException.class)
                .hasMessageContaining("indisponível");
        server.verify();
    }

    @Test
    void respostaSemIdTokenRecusada() {
        server.expect(requestTo(ISSUER + "/token"))
                .andRespond(withSuccess("{\"access_token\":\"at\",\"token_type\":\"Bearer\"}", MediaType.APPLICATION_JSON));
        assertThatThrownBy(() -> client.exchange("c", "v")).isInstanceOf(TokenExchangeException.class);
    }

    @Test
    void basicCodificaCaracteresEspeciais() {
        assertThat(TokenClient.basic("a:b", "s&p=c")).isEqualTo("Basic "
                + java.util.Base64.getEncoder().encodeToString("a%3Ab:s%26p%3Dc".getBytes()));
    }
}
