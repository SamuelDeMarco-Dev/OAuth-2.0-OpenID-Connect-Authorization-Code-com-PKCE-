package br.unoesc.cyber.client.token;

import static br.unoesc.cyber.client.support.TestProperties.ISSUER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withUnauthorizedRequest;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import br.unoesc.cyber.client.discovery.ProviderUnavailableException;
import br.unoesc.cyber.client.support.TestTokens;

class UserInfoClientTest {

    MockRestServiceServer server;
    UserInfoClient client;

    @BeforeEach
    void setUp() {
        RestClient.Builder builder = RestClient.builder();
        server = MockRestServiceServer.bindTo(builder).build();
        client = new UserInfoClient(builder.build(), TestTokens.metadata());
    }

    @Test
    void subIgualAoDoIdTokenAprovado() {
        server.expect(requestTo(ISSUER + "/userinfo")).andExpect(header("Authorization", "Bearer at-123"))
                .andRespond(withSuccess("{\"sub\":\"sub-123\",\"name\":\"Joao\"}", MediaType.APPLICATION_JSON));
        assertThat(client.fetchAndCheck("at-123", "sub-123")).containsEntry("name", "Joao");
    }

    @Test
    void item10_subDiferenteRejeitado() {
        server.expect(requestTo(ISSUER + "/userinfo"))
                .andRespond(withSuccess("{\"sub\":\"outro-sub\"}", MediaType.APPLICATION_JSON));
        assertThatThrownBy(() -> client.fetchAndCheck("at", "sub-123"))
                .isInstanceOf(IdTokenValidationException.class)
                .satisfies(e -> assertThat(((IdTokenValidationException) e).checklistItem()).isEqualTo(10));
    }

    @Test
    void tokenRecusadoPeloProvedorInterrompeOLogin() {
        server.expect(requestTo(ISSUER + "/userinfo")).andRespond(withUnauthorizedRequest());
        assertThatThrownBy(() -> client.fetchAndCheck("at", "sub-123")).isInstanceOf(ProviderUnavailableException.class);
    }
}
