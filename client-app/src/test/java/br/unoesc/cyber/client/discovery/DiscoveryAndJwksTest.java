package br.unoesc.cyber.client.discovery;

import static br.unoesc.cyber.client.support.TestProperties.ISSUER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.ExpectedCount.once;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.time.Duration;
import java.time.Instant;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

import br.unoesc.cyber.client.support.MutableClock;
import br.unoesc.cyber.client.support.TestProperties;

class DiscoveryAndJwksTest {

    MockRestServiceServer server;
    RestClient rest;
    MutableClock clock = new MutableClock(Instant.parse("2026-11-26T12:00:00Z"));

    @BeforeEach
    void setUp() {
        RestClient.Builder builder = RestClient.builder();
        server = MockRestServiceServer.bindTo(builder).build();
        rest = builder.build();
    }

    void expectDiscovery(String json) {
        server.expect(once(), requestTo(ISSUER + "/.well-known/openid-configuration"))
                .andRespond(withSuccess(json, MediaType.APPLICATION_JSON));
    }

    static String jwks(String... kids) throws Exception {
        var keys = new java.util.ArrayList<com.nimbusds.jose.jwk.JWK>();
        for (String kid : kids) {
            keys.add(new RSAKeyGenerator(2048).keyID(kid).keyUse(KeyUse.SIGNATURE).generate().toPublicJWK());
        }
        return new JWKSet(keys).toString();
    }

    @Test
    void descobertaCarregadaUmaVezEComIssuerIdentico() {
        expectDiscovery(TestProperties.discoveryJson());
        ProviderMetadataService service = new ProviderMetadataService(rest, TestProperties.props());
        ProviderMetadata m = service.get();
        assertThat(service.get()).isSameAs(m);
        assertThat(m.tokenEndpoint()).isEqualTo(ISSUER + "/token");
        assertThat(m.jwksUri()).isEqualTo(ISSUER + "/jwks.json");
        server.verify();
    }

    @Test
    void issuerDivergenteRecusado() {
        expectDiscovery(TestProperties.discoveryJson().replaceFirst("\"issuer\":\"[^\"]*\"", "\"issuer\":\"https://evil\""));
        assertThatThrownBy(() -> new ProviderMetadataService(rest, TestProperties.props()).get())
                .isInstanceOf(ProviderUnavailableException.class).hasMessageContaining("issuer");
    }

    @Test
    void endpointSemHttpsRecusado() {
        expectDiscovery(TestProperties.discoveryJson().replace("\"" + ISSUER + "/token\"", "\"http://as/token\""));
        assertThatThrownBy(() -> new ProviderMetadataService(rest, TestProperties.props()).get())
                .isInstanceOf(ProviderUnavailableException.class).hasMessageContaining("token_endpoint");
    }

    @Test
    void provedorForaDoArViraErroControlado() {
        server.expect(requestTo(ISSUER + "/.well-known/openid-configuration")).andRespond(withServerError());
        assertThatThrownBy(() -> new ProviderMetadataService(rest, TestProperties.props()).get())
                .isInstanceOf(ProviderUnavailableException.class);
    }

    @Test
    void jwksBuscaPorKidERecarregaUmaVezSeDesconhecido() throws Exception {
        expectDiscovery(TestProperties.discoveryJson());
        server.expect(once(), requestTo(ISSUER + "/jwks.json")).andRespond(withSuccess(jwks("k1"), MediaType.APPLICATION_JSON));
        server.expect(once(), requestTo(ISSUER + "/jwks.json")).andRespond(withSuccess(jwks("k1", "k2"), MediaType.APPLICATION_JSON));
        JwksCache cache = new JwksCache(rest, new ProviderMetadataService(rest, TestProperties.props()), clock);

        assertThat(cache.find("k1")).isPresent();
        assertThat(cache.find("k1").get().isPrivate()).isFalse();
        // kid novo logo em seguida: não recarrega (limite de 10 s)
        assertThat(cache.find("k2")).isEmpty();
        clock.advance(Duration.ofSeconds(11));
        // rotação no provedor: kid novo provoca uma recarga
        assertThat(cache.find("k2")).isPresent();
        assertThat(cache.find(null)).isEmpty();
        server.verify();
    }
}
