package br.unoesc.cyber.client.token;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import br.unoesc.cyber.client.discovery.ProviderMetadataService;
import br.unoesc.cyber.client.discovery.ProviderUnavailableException;

/**
 * Checklist §4.3 item 10 (OIDC Core §5.3.2): o {@code sub} devolvido pelo /userinfo deve ser
 * IDÊNTICO ao do ID Token já validado; caso contrário, a resposta pode ter sido substituída.
 */
@Component
public class UserInfoClient {

    private static final Logger log = LoggerFactory.getLogger(UserInfoClient.class);
    private static final ParameterizedTypeReference<Map<String, Object>> JSON = new ParameterizedTypeReference<>() {
    };

    private final RestClient http;
    private final ProviderMetadataService metadata;

    public UserInfoClient(RestClient oidcRestClient, ProviderMetadataService metadata) {
        this.http = oidcRestClient;
        this.metadata = metadata;
    }

    /** Busca o /userinfo com o access token e exige {@code sub == expectedSub}. */
    public Map<String, Object> fetchAndCheck(String accessToken, String expectedSub) {
        String endpoint = metadata.get().userinfoEndpoint();
        if (endpoint == null) {
            log.info("Provedor sem userinfo_endpoint: verificação 4.3 #10 não se aplica");
            return Map.of();
        }
        Map<String, Object> claims;
        try {
            claims = http.get().uri(endpoint)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                    .accept(MediaType.APPLICATION_JSON)
                    .retrieve().body(JSON);
        } catch (RestClientException e) {
            throw new ProviderUnavailableException("Falha ao consultar o /userinfo", e);
        }
        Object sub = claims == null ? null : claims.get("sub");
        if (!expectedSub.equals(sub)) {
            throw new IdTokenValidationException(10, "sub do /userinfo (" + sub + ") difere do ID Token (" + expectedSub + ")");
        }
        log.info("#10 sub do /userinfo idêntico ao do ID Token ({})", expectedSub);
        return claims;
    }
}
