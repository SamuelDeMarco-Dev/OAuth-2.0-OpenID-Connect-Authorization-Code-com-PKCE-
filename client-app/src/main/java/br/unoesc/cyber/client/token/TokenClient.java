package br.unoesc.cyber.client.token;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestClientResponseException;

import br.unoesc.cyber.client.config.OidcClientProperties;
import br.unoesc.cyber.client.discovery.ProviderMetadataService;

/**
 * POST no token_endpoint (PDF §4.2 passo 6) com {@code client_secret_basic}.
 * UMA tentativa só: o code é de uso único e repetir a troca dispararia a revogação no provedor (§4.6).
 */
@Component
public class TokenClient {

    private static final Logger log = LoggerFactory.getLogger(TokenClient.class);
    private static final ParameterizedTypeReference<Map<String, Object>> JSON = new ParameterizedTypeReference<>() {
    };

    private final RestClient http;
    private final ProviderMetadataService metadata;
    private final OidcClientProperties props;

    public TokenClient(RestClient oidcRestClient, ProviderMetadataService metadata, OidcClientProperties props) {
        this.http = oidcRestClient;
        this.metadata = metadata;
        this.props = props;
    }

    public TokenSet exchange(String code, String codeVerifier) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "authorization_code");
        form.add("code", code);
        form.add("redirect_uri", props.redirectUri());
        form.add("code_verifier", codeVerifier);

        String endpoint = metadata.get().tokenEndpoint();
        Map<String, Object> json;
        try {
            json = http.post().uri(endpoint)
                    .header(HttpHeaders.AUTHORIZATION, basic(props.clientId(), props.clientSecret()))
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .accept(MediaType.APPLICATION_JSON)
                    .body(form)
                    .retrieve()
                    .body(JSON);
        } catch (RestClientResponseException e) {
            log.warn("token_endpoint recusou a troca: HTTP {} {}", e.getStatusCode().value(), e.getResponseBodyAsString());
            throw new TokenExchangeException("O provedor recusou a troca do código", e);
        } catch (ResourceAccessException e) {
            log.warn("token_endpoint indisponível ou timeout ({}): a troca NÃO será repetida", e.getMessage());
            throw new TokenExchangeException("Provedor indisponível", e);
        } catch (RestClientException e) {
            log.warn("Resposta inválida do token_endpoint: {}", e.getMessage());
            throw new TokenExchangeException("Resposta inválida do provedor", e);
        }
        if (json == null || !(json.get("id_token") instanceof String idToken)
                || !(json.get("access_token") instanceof String accessToken)) {
            throw new TokenExchangeException("Resposta do provedor sem id_token/access_token");
        }
        if (!"Bearer".equalsIgnoreCase(String.valueOf(json.get("token_type")))) {
            throw new TokenExchangeException("token_type inesperado: " + json.get("token_type"));
        }
        long expiresIn = json.get("expires_in") instanceof Number n ? n.longValue() : 0;
        return new TokenSet(accessToken, idToken, (String) json.get("refresh_token"), expiresIn);
    }

    /** client_secret_basic: Base64(urlencode(id) ":" urlencode(secret)) — RFC 6749 §2.3.1. */
    static String basic(String clientId, String clientSecret) {
        String raw = URLEncoder.encode(clientId, StandardCharsets.UTF_8) + ":"
                + URLEncoder.encode(clientSecret, StandardCharsets.UTF_8);
        return "Basic " + Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
    }
}
