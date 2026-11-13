package br.unoesc.cyber.client.discovery;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import br.unoesc.cyber.client.config.OidcClientProperties;

/**
 * Lê {@code <issuer>/.well-known/openid-configuration} uma vez (carga preguiçosa: a aplicação sobe
 * mesmo com o provedor fora do ar) e exige que o {@code issuer} devolvido seja IDÊNTICO ao configurado.
 */
@Service
public class ProviderMetadataService {

    private static final Logger log = LoggerFactory.getLogger(ProviderMetadataService.class);
    private static final ParameterizedTypeReference<Map<String, Object>> JSON = new ParameterizedTypeReference<>() {
    };

    private final RestClient http;
    private final OidcClientProperties props;
    private volatile ProviderMetadata cached;

    public ProviderMetadataService(RestClient oidcRestClient, OidcClientProperties props) {
        this.http = oidcRestClient;
        this.props = props;
    }

    public ProviderMetadata get() {
        ProviderMetadata m = cached;
        if (m == null) {
            synchronized (this) {
                if (cached == null) {
                    cached = load();
                }
                m = cached;
            }
        }
        return m;
    }

    private ProviderMetadata load() {
        String url = props.issuer() + "/.well-known/openid-configuration";
        Map<String, Object> json;
        try {
            json = http.get().uri(url).retrieve().body(JSON);
        } catch (RestClientException e) {
            throw new ProviderUnavailableException("Falha ao ler a descoberta em " + url, e);
        }
        if (json == null || !props.issuer().equals(json.get("issuer"))) {
            throw new ProviderUnavailableException("issuer da descoberta difere do configurado: "
                    + (json == null ? null : json.get("issuer")));
        }
        ProviderMetadata m = new ProviderMetadata(props.issuer(),
                https(json, "authorization_endpoint", true), https(json, "token_endpoint", true),
                https(json, "userinfo_endpoint", false), https(json, "jwks_uri", true),
                https(json, "end_session_endpoint", false));
        log.info("Descoberta carregada de {}: token_endpoint={}, jwks_uri={}", props.issuer(), m.tokenEndpoint(),
                m.jwksUri());
        return m;
    }

    private static String https(Map<String, Object> json, String name, boolean required) {
        Object v = json.get(name);
        if (v == null && !required) {
            return null;
        }
        if (!(v instanceof String s) || !s.startsWith("https://")) {
            throw new ProviderUnavailableException("Descoberta inválida: " + name + " ausente ou sem HTTPS");
        }
        return s;
    }
}
