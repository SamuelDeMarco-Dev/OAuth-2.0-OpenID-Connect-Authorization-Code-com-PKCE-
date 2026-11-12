package br.unoesc.cyber.authserver.discovery;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import br.unoesc.cyber.authserver.config.AuthServerProperties;

/**
 * Metadados de descoberta (OIDC Discovery 1.0 §3). As URLs derivam SOMENTE do issuer configurado,
 * nunca do cabeçalho Host da requisição.
 */
@RestController
class DiscoveryController {

    private final Map<String, Object> metadata;

    DiscoveryController(AuthServerProperties props) {
        String issuer = props.issuer();
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("issuer", issuer);
        m.put("authorization_endpoint", issuer + "/authorize");
        m.put("token_endpoint", issuer + "/token");
        m.put("userinfo_endpoint", issuer + "/userinfo");
        m.put("jwks_uri", issuer + "/jwks.json");
        m.put("end_session_endpoint", issuer + "/logout");
        m.put("scopes_supported", props.scopesSupported());
        m.put("response_types_supported", List.of("code"));
        m.put("response_modes_supported", List.of("query"));
        m.put("grant_types_supported", List.of("authorization_code", "refresh_token"));
        m.put("subject_types_supported", List.of("public"));
        m.put("code_challenge_methods_supported", List.of("S256"));
        m.put("id_token_signing_alg_values_supported", List.of("RS256"));
        m.put("token_endpoint_auth_methods_supported", List.of("client_secret_basic", "client_secret_post"));
        m.put("claims_supported", List.of("iss", "sub", "aud", "exp", "iat", "nonce", "azp",
                "name", "email", "email_verified", "role"));
        this.metadata = java.util.Collections.unmodifiableMap(m);
    }

    @GetMapping("/.well-known/openid-configuration")
    Map<String, Object> configuration() {
        return metadata;
    }
}
