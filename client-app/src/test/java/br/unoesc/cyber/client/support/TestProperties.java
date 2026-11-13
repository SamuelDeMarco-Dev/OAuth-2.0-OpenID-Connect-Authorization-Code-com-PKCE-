package br.unoesc.cyber.client.support;

import java.time.Duration;
import java.util.List;

import br.unoesc.cyber.client.config.OidcClientProperties;

/** Propriedades fixas para testes unitários do cliente. */
public final class TestProperties {

    public static final String ISSUER = "https://as.test.example";
    public static final String CLIENT_ID = "app-test";
    public static final String CLIENT_SECRET = "segredo-teste";
    public static final String REDIRECT_URI = "https://app.test.example/callback";

    private TestProperties() {
    }

    public static OidcClientProperties props() {
        return new OidcClientProperties(ISSUER, CLIENT_ID, CLIENT_SECRET, REDIRECT_URI,
                List.of("openid", "profile", "email"), List.of("RS256"), Duration.ofSeconds(60),
                Duration.ofSeconds(5), null, null,
                new OidcClientProperties.Session("APP_SID", Duration.ofMinutes(30), Duration.ofHours(8)));
    }

    public static String discoveryJson() {
        return """
                {"issuer":"%1$s","authorization_endpoint":"%1$s/authorize","token_endpoint":"%1$s/token",
                 "userinfo_endpoint":"%1$s/userinfo","jwks_uri":"%1$s/jwks.json","end_session_endpoint":"%1$s/logout"}
                """.formatted(ISSUER);
    }
}
