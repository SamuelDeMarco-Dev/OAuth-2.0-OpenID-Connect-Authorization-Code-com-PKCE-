package br.unoesc.cyber.client.config;

import java.time.Duration;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuração da Relying Party (prefixo {@code oidc.client}).
 * Trocar de provedor (Opção 1 / Opção 2) muda apenas estes valores.
 */
@ConfigurationProperties(prefix = "oidc.client")
public record OidcClientProperties(
        String issuer,
        String clientId,
        String clientSecret,
        String redirectUri,
        List<String> scopes,
        /* Lista FIXA de algoritmos aceitos (RFC 8725 §3.1). Nunca derivar do header "alg". */
        List<String> acceptedAlgorithms,
        Duration clockSkew,
        Duration httpTimeout,
        String truststorePath,
        String truststorePassword,
        Session session) {

    public record Session(String cookieName, Duration idleTimeout, Duration absoluteTimeout) {
    }
}
