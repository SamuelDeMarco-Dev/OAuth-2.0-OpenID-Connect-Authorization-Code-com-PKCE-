package br.unoesc.cyber.authserver.config;

import java.time.Duration;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuração do OpenID Provider (prefixo {@code oidc.server}).
 * Valores sensíveis vêm do .env (nunca versionado).
 */
@ConfigurationProperties(prefix = "oidc.server")
public record AuthServerProperties(
        String issuer,
        Duration authorizationCodeTtl,
        Duration accessTokenTtl,
        Duration idTokenTtl,
        Duration refreshTokenTtl,
        List<String> scopesSupported,
        SigningKey signingKey,
        SeedClient seedClient,
        SeedUsers seedUsers,
        Login login) {

    /** Chave RSA atual (assina) e, opcionalmente, a anterior (só publicada no JWKS durante a rotação). */
    public record SigningKey(String kid, String privateKeyPath, String previousKid, String previousPublicKeyPath) {
    }

    /** Cliente cadastrado na inicialização a partir do .env. */
    public record SeedClient(String clientId, String clientSecret, String redirectUri) {
    }

    /** Usuários de demonstração (role admin e role user) criados no boot. */
    public record SeedUsers(String adminUsername, String adminPassword, String userUsername, String userPassword) {
    }

    public record Login(int maxAttempts, Duration window, Duration lockout, int bcryptCost) {
    }
}
