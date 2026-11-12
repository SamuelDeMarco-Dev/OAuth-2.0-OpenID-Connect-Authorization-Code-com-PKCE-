package br.unoesc.cyber.authserver.support;

import java.security.KeyPair;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Base dos testes de integração: sem TLS, H2 em memória e issuer fixo.
 * Todas as subclasses compartilham o mesmo contexto (cache do Spring).
 */
@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:h2:mem:as-test;DB_CLOSE_DELAY=-1",
        "server.ssl.enabled=false",
        "oidc.server.issuer=" + AbstractIntegrationTest.ISSUER
})
@AutoConfigureMockMvc
public abstract class AbstractIntegrationTest {

    public static final String ISSUER = "https://auth.test.example";
    public static final String KID = "test-kid";
    public static final String CLIENT_ID = "app-test";
    public static final String CLIENT_SECRET = "segredo-de-teste";
    public static final String REDIRECT_URI = "https://app.test.example/callback";
    public static final String ADMIN = "admin";
    public static final String ADMIN_PASSWORD = "senha-admin-teste";
    public static final String USER = "aluno";
    public static final String USER_PASSWORD = "senha-aluno-teste";

    /** Par de chaves de assinatura do contexto de teste (gerado uma vez por JVM). */
    public static final KeyPair SIGNING_KEYS = TestKeys.generate();
    private static final String SIGNING_KEY_PATH = TestKeys.writePrivatePem(SIGNING_KEYS).toString();

    @DynamicPropertySource
    static void testProperties(DynamicPropertyRegistry registry) {
        registry.add("oidc.server.signing-key.kid", () -> KID);
        registry.add("oidc.server.signing-key.private-key-path", () -> SIGNING_KEY_PATH);
        registry.add("oidc.server.seed-client.client-id", () -> CLIENT_ID);
        registry.add("oidc.server.seed-client.client-secret", () -> CLIENT_SECRET);
        registry.add("oidc.server.seed-client.redirect-uri", () -> REDIRECT_URI);
        registry.add("oidc.server.seed-users.admin-username", () -> ADMIN);
        registry.add("oidc.server.seed-users.admin-password", () -> ADMIN_PASSWORD);
        registry.add("oidc.server.seed-users.user-username", () -> USER);
        registry.add("oidc.server.seed-users.user-password", () -> USER_PASSWORD);
    }
}
