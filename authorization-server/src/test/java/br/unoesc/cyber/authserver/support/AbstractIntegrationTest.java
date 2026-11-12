package br.unoesc.cyber.authserver.support;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;

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
}
