package br.unoesc.cyber.client.support;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;

/** Base dos testes de integração do cliente: sem TLS, H2 em memória, provedor fictício. */
@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:h2:mem:client-test;DB_CLOSE_DELAY=-1",
        "server.ssl.enabled=false",
        "oidc.client.issuer=" + TestProperties.ISSUER,
        "oidc.client.client-id=" + TestProperties.CLIENT_ID,
        "oidc.client.client-secret=" + TestProperties.CLIENT_SECRET,
        "oidc.client.redirect-uri=" + TestProperties.REDIRECT_URI,
        "oidc.client.truststore-path="
})
@AutoConfigureMockMvc
public abstract class AbstractIntegrationTest {
}
