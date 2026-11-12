package br.unoesc.cyber.authserver;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:h2:mem:as-test;DB_CLOSE_DELAY=-1",
        "server.ssl.enabled=false"
})
class AuthorizationServerApplicationTests {

    @Test
    void contextLoads() {
    }
}
