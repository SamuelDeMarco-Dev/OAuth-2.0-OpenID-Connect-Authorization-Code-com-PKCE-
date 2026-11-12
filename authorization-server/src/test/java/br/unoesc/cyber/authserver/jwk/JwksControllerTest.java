package br.unoesc.cyber.authserver.jwk;

import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.MockMvc;

import br.unoesc.cyber.authserver.support.AbstractIntegrationTest;

class JwksControllerTest extends AbstractIntegrationTest {

    @Autowired
    MockMvc mvc;

    @Test
    void publicaSomenteParametrosPublicos() throws Exception {
        mvc.perform(get("/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys", hasSize(1)))
                .andExpect(jsonPath("$.keys[0].kid").value(KID))
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].use").value("sig"))
                .andExpect(jsonPath("$.keys[0].alg").value("RS256"))
                .andExpect(jsonPath("$.keys[0].n").exists())
                .andExpect(jsonPath("$.keys[0].e").exists())
                .andExpect(jsonPath("$.keys[0].d").doesNotExist())
                .andExpect(jsonPath("$.keys[0].p").doesNotExist())
                .andExpect(jsonPath("$.keys[0].q").doesNotExist());
    }
}
