package br.unoesc.cyber.authserver.discovery;

import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.MockMvc;

import br.unoesc.cyber.authserver.support.AbstractIntegrationTest;

class DiscoveryControllerTest extends AbstractIntegrationTest {

    @Autowired
    MockMvc mvc;

    @Test
    void publicaMetadadosMinimosDoPdf() throws Exception {
        mvc.perform(get("/.well-known/openid-configuration").header("Host", "evil.example"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value(ISSUER))
                .andExpect(jsonPath("$.authorization_endpoint").value(ISSUER + "/authorize"))
                .andExpect(jsonPath("$.token_endpoint").value(ISSUER + "/token"))
                .andExpect(jsonPath("$.userinfo_endpoint").value(ISSUER + "/userinfo"))
                .andExpect(jsonPath("$.jwks_uri").value(ISSUER + "/jwks.json"))
                .andExpect(jsonPath("$.scopes_supported", hasItems("openid", "profile", "email")))
                .andExpect(jsonPath("$.response_types_supported", hasItem("code")))
                .andExpect(jsonPath("$.response_types_supported", not(hasItem("token"))))
                .andExpect(jsonPath("$.grant_types_supported", hasItem("authorization_code")))
                .andExpect(jsonPath("$.grant_types_supported", not(hasItem("password"))))
                .andExpect(jsonPath("$.code_challenge_methods_supported", hasItem("S256")))
                .andExpect(jsonPath("$.code_challenge_methods_supported", not(hasItem("plain"))))
                .andExpect(jsonPath("$.id_token_signing_alg_values_supported", hasItem("RS256")))
                .andExpect(jsonPath("$.token_endpoint_auth_methods_supported",
                        hasItems("client_secret_basic", "client_secret_post")));
    }
}
