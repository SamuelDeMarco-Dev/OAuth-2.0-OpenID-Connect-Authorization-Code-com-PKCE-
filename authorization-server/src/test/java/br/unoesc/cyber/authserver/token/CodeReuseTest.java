package br.unoesc.cyber.authserver.token;

import static br.unoesc.cyber.authserver.support.OAuthTestFlows.VERIFIER;
import static br.unoesc.cyber.authserver.support.OAuthTestFlows.basic;
import static br.unoesc.cyber.authserver.support.OAuthTestFlows.issueCode;
import static br.unoesc.cyber.authserver.support.OAuthTestFlows.tokenRequest;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import com.jayway.jsonpath.JsonPath;

import br.unoesc.cyber.authserver.authorize.AuthorizationCodeService;
import br.unoesc.cyber.authserver.crypto.Hashes;
import br.unoesc.cyber.authserver.support.AbstractIntegrationTest;
import br.unoesc.cyber.authserver.user.AppUserRepository;

class CodeReuseTest extends AbstractIntegrationTest {

    @Autowired
    MockMvc mvc;
    @Autowired
    AuthorizationCodeService codeService;
    @Autowired
    IssuedTokenRepository tokens;
    @Autowired
    AppUserRepository users;

    /** Teste negativo #9: reutilização do code → invalid_grant e revogação dos tokens emitidos com ele. */
    @Test
    void negativo09_reutilizacaoDoCode_invalidGrantERevogacao() throws Exception {
        String code = issueCode(codeService, users.findByUsername(ADMIN).orElseThrow().getSub());

        // 1ª troca: sucesso
        String body = mvc.perform(tokenRequest(code, VERIFIER)).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String access = JsonPath.read(body, "$.access_token");
        String refresh = JsonPath.read(body, "$.refresh_token");
        mvc.perform(get("/userinfo").header(HttpHeaders.AUTHORIZATION, "Bearer " + access)).andExpect(status().isOk());

        // 2ª troca do MESMO code: invalid_grant
        mvc.perform(tokenRequest(code, VERIFIER))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));

        // todos os tokens da 1ª troca foram revogados
        assertThat(tokens.findByCodeHash(Hashes.sha256Hex(code))).isNotEmpty().allMatch(IssuedToken::isRevoked);
        mvc.perform(get("/userinfo").header(HttpHeaders.AUTHORIZATION, "Bearer " + access))
                .andExpect(status().isUnauthorized());
        mvc.perform(post("/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.AUTHORIZATION, basic(CLIENT_ID, CLIENT_SECRET))
                .param("grant_type", "refresh_token").param("refresh_token", refresh))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    @Test
    void reusoTambemRevogaTokensJaRotacionados() throws Exception {
        String code = issueCode(codeService, users.findByUsername(USER).orElseThrow().getSub());
        String first = mvc.perform(tokenRequest(code, VERIFIER)).andReturn().getResponse().getContentAsString();
        String rotated = mvc.perform(post("/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.AUTHORIZATION, basic(CLIENT_ID, CLIENT_SECRET))
                .param("grant_type", "refresh_token").param("refresh_token", JsonPath.<String>read(first, "$.refresh_token")))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();

        mvc.perform(tokenRequest(code, VERIFIER)).andExpect(status().isBadRequest());

        mvc.perform(get("/userinfo").header(HttpHeaders.AUTHORIZATION,
                "Bearer " + JsonPath.read(rotated, "$.access_token"))).andExpect(status().isUnauthorized());
    }
}
