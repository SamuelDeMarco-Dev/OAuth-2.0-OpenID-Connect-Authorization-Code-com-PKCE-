package br.unoesc.cyber.authserver.token;

import static br.unoesc.cyber.authserver.support.OAuthTestFlows.VERIFIER;
import static br.unoesc.cyber.authserver.support.OAuthTestFlows.basic;
import static br.unoesc.cyber.authserver.support.OAuthTestFlows.issueCode;
import static br.unoesc.cyber.authserver.support.OAuthTestFlows.tokenRequest;
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import com.jayway.jsonpath.JsonPath;

import br.unoesc.cyber.authserver.authorize.AuthorizationCode;
import br.unoesc.cyber.authserver.authorize.AuthorizationCodeRepository;
import br.unoesc.cyber.authserver.authorize.AuthorizationCodeService;
import br.unoesc.cyber.authserver.authorize.AuthorizationRequest;
import br.unoesc.cyber.authserver.client.ClientRegistry;
import br.unoesc.cyber.authserver.crypto.Hashes;
import br.unoesc.cyber.authserver.support.AbstractIntegrationTest;
import br.unoesc.cyber.authserver.support.OAuthTestFlows;
import br.unoesc.cyber.authserver.user.AppUserRepository;

class TokenControllerTest extends AbstractIntegrationTest {

    @Autowired
    MockMvc mvc;
    @Autowired
    AuthorizationCodeService codeService;
    @Autowired
    AuthorizationCodeRepository codes;
    @Autowired
    AppUserRepository users;
    @Autowired
    ClientRegistry clients;

    String sub;

    @BeforeEach
    void setUp() {
        sub = users.findByUsername(USER).orElseThrow().getSub();
    }

    static void expectError(ResultActions r, int status, String error) throws Exception {
        r.andExpect(status().is(status))
                .andExpect(jsonPath("$.error").value(error))
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
                .andExpect(header().string(HttpHeaders.PRAGMA, "no-cache"));
    }

    @Test
    void trocaComClientSecretBasic() throws Exception {
        mvc.perform(tokenRequest(issueCode(codeService, sub), VERIFIER))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.CONTENT_TYPE, startsWith("application/json")))
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
                .andExpect(header().string(HttpHeaders.PRAGMA, "no-cache"))
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.expires_in").value(900))
                .andExpect(jsonPath("$.scope").value("openid profile email"))
                .andExpect(jsonPath("$.access_token").isString())
                .andExpect(jsonPath("$.id_token").isString())
                .andExpect(jsonPath("$.refresh_token").isString());
    }

    @Test
    void trocaComClientSecretPost() throws Exception {
        mvc.perform(post("/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "authorization_code").param("code", issueCode(codeService, sub))
                .param("redirect_uri", REDIRECT_URI).param("code_verifier", VERIFIER)
                .param("client_id", CLIENT_ID).param("client_secret", CLIENT_SECRET))
                .andExpect(status().isOk());
    }

    /** Teste negativo #10. */
    @Test
    void negativo10_codeVerifierIncorreto_invalidGrant() throws Exception {
        expectError(mvc.perform(tokenRequest(issueCode(codeService, sub), VERIFIER.replace('d', 'e'))), 400,
                "invalid_grant");
    }

    @Test
    void codeReutilizadoRetornaInvalidGrant() throws Exception {
        String code = issueCode(codeService, sub);
        mvc.perform(tokenRequest(code, VERIFIER)).andExpect(status().isOk());
        expectError(mvc.perform(tokenRequest(code, VERIFIER)), 400, "invalid_grant");
    }

    @Test
    void parametroRepetidoRetornaInvalidRequest() throws Exception {
        expectError(mvc.perform(tokenRequest(issueCode(codeService, sub), VERIFIER)
                .param("redirect_uri", REDIRECT_URI + "/")), 400, "invalid_request");
    }

    @Test
    void redirectUriDiferenteDaUsadaNoAuthorize() throws Exception {
        String code = issueCode(codeService, sub);
        expectError(mvc.perform(post("/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.AUTHORIZATION, basic(CLIENT_ID, CLIENT_SECRET))
                .param("grant_type", "authorization_code").param("code", code)
                .param("redirect_uri", REDIRECT_URI + "/").param("code_verifier", VERIFIER)), 400, "invalid_grant");
    }

    @Test
    void codeExpirado() throws Exception {
        String code = Hashes.randomToken(new java.security.SecureRandom(), 32);
        codes.save(new AuthorizationCode(Hashes.sha256Hex(code), new AuthorizationRequest(CLIENT_ID, REDIRECT_URI,
                List.of("openid"), "s", "n", OAuthTestFlows.CHALLENGE), sub, Instant.now().minusSeconds(1)));
        expectError(mvc.perform(tokenRequest(code, VERIFIER)), 400, "invalid_grant");
    }

    @Test
    void codeInexistente() throws Exception {
        expectError(mvc.perform(tokenRequest("nao-existe", VERIFIER)), 400, "invalid_grant");
    }

    @Test
    void codeDeOutroCliente() throws Exception {
        clients.upsert("outro-cliente", "outro-segredo", "https://outro.example/cb", "openid");
        String code = issueCode(codeService, sub);
        expectError(mvc.perform(post("/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.AUTHORIZATION, basic("outro-cliente", "outro-segredo"))
                .param("grant_type", "authorization_code").param("code", code)
                .param("redirect_uri", REDIRECT_URI).param("code_verifier", VERIFIER)), 400, "invalid_grant");
    }

    @Test
    void segredoInvalidoRetorna401ComWwwAuthenticate() throws Exception {
        ResultActions r = mvc.perform(post("/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.AUTHORIZATION, basic(CLIENT_ID, "errado"))
                .param("grant_type", "authorization_code").param("code", "x")
                .param("redirect_uri", REDIRECT_URI).param("code_verifier", VERIFIER));
        expectError(r, 401, "invalid_client");
        r.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, startsWith("Basic realm=")));
    }

    @Test
    void semAutenticacaoDoCliente() throws Exception {
        expectError(mvc.perform(post("/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "authorization_code").param("client_id", CLIENT_ID)), 401, "invalid_client");
    }

    @Test
    void grantPasswordNaoSuportado() throws Exception {
        expectError(mvc.perform(post("/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.AUTHORIZATION, basic(CLIENT_ID, CLIENT_SECRET))
                .param("grant_type", "password").param("username", "admin").param("password", "x")),
                400, "unsupported_grant_type");
    }

    @Test
    void grantTypeAusente() throws Exception {
        expectError(mvc.perform(post("/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.AUTHORIZATION, basic(CLIENT_ID, CLIENT_SECRET))), 400, "invalid_request");
    }

    @Test
    void jsonNaoAceito() throws Exception {
        expectError(mvc.perform(post("/token").contentType(MediaType.APPLICATION_JSON).content("{}")), 400,
                "invalid_request");
    }

    @Test
    void doisMetodosDeAutenticacaoAoMesmoTempo() throws Exception {
        expectError(mvc.perform(tokenRequest(issueCode(codeService, sub), VERIFIER)
                .param("client_secret", CLIENT_SECRET)), 400, "invalid_request");
    }

    @Test
    void refreshTokenRotativo() throws Exception {
        String body = mvc.perform(tokenRequest(issueCode(codeService, sub), VERIFIER))
                .andReturn().getResponse().getContentAsString();
        String refresh = JsonPath.read(body, "$.refresh_token");
        mvc.perform(post("/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.AUTHORIZATION, basic(CLIENT_ID, CLIENT_SECRET))
                .param("grant_type", "refresh_token").param("refresh_token", refresh))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
                .andExpect(jsonPath("$.refresh_token").value(org.hamcrest.Matchers.not(refresh)));
        expectError(mvc.perform(post("/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.AUTHORIZATION, basic(CLIENT_ID, CLIENT_SECRET))
                .param("grant_type", "refresh_token").param("refresh_token", refresh)), 400, "invalid_grant");
    }
}
