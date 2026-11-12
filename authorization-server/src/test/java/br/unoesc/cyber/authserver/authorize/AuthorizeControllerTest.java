package br.unoesc.cyber.authserver.authorize;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.util.UriComponentsBuilder;

import br.unoesc.cyber.authserver.support.AbstractIntegrationTest;

class AuthorizeControllerTest extends AbstractIntegrationTest {

    static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"; // RFC 7636 apêndice B
    static final String STATE = "st&te=+/?%ç";

    @Autowired
    MockMvc mvc;

    static MockHttpServletRequestBuilder valid() {
        return get("/authorize")
                .param("response_type", "code")
                .param("client_id", CLIENT_ID)
                .param("redirect_uri", REDIRECT_URI)
                .param("scope", "openid profile email")
                .param("state", STATE)
                .param("nonce", "n-0S6_WzA2Mj")
                .param("code_challenge", CHALLENGE)
                .param("code_challenge_method", "S256");
    }

    /** Lê um parâmetro da query já decodificado (para comparar o state byte a byte). */
    static String query(String location, String name) {
        String raw = UriComponentsBuilder.fromUriString(location).build(true).getQueryParams().getFirst(name);
        return raw == null ? null : java.net.URLDecoder.decode(raw, java.nio.charset.StandardCharsets.UTF_8);
    }

    @Test
    void requisicaoValidaGuardaNaSessaoEVaiParaLogin() throws Exception {
        MockHttpSession session = new MockHttpSession();
        mvc.perform(valid().session(session)).andExpect(status().isFound()).andExpect(redirectedUrl("/login"));
        AuthorizationRequest pending = (AuthorizationRequest) session.getAttribute(AsSessionKeys.PENDING_AUTHORIZATION);
        assertThat(pending.clientId()).isEqualTo(CLIENT_ID);
        assertThat(pending.state()).isEqualTo(STATE);
        assertThat(pending.nonce()).isEqualTo("n-0S6_WzA2Mj");
        assertThat(pending.codeChallenge()).isEqualTo(CHALLENGE);
        assertThat(pending.scopes()).containsExactly("openid", "profile", "email");
    }

    @Test
    void postTambemAceito() throws Exception {
        mvc.perform(post("/authorize").param("response_type", "code").param("client_id", CLIENT_ID)
                .param("redirect_uri", REDIRECT_URI).param("scope", "openid").param("state", "s")
                .param("nonce", "n").param("code_challenge", CHALLENGE).param("code_challenge_method", "S256"))
                .andExpect(redirectedUrl("/login"));
    }

    @Test
    void usuarioJaAutenticadoVaiDiretoParaConsentimento() throws Exception {
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(AsSessionKeys.AUTHENTICATED_SUB, "sub-1");
        mvc.perform(valid().session(session)).andExpect(redirectedUrl("/consent"));
    }

    @Test
    void clientIdDesconhecidoMostraErroSemRedirecionar() throws Exception {
        // client_id repetido também é tratado na página
        mvc.perform(valid().param("client_id", "outro"))
                .andExpect(status().isBadRequest()).andExpect(header().doesNotExist("Location"));
        mvc.perform(get("/authorize").param("client_id", "nao-existe").param("redirect_uri", REDIRECT_URI))
                .andExpect(status().isBadRequest()).andExpect(view().name("error"))
                .andExpect(header().doesNotExist("Location"));
    }

    /** Teste negativo #11: barra final, parâmetro adicional, subcaminho (+ variações de normalização). */
    @ParameterizedTest
    @ValueSource(strings = { REDIRECT_URI + "/", REDIRECT_URI + "?x=1", REDIRECT_URI + "/sub",
            "https://APP.test.example/callback", "https://app.test.example:443/callback",
            "https://app.test.example/callback#frag", "https://evil.example/callback", "" })
    void negativo11_redirectUriSemCorrespondenciaExata_rejeitada(String redirect) throws Exception {
        mvc.perform(get("/authorize").param("response_type", "code").param("client_id", CLIENT_ID)
                .param("redirect_uri", redirect).param("scope", "openid").param("state", "s").param("nonce", "n")
                .param("code_challenge", CHALLENGE).param("code_challenge_method", "S256"))
                .andExpect(status().isBadRequest())
                .andExpect(view().name("error"))
                .andExpect(header().doesNotExist("Location"));
    }

    @Test
    void semOpenidRetornaInvalidScopeComStateIntacto() throws Exception {
        String loc = mvc.perform(build("scope", "profile email"))
                .andExpect(status().isFound()).andReturn().getResponse().getRedirectedUrl();
        assertThat(loc).startsWith(REDIRECT_URI + "?error=");
        assertThat(query(loc, "error")).isEqualTo("invalid_scope");
        assertThat(query(loc, "state")).isEqualTo(STATE);
    }

    @Test
    void escopoNaoPermitidoRetornaInvalidScope() throws Exception {
        String loc = mvc.perform(build("scope", "openid admin")).andReturn().getResponse().getRedirectedUrl();
        assertThat(query(loc, "error")).isEqualTo("invalid_scope");
    }

    @Test
    void metodoPlainRecusado() throws Exception {
        String loc = mvc.perform(build("code_challenge_method", "plain")).andReturn().getResponse().getRedirectedUrl();
        assertThat(query(loc, "error")).isEqualTo("invalid_request");
    }

    @Test
    void responseTypeTokenRecusado() throws Exception {
        String loc = mvc.perform(build("response_type", "token")).andReturn().getResponse().getRedirectedUrl();
        assertThat(query(loc, "error")).isEqualTo("unsupported_response_type");
    }

    @ParameterizedTest
    @ValueSource(strings = { "nonce", "code_challenge", "code_challenge_method", "response_type", "scope" })
    void parametroObrigatorioAusenteRetornaInvalidRequest(String ausente) throws Exception {
        String loc = mvc.perform(build(ausente, null)).andReturn().getResponse().getRedirectedUrl();
        assertThat(query(loc, "error")).isEqualTo("invalid_request");
        assertThat(query(loc, "state")).isEqualTo(STATE);
    }

    @Test
    void stateAusenteRetornaInvalidRequest() throws Exception {
        String loc = mvc.perform(build("state", null)).andReturn().getResponse().getRedirectedUrl();
        assertThat(query(loc, "error")).isEqualTo("invalid_request");
        assertThat(query(loc, "state")).isNull();
    }

    @Test
    void parametroRepetidoRetornaInvalidRequest() throws Exception {
        String loc = mvc.perform(valid().param("nonce", "outro")).andReturn().getResponse().getRedirectedUrl();
        assertThat(query(loc, "error")).isEqualTo("invalid_request");
    }

    @Test
    void codeChallengeMalformadoRecusado() throws Exception {
        String loc = mvc.perform(build("code_challenge", "curto")).andReturn().getResponse().getRedirectedUrl();
        assertThat(query(loc, "error")).isEqualTo("invalid_request");
    }

    /** Monta uma requisição válida trocando (ou removendo, se null) um parâmetro. */
    static MockHttpServletRequestBuilder build(String name, String value) {
        java.util.Map<String, String> p = new java.util.LinkedHashMap<>();
        p.put("response_type", "code");
        p.put("client_id", CLIENT_ID);
        p.put("redirect_uri", REDIRECT_URI);
        p.put("scope", "openid profile email");
        p.put("state", STATE);
        p.put("nonce", "n-1");
        p.put("code_challenge", CHALLENGE);
        p.put("code_challenge_method", "S256");
        if (value == null) {
            p.remove(name);
        } else {
            p.put(name, value);
        }
        MockHttpServletRequestBuilder b = get("/authorize");
        p.forEach(b::param);
        return b;
    }
}
