package br.unoesc.cyber.authserver.login;

import static br.unoesc.cyber.authserver.support.OAuthTestFlows.VERIFIER;
import static br.unoesc.cyber.authserver.support.OAuthTestFlows.basic;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.util.UriComponentsBuilder;

import br.unoesc.cyber.authserver.authorize.AsSessionKeys;
import br.unoesc.cyber.authserver.support.AbstractIntegrationTest;
import br.unoesc.cyber.authserver.support.OAuthTestFlows;
import br.unoesc.cyber.authserver.user.AppUser;
import br.unoesc.cyber.authserver.user.AppUserRepository;

class ConsentAndFullFlowTest extends AbstractIntegrationTest {

    @Autowired
    MockMvc mvc;
    @Autowired
    AppUserRepository users;
    @Autowired
    PasswordEncoder encoder;

    static String param(String url, String name) {
        String raw = UriComponentsBuilder.fromUriString(url).build(true).getQueryParams().getFirst(name);
        return raw == null ? null : URLDecoder.decode(raw, StandardCharsets.UTF_8);
    }

    /** Usuário novo por teste: o consentimento fica registrado e seria reaproveitado entre testes. */
    String newUser() {
        String username = "consent-" + UUID.randomUUID();
        users.save(new AppUser(UUID.randomUUID().toString(), username, encoder.encode("s3nha"), "Usuário Teste",
                username + "@example.com", true, "user", Instant.now()));
        return username;
    }

    MockHttpSession authorizeAndLogin(String username) throws Exception {
        MockHttpSession session = new MockHttpSession();
        mvc.perform(get("/authorize").session(session).param("response_type", "code").param("client_id", CLIENT_ID)
                .param("redirect_uri", REDIRECT_URI).param("scope", "openid profile email").param("state", "s&t=1")
                .param("nonce", "nonce-fluxo").param("code_challenge", OAuthTestFlows.CHALLENGE)
                .param("code_challenge_method", "S256")).andExpect(redirectedUrl("/login"));
        mvc.perform(get("/login").session(session)).andExpect(status().isOk());
        mvc.perform(post("/login").session(session).param("username", username).param("password", "s3nha")
                .param(FormTokens.PARAM, FormTokens.issue(session))
                .with(r -> { r.setRemoteAddr("10.2.0." + (username.hashCode() & 0xff)); return r; }))
                .andExpect(redirectedUrl("/consent"));
        return session;
    }

    String approve(MockHttpSession session) throws Exception {
        mvc.perform(get("/consent").session(session)).andExpect(status().isOk()).andExpect(view().name("consent"))
                .andExpect(content().string(containsString("Ver seu nome")));
        return mvc.perform(post("/consent").session(session).param("decision", "approve")
                .param(FormTokens.PARAM, FormTokens.issue(session)))
                .andExpect(status().isFound()).andReturn().getResponse().getRedirectedUrl();
    }

    @Test
    void fluxoCompletoAuthorizeLoginConsentimentoToken() throws Exception {
        MockHttpSession session = authorizeAndLogin(newUser());
        String location = approve(session);

        assertThat(location).startsWith(REDIRECT_URI + "?code=");
        assertThat(param(location, "state")).isEqualTo("s&t=1");
        assertThat(session.getAttribute(AsSessionKeys.PENDING_AUTHORIZATION)).as("pendência de uso único").isNull();

        mvc.perform(post("/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.AUTHORIZATION, basic(CLIENT_ID, CLIENT_SECRET))
                .param("grant_type", "authorization_code").param("code", param(location, "code"))
                .param("redirect_uri", REDIRECT_URI).param("code_verifier", VERIFIER))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id_token").isString());
    }

    @Test
    void negarRetornaAccessDenied() throws Exception {
        MockHttpSession session = authorizeAndLogin(newUser());
        String location = mvc.perform(post("/consent").session(session).param("decision", "deny")
                .param(FormTokens.PARAM, FormTokens.issue(session)))
                .andReturn().getResponse().getRedirectedUrl();
        assertThat(param(location, "error")).isEqualTo("access_denied");
        assertThat(param(location, "state")).isEqualTo("s&t=1");
        assertThat(param(location, "code")).isNull();
    }

    @Test
    void consentimentoRegistradoEReaproveitado() throws Exception {
        String user = newUser();
        approve(authorizeAndLogin(user));

        MockHttpSession again = authorizeAndLogin(user);
        String location = mvc.perform(get("/consent").session(again)).andExpect(status().isFound())
                .andReturn().getResponse().getRedirectedUrl();
        assertThat(location).startsWith(REDIRECT_URI + "?code=");
    }

    @Test
    void consentimentoExigeLogin() throws Exception {
        mvc.perform(get("/consent").session(LoginControllerTest.pendingSession())).andExpect(redirectedUrl("/login"));
    }

    @Test
    void consentimentoSemTokenDoFormularioRecusado() throws Exception {
        MockHttpSession session = authorizeAndLogin(newUser());
        mvc.perform(post("/consent").session(session).param("decision", "approve"))
                .andExpect(status().isBadRequest());
        assertThat(session.getAttribute(AsSessionKeys.PENDING_AUTHORIZATION)).isNotNull();
    }

    @Test
    void semAutorizacaoPendenteMostraErro() throws Exception {
        mvc.perform(get("/consent")).andExpect(status().isBadRequest());
    }
}
