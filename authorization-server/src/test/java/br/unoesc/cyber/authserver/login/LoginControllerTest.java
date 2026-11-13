package br.unoesc.cyber.authserver.login;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import br.unoesc.cyber.authserver.authorize.AsSessionKeys;
import br.unoesc.cyber.authserver.authorize.AuthorizationRequest;
import br.unoesc.cyber.authserver.support.AbstractIntegrationTest;
import br.unoesc.cyber.authserver.support.OAuthTestFlows;
import br.unoesc.cyber.authserver.user.AppUser;
import br.unoesc.cyber.authserver.user.AppUserRepository;

class LoginControllerTest extends AbstractIntegrationTest {

    /** IP diferente por teste: o contexto (e o rate limiter) é compartilhado entre as classes. */
    static final AtomicInteger IP = new AtomicInteger(1);

    @Autowired
    MockMvc mvc;
    @Autowired
    AppUserRepository users;
    @Autowired
    PasswordEncoder encoder;

    public static MockHttpSession pendingSession() {
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(AsSessionKeys.PENDING_AUTHORIZATION, new AuthorizationRequest(CLIENT_ID, REDIRECT_URI,
                List.of("openid", "profile", "email"), "state-xyz", "nonce-xyz", OAuthTestFlows.CHALLENGE));
        return session;
    }

    ResultActions submit(MockHttpSession session, String user, String password, String ip) throws Exception {
        return mvc.perform(post("/login").session(session)
                .param("username", user).param("password", password)
                .param(FormTokens.PARAM, FormTokens.issue(session))
                .with(r -> { r.setRemoteAddr(ip); return r; }));
    }

    static String nextIp() {
        return "10.1.0." + IP.incrementAndGet();
    }

    @Test
    void semAutorizacaoEmAndamentoMostraErro() throws Exception {
        mvc.perform(get("/login")).andExpect(status().isBadRequest()).andExpect(view().name("error"));
    }

    @Test
    void formularioMostraClienteETokenAntiCsrf() throws Exception {
        mvc.perform(get("/login").session(pendingSession()))
                .andExpect(status().isOk()).andExpect(view().name("login"))
                .andExpect(content().string(containsString(CLIENT_ID)))
                .andExpect(content().string(containsString("name=\"form_token\"")));
    }

    @Test
    void loginCorretoRotacionaSessaoEVaiParaConsentimento() throws Exception {
        MockHttpSession session = pendingSession();
        String idAntes = session.getId();
        submit(session, ADMIN, ADMIN_PASSWORD, nextIp()).andExpect(redirectedUrl("/consent"));
        assertThat(session.getId()).as("id da sessão rotacionado").isNotEqualTo(idAntes);
        assertThat(session.getAttribute(AsSessionKeys.AUTHENTICATED_SUB))
                .isEqualTo(users.findByUsername(ADMIN).orElseThrow().getSub());
    }

    @Test
    void senhaErradaEUsuarioInexistenteTemMesmaResposta() throws Exception {
        String a = submit(pendingSession(), USER, "errada", nextIp()).andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();
        String b = submit(pendingSession(), "nao-existe", "errada", nextIp()).andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();
        assertThat(a).contains(LoginController.INVALID_CREDENTIALS);
        assertThat(b).contains(LoginController.INVALID_CREDENTIALS);
        // fora o nome digitado e o token aleatório do formulário, as páginas são idênticas
        String token = "name=\"form_token\" value=\"[^\"]*\"";
        assertThat(a.replace(USER, "X").replaceAll(token, ""))
                .isEqualTo(b.replace("nao-existe", "X").replaceAll(token, ""));
    }

    @Test
    void semTokenDoFormularioRecusa() throws Exception {
        MockHttpSession session = pendingSession();
        mvc.perform(post("/login").session(session).param("username", ADMIN).param("password", ADMIN_PASSWORD))
                .andExpect(status().isBadRequest());
        assertThat(session.getAttribute(AsSessionKeys.AUTHENTICATED_SUB)).isNull();
    }

    /** Teste negativo #15 pelo formulário: após 5 falhas, nem a senha correta entra. */
    @Test
    void negativo15_forcaBrutaNoFormulario_bloqueada() throws Exception {
        String username = "vitima-" + UUID.randomUUID();
        users.save(new AppUser(UUID.randomUUID().toString(), username, encoder.encode("senha-correta"), "Vítima",
                null, false, "user", Instant.now()));
        for (int i = 0; i < 5; i++) {
            submit(pendingSession(), username, "chute-" + i, nextIp()).andExpect(status().isUnauthorized());
        }
        MockHttpSession session = pendingSession();
        submit(session, username, "senha-correta", nextIp())
                .andExpect(status().isTooManyRequests())
                .andExpect(content().string(containsString(LoginController.TOO_MANY_ATTEMPTS)));
        assertThat(session.getAttribute(AsSessionKeys.AUTHENTICATED_SUB)).isNull();
    }

    @Test
    void logoutInvalidaSessao() throws Exception {
        MockHttpSession session = pendingSession();
        session.setAttribute(AsSessionKeys.AUTHENTICATED_SUB, "sub");
        mvc.perform(post("/logout").session(session)).andExpect(status().isOk()).andExpect(view().name("logged-out"));
        assertThat(session.isInvalid()).isTrue();
    }
}
