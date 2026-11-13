package br.unoesc.cyber.client.session;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import jakarta.servlet.http.Cookie;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;

import br.unoesc.cyber.client.crypto.Hashes;
import br.unoesc.cyber.client.support.AbstractIntegrationTest;
import br.unoesc.cyber.client.support.MutableClock;
import br.unoesc.cyber.client.support.TestProperties;
import br.unoesc.cyber.client.token.ValidatedIdToken;
import br.unoesc.cyber.client.user.UserLinkService;

class SessionServiceTest extends AbstractIntegrationTest {

    @Autowired
    LocalSessionRepository repository;
    @Autowired
    UserLinkService userLink;
    @Autowired
    SessionService realService;
    @Autowired
    MockMvc mvc;

    MutableClock clock = new MutableClock(Instant.parse("2026-11-26T08:00:00Z"));
    SessionService service;
    long userId;

    @BeforeEach
    void setUp() {
        service = new SessionService(repository, clock, new SecureRandom(), TestProperties.props());
        String sub = UUID.randomUUID().toString();
        userId = userLink.link(new ValidatedIdToken("https://as", sub, "Maria Teste", sub + "@x.com", true, "user",
                List.of())).getId();
    }

    /** Inicia uma sessão e devolve o valor bruto do cookie APP_SID. */
    String start(MockHttpServletRequest request) {
        MockHttpServletResponse response = new MockHttpServletResponse();
        service.start(userId, request, response);
        String setCookie = response.getHeader(HttpHeaders.SET_COOKIE);
        return setCookie.substring("APP_SID=".length(), setCookie.indexOf(';'));
    }

    static MockHttpServletRequest withCookie(String sid) {
        MockHttpServletRequest r = new MockHttpServletRequest();
        r.setCookies(new Cookie("APP_SID", sid));
        return r;
    }

    @Test
    void cookieSeguroComIdDe256BitsEHashNoBanco() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        service.start(userId, request, response);
        String setCookie = response.getHeader(HttpHeaders.SET_COOKIE);
        assertThat(setCookie).contains("HttpOnly").contains("Secure").contains("SameSite=Lax").contains("Path=/");

        String sid = setCookie.substring("APP_SID=".length(), setCookie.indexOf(';'));
        assertThat(sid).hasSize(43); // 32 bytes em Base64URL = 256 bits (mínimo exigido: 128)
        assertThat(repository.findById(sid)).as("valor bruto não é armazenado").isEmpty();
        assertThat(repository.findById(Hashes.sha256Hex(sid))).isPresent();
    }

    @Test
    void loginRotacionaSessaoPreLoginEAnterior() {
        MockHttpSession preLogin = new MockHttpSession();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setSession(preLogin);
        String first = start(request);
        assertThat(preLogin.isInvalid()).as("sessão pré-login descartada").isTrue();

        String second = start(withCookie(first));
        assertThat(second).isNotEqualTo(first);
        assertThat(repository.findById(Hashes.sha256Hex(first))).as("sessão anterior apagada").isEmpty();
        assertThat(service.resolve(withCookie(first))).isEmpty();
        assertThat(service.resolve(withCookie(second))).contains(userId);
    }

    @Test
    void expiraPorInatividadeDe30Minutos() {
        String sid = start(new MockHttpServletRequest());
        clock.advance(Duration.ofMinutes(29));
        assertThat(service.resolve(withCookie(sid))).contains(userId);
        clock.advance(Duration.ofMinutes(29)); // 29 min desde o último acesso: ainda vale
        assertThat(service.resolve(withCookie(sid))).contains(userId);
        clock.advance(Duration.ofMinutes(31));
        assertThat(service.resolve(withCookie(sid))).isEmpty();
        assertThat(repository.findById(Hashes.sha256Hex(sid))).isEmpty();
    }

    @Test
    void expiraAbsolutamenteEm8HorasMesmoComUsoContinuo() {
        String sid = start(new MockHttpServletRequest());
        for (int i = 0; i < 23; i++) { // 23 × 20 min = 7h40
            clock.advance(Duration.ofMinutes(20));
            assertThat(service.resolve(withCookie(sid))).contains(userId);
        }
        clock.advance(Duration.ofMinutes(20)); // 8h00
        assertThat(service.resolve(withCookie(sid))).isEmpty();
    }

    @Test
    void logoutInvalidaNoServidorEExpiraCookie() {
        String sid = start(new MockHttpServletRequest());
        MockHttpServletResponse response = new MockHttpServletResponse();
        service.end(withCookie(sid), response);
        assertThat(repository.findById(Hashes.sha256Hex(sid))).isEmpty();
        assertThat(response.getHeader(HttpHeaders.SET_COOKIE)).contains("Max-Age=0");
        assertThat(service.resolve(withCookie(sid))).isEmpty();
    }

    @Test
    void cookieForjadoNaoAutentica() {
        assertThat(service.resolve(withCookie("valor-inventado"))).isEmpty();
    }

    @Test
    void paginaInicialReconheceSessaoEValidaNoServidor() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        realService.start(userId, new MockHttpServletRequest(), response);
        String setCookie = response.getHeader(HttpHeaders.SET_COOKIE);
        String sid = setCookie.substring("APP_SID=".length(), setCookie.indexOf(';'));

        mvc.perform(get("/").cookie(new Cookie("APP_SID", sid)))
                .andExpect(content().string(containsString("Maria Teste")));
        mvc.perform(post("/logout").cookie(new Cookie("APP_SID", sid))).andExpect(redirectedUrl("/"));
        mvc.perform(get("/").cookie(new Cookie("APP_SID", sid)))
                .andExpect(content().string(containsString("não está autenticado")))
                .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("Max-Age=0")));
    }
}
