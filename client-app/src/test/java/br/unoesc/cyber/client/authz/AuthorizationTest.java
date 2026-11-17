package br.unoesc.cyber.client.authz;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.UUID;

import jakarta.servlet.http.Cookie;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;

import br.unoesc.cyber.client.session.SessionService;
import br.unoesc.cyber.client.support.AbstractIntegrationTest;
import br.unoesc.cyber.client.token.ValidatedIdToken;
import br.unoesc.cyber.client.user.UserLinkService;

class AuthorizationTest extends AbstractIntegrationTest {

    @Autowired
    MockMvc mvc;
    @Autowired
    UserLinkService userLink;
    @Autowired
    SessionService sessions;

    /** Cria usuário com a role pedida (como se viesse de um ID Token validado) e devolve o cookie da sessão. */
    Cookie login(String sub, String role) {
        long id = userLink.link(new ValidatedIdToken("https://as", sub, "Usuário " + role, null, false, role,
                List.of())).getId();
        MockHttpServletResponse response = new MockHttpServletResponse();
        sessions.start(id, new MockHttpServletRequest(), response);
        String setCookie = response.getHeader(HttpHeaders.SET_COOKIE);
        return new Cookie("APP_SID", setCookie.substring("APP_SID=".length(), setCookie.indexOf(';')));
    }

    /** Teste negativo #13: /admin com role = user → HTTP 403. */
    @Test
    void negativo13_adminComRoleUser_403() throws Exception {
        Cookie sid = login(UUID.randomUUID().toString(), "user");
        mvc.perform(get("/admin").cookie(sid)).andExpect(status().isForbidden());
        mvc.perform(get("/admin/qualquer-coisa").cookie(sid)).andExpect(status().isForbidden());
    }

    @Test
    void adminAcessaAreaAdministrativa() throws Exception {
        mvc.perform(get("/admin").cookie(login(UUID.randomUUID().toString(), "admin")))
                .andExpect(status().isOk()).andExpect(content().string(containsString("Área administrativa")));
    }

    @Test
    void semSessaoVaiParaLogin() throws Exception {
        mvc.perform(get("/admin")).andExpect(redirectedUrl("/login"));
        mvc.perform(get("/perfil")).andExpect(redirectedUrl("/login"));
        mvc.perform(get("/admin").cookie(new Cookie("APP_SID", "forjado"))).andExpect(redirectedUrl("/login"));
    }

    @Test
    void perfilParaQualquerUsuarioAutenticado() throws Exception {
        String sub = UUID.randomUUID().toString();
        mvc.perform(get("/perfil").cookie(login(sub, "user")))
                .andExpect(status().isOk()).andExpect(content().string(containsString(sub)));
    }

    /** A role é revalidada a cada requisição: rebaixar no provedor tira o acesso no login seguinte, sem cache. */
    @Test
    void roleRevalidadaACadaRequisicao() throws Exception {
        String sub = UUID.randomUUID().toString();
        Cookie sid = login(sub, "admin");
        mvc.perform(get("/admin").cookie(sid)).andExpect(status().isOk());
        userLink.link(new ValidatedIdToken("https://as", sub, "Rebaixado", null, false, "user", List.of()));
        mvc.perform(get("/admin").cookie(sid)).andExpect(status().isForbidden());
    }

    @Test
    void parametroOuHeaderNaoConcedemRole() throws Exception {
        Cookie sid = login(UUID.randomUUID().toString(), "user");
        mvc.perform(get("/admin").cookie(sid).param("role", "admin").header("X-Role", "admin"))
                .andExpect(status().isForbidden());
    }
}
