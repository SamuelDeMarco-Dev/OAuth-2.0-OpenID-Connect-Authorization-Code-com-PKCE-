package br.unoesc.cyber.client.user;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import br.unoesc.cyber.client.support.AbstractIntegrationTest;
import br.unoesc.cyber.client.token.ValidatedIdToken;

class UserLinkServiceTest extends AbstractIntegrationTest {

    static final String ISS = "https://as.test.example";

    @Autowired
    UserLinkService service;
    @Autowired
    UserAccountRepository users;

    static ValidatedIdToken token(String sub, String email, boolean verified, String role) {
        return new ValidatedIdToken(ISS, sub, "Nome " + sub, email, verified, role, List.of());
    }

    static String sub() {
        return UUID.randomUUID().toString();
    }

    @Test
    void primeiroLoginCriaRegistroSoComDadosValidados() {
        String sub = sub();
        String email = sub + "@example.com";
        UserAccount u = service.link(token(sub, email, true, "admin"));
        assertThat(u.getId()).isNotNull();
        assertThat(u.getOidcSub()).isEqualTo(sub);
        assertThat(u.getOidcIss()).isEqualTo(ISS);
        assertThat(u.getUserName()).isEqualTo(email);
        assertThat(u.getRole()).isEqualTo("admin");
        assertThat(u.getCreatedAt()).isNotNull();
    }

    @Test
    void mesmoSubResolveParaOMesmoIdEAtualizaRole() {
        String sub = sub();
        Long id = service.link(token(sub, sub + "@x.com", true, "user")).getId();
        UserAccount again = service.link(token(sub, "outro-email@x.com", true, "admin"));
        assertThat(again.getId()).isEqualTo(id);
        assertThat(users.findById(id).orElseThrow().getRole()).isEqualTo("admin");
    }

    /** e-mail NÃO é identificador: mesmo e-mail com outro sub é outra pessoa. */
    @Test
    void mesmoEmailComSubDiferenteNaoLogaComoOMesmoUsuario() {
        String email = "compartilhado-" + UUID.randomUUID() + "@x.com";
        UserAccount a = service.link(token(sub(), email, true, "admin"));
        UserAccount b = service.link(token(sub(), email, true, "user"));
        assertThat(b.getId()).isNotEqualTo(a.getId());
        assertThat(b.getUserName()).isNotEqualTo(a.getUserName()).startsWith(email + " (");
        assertThat(b.getRole()).isEqualTo("user");
    }

    @Test
    void emailNaoVerificadoNaoViraUserName() {
        String sub = sub();
        UserAccount u = service.link(token(sub, "nao-verificado@x.com", false, null));
        assertThat(u.getUserName()).isEqualTo("usuario-" + sub.substring(0, 8));
        assertThat(u.getRole()).isEqualTo("user");
    }

    @Test
    void mesmoSubDeOutroEmissorNaoReaproveitaConta() {
        String sub = sub();
        service.link(token(sub, null, false, "admin"));
        assertThat(users.findByOidcIssAndOidcSub("https://outro-emissor", sub)).isEmpty();
    }
}
