package br.unoesc.cyber.authserver.client;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import br.unoesc.cyber.authserver.config.SeedDataRunner;
import br.unoesc.cyber.authserver.support.AbstractIntegrationTest;
import br.unoesc.cyber.authserver.user.AppUser;
import br.unoesc.cyber.authserver.user.AppUserRepository;

class SeedAndClientRegistryTest extends AbstractIntegrationTest {

    @Autowired
    ClientRegistry clients;
    @Autowired
    OAuthClientRepository clientRepository;
    @Autowired
    AppUserRepository users;
    @Autowired
    SeedDataRunner seeder;

    @Test
    void clienteCadastradoComSecretEmBcrypt() {
        OAuthClient client = clientRepository.findById(CLIENT_ID).orElseThrow();
        assertThat(client.getClientSecretHash()).startsWith("$2a$12$").doesNotContain(CLIENT_SECRET);
        assertThat(client.allowedScopeSet()).containsExactlyInAnyOrder("openid", "profile", "email");
        assertThat(clients.authenticate(CLIENT_ID, CLIENT_SECRET)).isPresent();
        assertThat(clients.authenticate(CLIENT_ID, "errado")).isEmpty();
        assertThat(clients.authenticate("inexistente", CLIENT_SECRET)).isEmpty();
        assertThat(clients.authenticate(CLIENT_ID, null)).isEmpty();
    }

    @Test
    void redirectUriComparadaPorIgualdadeExata() {
        OAuthClient client = clientRepository.findById(CLIENT_ID).orElseThrow();
        assertThat(client.isRegisteredRedirectUri(REDIRECT_URI)).isTrue();
        assertThat(client.isRegisteredRedirectUri(REDIRECT_URI + "/")).isFalse();
        assertThat(client.isRegisteredRedirectUri(REDIRECT_URI + "?x=1")).isFalse();
        assertThat(client.isRegisteredRedirectUri(REDIRECT_URI + "/sub")).isFalse();
        assertThat(client.isRegisteredRedirectUri(REDIRECT_URI.toUpperCase())).isFalse();
    }

    @Test
    void usuariosSeedComSubImutavelEHashForte() {
        AppUser admin = users.findByUsername(ADMIN).orElseThrow();
        AppUser aluno = users.findByUsername(USER).orElseThrow();
        assertThat(UUID.fromString(admin.getSub())).isNotNull();
        assertThat(admin.getRole()).isEqualTo("admin");
        assertThat(aluno.getRole()).isEqualTo("user");
        assertThat(admin.getPasswordHash()).startsWith("$2a$12$");
        assertThat(admin.isEmailVerified()).isTrue();
    }

    @Test
    void seedIdempotente() throws Exception {
        long clientes = clientRepository.count();
        long usuarios = users.count();
        String sub = users.findByUsername(ADMIN).orElseThrow().getSub();
        seeder.seed();
        assertThat(clientRepository.count()).isEqualTo(clientes);
        assertThat(users.count()).isEqualTo(usuarios);
        assertThat(users.findByUsername(ADMIN).orElseThrow().getSub()).isEqualTo(sub);
    }
}
