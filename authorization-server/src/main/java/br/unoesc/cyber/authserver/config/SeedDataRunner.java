package br.unoesc.cyber.authserver.config;

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import br.unoesc.cyber.authserver.client.ClientRegistry;
import br.unoesc.cyber.authserver.user.AppUser;
import br.unoesc.cyber.authserver.user.AppUserRepository;

/**
 * Cadastra o cliente OAuth e os usuários de demonstração a partir do .env.
 * Segredos nunca ficam em migrations ou no código (PDF §1.2). Idempotente.
 *
 * <p>Roda em {@code afterSingletonsInstantiated}, ou seja, ANTES de o Tomcat aceitar conexões
 * (um ApplicationRunner rodaria depois, abrindo uma janela em que o cliente ainda não existe).
 */
@Component
public class SeedDataRunner implements SmartInitializingSingleton {

    private static final Logger log = LoggerFactory.getLogger(SeedDataRunner.class);

    private final AuthServerProperties props;
    private final ClientRegistry clients;
    private final AppUserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final Clock clock;

    SeedDataRunner(AuthServerProperties props, ClientRegistry clients, AppUserRepository users,
            PasswordEncoder passwordEncoder, Clock clock) {
        this.props = props;
        this.clients = clients;
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.clock = clock;
    }

    @Override
    public void afterSingletonsInstantiated() {
        seed();
    }

    public void seed() {
        var c = props.seedClient();
        if (usable(c.clientSecret())) {
            clients.upsert(c.clientId(), c.clientSecret(), c.redirectUri(), String.join(" ", props.scopesSupported()));
            log.info("Cliente '{}' cadastrado com redirect_uri {}", c.clientId(), c.redirectUri());
        } else {
            log.warn("OIDC_CLIENT_SECRET ausente: cliente não cadastrado (rode scripts/gen-dev-secrets.sh)");
        }
        var u = props.seedUsers();
        seedUser(u.adminUsername(), u.adminPassword(), "Administrador Demo", "admin");
        seedUser(u.userUsername(), u.userPassword(), "Aluno Demo", "user");
    }

    private void seedUser(String username, String password, String fullName, String role) {
        if (!usable(password)) {
            log.warn("Senha de '{}' ausente no .env: usuário não criado", username);
            return;
        }
        if (users.findByUsername(username).isPresent()) {
            return;
        }
        users.save(new AppUser(UUID.randomUUID().toString(), username, passwordEncoder.encode(password), fullName,
                username + "@example.com", true, role, Instant.now(clock)));
        log.info("Usuário de demonstração '{}' (role={}) criado", username, role);
    }

    private static boolean usable(String secret) {
        return StringUtils.hasText(secret) && !secret.startsWith("${") && !secret.equals("troque-me");
    }
}
