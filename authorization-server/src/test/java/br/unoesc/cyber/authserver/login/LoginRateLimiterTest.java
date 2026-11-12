package br.unoesc.cyber.authserver.login;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import br.unoesc.cyber.authserver.support.MutableClock;

class LoginRateLimiterTest {

    MutableClock clock;
    LoginRateLimiter limiter;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(Instant.parse("2026-11-26T12:00:00Z"));
        limiter = new LoginRateLimiter(clock, 5, Duration.ofMinutes(5), Duration.ofMinutes(15));
    }

    void falhar(String user, String ip, int vezes) {
        for (int i = 0; i < vezes; i++) {
            assertThat(limiter.isBlocked(user, ip)).isFalse();
            limiter.recordFailure(user, ip);
        }
    }

    /** Teste negativo #15: força bruta bloqueada — a 6ª tentativa nem chega a verificar a senha. */
    @Test
    void negativo15_forcaBruta_bloqueadaPorRateLimiting() {
        falhar("admin", "10.0.0.1", 5);
        assertThat(limiter.isBlocked("admin", "10.0.0.1")).isTrue();
        assertThat(limiter.isBlocked("ADMIN ", "10.0.0.99")).as("bloqueio vale para o usuário em qualquer IP").isTrue();
    }

    @Test
    void bloqueioExpiraAposLockout() {
        falhar("admin", "10.0.0.1", 5);
        clock.advance(Duration.ofMinutes(14));
        assertThat(limiter.isBlocked("admin", "10.0.0.1")).isTrue();
        clock.advance(Duration.ofMinutes(2));
        assertThat(limiter.isBlocked("admin", "10.0.0.1")).isFalse();
    }

    @Test
    void falhasForaDaJanelaNaoAcumulam() {
        falhar("admin", "10.0.0.1", 4);
        clock.advance(Duration.ofMinutes(6));
        falhar("admin", "10.0.0.1", 4);
        assertThat(limiter.isBlocked("admin", "10.0.0.1")).isFalse();
    }

    @Test
    void sucessoZeraContadorDoUsuario() {
        falhar("admin", "10.0.0.1", 4);
        limiter.recordSuccess("admin", "10.0.0.1");
        falhar("admin", "10.0.0.1", 4);
        assertThat(limiter.isBlocked("admin", "10.0.0.1")).isFalse();
    }

    @Test
    void ipQueTestaMuitosUsuariosEBloqueado() {
        for (int i = 0; i < 20; i++) {
            limiter.recordFailure("user" + i, "10.0.0.7");
        }
        assertThat(limiter.isBlocked("nunca-tentado", "10.0.0.7")).isTrue();
        assertThat(limiter.isBlocked("nunca-tentado", "10.0.0.8")).isFalse();
    }

    @Test
    void usuarioInexistenteContaIgual() {
        falhar("nao-existe", "10.0.0.1", 5);
        assertThat(limiter.isBlocked("nao-existe", "10.0.0.2")).isTrue();
    }
}
