package br.unoesc.cyber.authserver.login;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import br.unoesc.cyber.authserver.config.AuthServerProperties;

/**
 * Limitação de tentativas de login (PDF §2.3, teste negativo #15).
 *
 * <p>Conta falhas por usuário (limite {@code max-attempts}) e por IP (limite 4× maior, para não
 * bloquear uma rede inteira atrás de NAT, mas ainda conter quem testa muitos usuários).
 * Atingido o limite dentro da janela, a chave fica bloqueada por {@code lockout} — inclusive
 * para a senha correta. Usuários inexistentes contam igual aos existentes (não revela existência).
 *
 * <p>Uso esperado no POST /login (issue #6):
 * <pre>
 * if (limiter.isBlocked(username, ip)) → mensagem genérica (ou 429), NÃO verifica a senha
 * senha ok   → limiter.recordSuccess(username, ip)
 * senha errada/usuário inexistente → limiter.recordFailure(username, ip)
 * </pre>
 */
@Component
public class LoginRateLimiter {

    private static final Logger log = LoggerFactory.getLogger(LoginRateLimiter.class);
    static final int IP_MULTIPLIER = 4;

    private final Clock clock;
    private final int maxAttempts;
    private final Duration window;
    private final Duration lockout;
    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    @Autowired
    public LoginRateLimiter(AuthServerProperties props, Clock clock) {
        this(clock, props.login().maxAttempts(), props.login().window(), props.login().lockout());
    }

    LoginRateLimiter(Clock clock, int maxAttempts, Duration window, Duration lockout) {
        this.clock = clock;
        this.maxAttempts = maxAttempts;
        this.window = window;
        this.lockout = lockout;
    }

    public boolean isBlocked(String username, String ip) {
        Instant now = clock.instant();
        return locked(userKey(username), now) || locked(ipKey(ip), now);
    }

    public void recordFailure(String username, String ip) {
        Instant now = clock.instant();
        fail(userKey(username), maxAttempts, now);
        fail(ipKey(ip), maxAttempts * IP_MULTIPLIER, now);
    }

    /** Sucesso zera só o contador do usuário; o do IP continua (senão uma conta válida "limparia" o IP). */
    public void recordSuccess(String username, String ip) {
        buckets.remove(userKey(username));
    }

    private boolean locked(String key, Instant now) {
        Bucket b = buckets.get(key);
        if (b == null) {
            return false;
        }
        synchronized (b) {
            if (b.lockedUntil != null && now.isBefore(b.lockedUntil)) {
                return true;
            }
            if (b.lockedUntil != null) {
                buckets.remove(key, b); // bloqueio expirou: recomeça do zero
            }
            return false;
        }
    }

    private void fail(String key, int limit, Instant now) {
        Bucket b = buckets.computeIfAbsent(key, k -> new Bucket());
        synchronized (b) {
            if (b.lockedUntil != null && now.isBefore(b.lockedUntil)) {
                return;
            }
            b.lockedUntil = null;
            while (!b.failures.isEmpty() && !b.failures.peekFirst().isAfter(now.minus(window))) {
                b.failures.pollFirst();
            }
            b.failures.addLast(now);
            if (b.failures.size() >= limit) {
                b.lockedUntil = now.plus(lockout);
                b.failures.clear();
                log.warn("Login bloqueado por excesso de tentativas: {} até {}", key, b.lockedUntil);
            }
        }
    }

    private static String userKey(String username) {
        return "user:" + (username == null ? "" : username.trim().toLowerCase(Locale.ROOT));
    }

    private static String ipKey(String ip) {
        return "ip:" + ip;
    }

    private static final class Bucket {
        final Deque<Instant> failures = new ArrayDeque<>();
        Instant lockedUntil;
    }
}
