package br.unoesc.cyber.client.session;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import br.unoesc.cyber.client.config.OidcClientProperties;
import br.unoesc.cyber.client.crypto.Hashes;

/**
 * Sessão local da aplicação (PDF §4.4).
 * <ul>
 *   <li>sessionID de 256 bits gerado pelo servidor (não é o JWT nem o access token);</li>
 *   <li>cookie {@code APP_SID}: HttpOnly, Secure, SameSite=Lax, Path=/;</li>
 *   <li>rotação no login: a sessão pré-login (state/nonce/verifier) e qualquer APP_SID anterior são descartadas;</li>
 *   <li>expiração por inatividade (30 min) e absoluta (8 h), verificadas no servidor a cada requisição;</li>
 *   <li>logout apaga o registro no servidor. Tokens não são guardados após o login, então não há cache a limpar.</li>
 * </ul>
 */
@Service
public class SessionService {

    private static final Logger log = LoggerFactory.getLogger(SessionService.class);
    /** Atributo da requisição com o id interno do usuário autenticado (preenchido pelo {@link SessionFilter}). */
    public static final String CURRENT_USER_ID = "APP_CURRENT_USER_ID";
    static final int SESSION_ID_BYTES = 32;

    private final LocalSessionRepository sessions;
    private final Clock clock;
    private final SecureRandom random;
    private final String cookieName;
    private final Duration idleTimeout;
    private final Duration absoluteTimeout;

    public SessionService(LocalSessionRepository sessions, Clock clock, SecureRandom random, OidcClientProperties props) {
        this.sessions = sessions;
        this.clock = clock;
        this.random = random;
        this.cookieName = props.session().cookieName();
        this.idleTimeout = props.session().idleTimeout();
        this.absoluteTimeout = props.session().absoluteTimeout();
    }

    /** Cria a sessão após o login (chamado pelo callback com o id interno obtido pelo vínculo iss + sub). */
    @Transactional
    public void start(long userId, HttpServletRequest request, HttpServletResponse response) {
        rawCookie(request).ifPresent(old -> sessions.deleteById(Hashes.sha256Hex(old)));
        HttpSession preLogin = request.getSession(false);
        if (preLogin != null) {
            preLogin.invalidate();
        }
        String sessionId = Hashes.randomToken(random, SESSION_ID_BYTES);
        sessions.save(new LocalSession(Hashes.sha256Hex(sessionId), userId, Instant.now(clock), absoluteTimeout));
        writeCookie(response, sessionId, absoluteTimeout);
        log.info("Sessão local criada para user_id={} (expira em no máximo {})", userId, absoluteTimeout);
    }

    /** Usuário da sessão válida, renovando a inatividade; sessão expirada é apagada. */
    @Transactional
    public Optional<Long> resolve(HttpServletRequest request) {
        Optional<String> raw = rawCookie(request);
        if (raw.isEmpty()) {
            return Optional.empty();
        }
        String hash = Hashes.sha256Hex(raw.get());
        Optional<LocalSession> found = sessions.findById(hash);
        if (found.isEmpty()) {
            return Optional.empty();
        }
        LocalSession session = found.get();
        Instant now = Instant.now(clock);
        if (session.isExpired(now, idleTimeout)) {
            sessions.delete(session);
            log.info("Sessão local expirada para user_id={}", session.getUserId());
            return Optional.empty();
        }
        session.touch(now);
        sessions.save(session); // explícito: não depende de dirty checking/transação
        return Optional.of(session.getUserId());
    }

    /** Logout: invalida no servidor e expira o cookie. */
    @Transactional
    public void end(HttpServletRequest request, HttpServletResponse response) {
        rawCookie(request).ifPresent(raw -> sessions.deleteById(Hashes.sha256Hex(raw)));
        HttpSession http = request.getSession(false);
        if (http != null) {
            http.invalidate();
        }
        clearCookie(response);
    }

    boolean hasCookie(HttpServletRequest request) {
        return rawCookie(request).isPresent();
    }

    void clearCookie(HttpServletResponse response) {
        writeCookie(response, "", Duration.ZERO);
    }

    public static Optional<Long> currentUserId(HttpServletRequest request) {
        return Optional.ofNullable((Long) request.getAttribute(CURRENT_USER_ID));
    }

    private void writeCookie(HttpServletResponse response, String value, Duration maxAge) {
        ResponseCookie cookie = ResponseCookie.from(cookieName, value)
                .httpOnly(true).secure(true).sameSite("Lax").path("/").maxAge(maxAge).build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    private Optional<String> rawCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return Optional.empty();
        }
        return Arrays.stream(cookies).filter(c -> cookieName.equals(c.getName())).map(Cookie::getValue)
                .filter(v -> v != null && !v.isEmpty()).findFirst();
    }
}
