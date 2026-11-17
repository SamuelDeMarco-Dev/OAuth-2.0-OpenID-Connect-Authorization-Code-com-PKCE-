package br.unoesc.cyber.client.authz;

import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import br.unoesc.cyber.client.session.SessionService;
import br.unoesc.cyber.client.user.UserAccount;
import br.unoesc.cyber.client.user.UserAccountRepository;

/**
 * Autorização no servidor (PDF §4.5), avaliada a CADA requisição:
 * <ul>
 *   <li>sem sessão local válida → redirect para /login;</li>
 *   <li>{@code /admin/**} exige {@code role = admin} → senão HTTP 403.</li>
 * </ul>
 * A role é lida do banco (gravada no login a partir do ID Token já validado criptograficamente),
 * nunca de parâmetro, cookie ou do HTML. Esconder o botão na interface não é o controle.
 */
@Component
class AuthorizationInterceptor implements HandlerInterceptor {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationInterceptor.class);
    static final String ADMIN = "admin";
    static final String CURRENT_USER = "currentUser";

    private final UserAccountRepository users;

    AuthorizationInterceptor(UserAccountRepository users) {
        this.users = users;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        Optional<UserAccount> user = SessionService.currentUserId(request).flatMap(users::findById);
        if (user.isEmpty()) {
            response.sendRedirect(request.getContextPath() + "/login");
            return false;
        }
        String path = request.getRequestURI().substring(request.getContextPath().length());
        if ((path.equals("/admin") || path.startsWith("/admin/")) && !ADMIN.equals(user.get().getRole())) {
            log.warn("Acesso NEGADO a {} para user_id={} role={}", path, user.get().getId(), user.get().getRole());
            response.sendError(HttpStatus.FORBIDDEN.value());
            return false;
        }
        request.setAttribute(CURRENT_USER, user.get());
        return true;
    }
}
