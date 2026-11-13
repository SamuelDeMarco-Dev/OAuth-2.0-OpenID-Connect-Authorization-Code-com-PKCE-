package br.unoesc.cyber.authserver.login;

import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import br.unoesc.cyber.authserver.authorize.AsSessionKeys;
import br.unoesc.cyber.authserver.authorize.AuthorizationRequest;
import br.unoesc.cyber.authserver.error.ErrorPageException;
import br.unoesc.cyber.authserver.user.AppUser;
import br.unoesc.cyber.authserver.user.AppUserRepository;

/**
 * Login do provedor (PDF §2.3). A senha só trafega entre o navegador e este servidor.
 * Mensagem de falha é genérica e o custo do BCrypt é pago mesmo para usuário inexistente,
 * para não revelar a existência da conta (nem pelo texto, nem pelo tempo de resposta).
 */
@Controller
class LoginController {

    private static final Logger log = LoggerFactory.getLogger(LoginController.class);
    static final String INVALID_CREDENTIALS = "Usuário ou senha inválidos.";
    static final String TOO_MANY_ATTEMPTS = "Muitas tentativas de login. Aguarde alguns minutos e tente novamente.";

    private final AppUserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final LoginRateLimiter limiter;
    private final String dummyHash;

    LoginController(AppUserRepository users, PasswordEncoder passwordEncoder, LoginRateLimiter limiter) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.limiter = limiter;
        this.dummyHash = passwordEncoder.encode("senha-ficticia-para-igualar-tempo");
    }

    @GetMapping("/login")
    String form(HttpSession session, Model model) {
        AuthorizationRequest pending = pending(session);
        model.addAttribute("clientId", pending.clientId());
        model.addAttribute("formToken", FormTokens.issue(session));
        return "login";
    }

    @PostMapping("/login")
    String login(@RequestParam(required = false) String username, @RequestParam(required = false) String password,
            @RequestParam(name = FormTokens.PARAM, required = false) String formToken, HttpServletRequest request,
            HttpServletResponse response, HttpSession session, Model model) {
        AuthorizationRequest pending = pending(session);
        if (!FormTokens.isValid(session, formToken)) {
            throw new ErrorPageException("Formulário expirado. Volte à aplicação e tente novamente.");
        }
        String user = username == null ? "" : username.trim();
        String ip = request.getRemoteAddr();
        model.addAttribute("clientId", pending.clientId());
        model.addAttribute("formToken", FormTokens.issue(session));
        model.addAttribute("username", user);

        if (limiter.isBlocked(user, ip)) {
            log.warn("Login recusado por rate limiting: usuário='{}' ip={}", user, ip);
            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            model.addAttribute("error", TOO_MANY_ATTEMPTS);
            return "login";
        }

        Optional<AppUser> account = users.findByUsername(user);
        String hash = account.map(AppUser::getPasswordHash).orElse(dummyHash);
        boolean passwordOk = password != null && passwordEncoder.matches(password, hash);
        if (account.isEmpty() || !passwordOk) {
            limiter.recordFailure(user, ip);
            log.info("Falha de login: usuário='{}' ip={}", user, ip);
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            model.addAttribute("error", INVALID_CREDENTIALS);
            return "login";
        }

        limiter.recordSuccess(user, ip);
        request.changeSessionId(); // evita fixação de sessão
        session.setAttribute(AsSessionKeys.AUTHENTICATED_SUB, account.get().getSub());
        FormTokens.rotate(session);
        log.info("Login bem-sucedido: usuário='{}' sub={} ip={}", user, account.get().getSub(), ip);
        return "redirect:/consent";
    }

    /** Encerra a sessão no Servidor de Autorização (PDF §2, endpoint /logout). */
    @PostMapping("/logout")
    String logout(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        return "logged-out";
    }

    private static AuthorizationRequest pending(HttpSession session) {
        AuthorizationRequest pending = (AuthorizationRequest) session.getAttribute(AsSessionKeys.PENDING_AUTHORIZATION);
        if (pending == null) {
            throw new ErrorPageException(
                    "Não há uma autorização em andamento (ou ela expirou). Volte à aplicação e clique em Entrar novamente.");
        }
        return pending;
    }
}
