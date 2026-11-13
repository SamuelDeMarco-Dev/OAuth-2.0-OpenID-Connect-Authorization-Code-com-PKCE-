package br.unoesc.cyber.client.login;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import br.unoesc.cyber.client.crypto.Hashes;
import br.unoesc.cyber.client.discovery.ProviderUnavailableException;
import br.unoesc.cyber.client.token.IdTokenValidationException;
import br.unoesc.cyber.client.token.TokenExchangeException;
import br.unoesc.cyber.client.user.UserAccount;

/**
 * GET /callback (PDF §4.2 passos 4–5 e §4.6). O {@code state} é conferido ANTES de qualquer outra
 * coisa: divergente ou ausente, o fluxo é abortado e o code nunca é enviado ao token_endpoint.
 * Mensagens ao usuário são genéricas; o detalhe fica só no log do servidor.
 */
@Controller
class CallbackController {

    private static final Logger log = LoggerFactory.getLogger(CallbackController.class);
    static final String GENERIC_FAILURE = "Não foi possível concluir o login. Tente entrar novamente.";
    static final String DENIED = "O login foi cancelado ou o acesso não foi autorizado.";

    private final LoginCompletionService completion;

    CallbackController(LoginCompletionService completion) {
        this.completion = completion;
    }

    @GetMapping("/callback")
    String callback(@RequestParam(required = false) String code, @RequestParam(required = false) String state,
            @RequestParam(required = false) String error,
            @RequestParam(name = "error_description", required = false) String errorDescription,
            HttpServletRequest request, HttpServletResponse response, Model model) {
        HttpSession session = request.getSession(false);
        PreLoginState pre = session == null ? null : (PreLoginState) session.getAttribute(PreLoginState.SESSION_KEY);
        if (session != null) {
            session.removeAttribute(PreLoginState.SESSION_KEY); // uso único, qualquer que seja o desfecho
        }

        if (error != null) {
            log.warn("Provedor devolveu erro no callback: error={} description={}", error, errorDescription);
            return fail(response, model, "access_denied".equals(error) ? DENIED : GENERIC_FAILURE);
        }
        if (pre == null || state == null || !Hashes.constantTimeEquals(state, pre.state())) {
            log.warn("Callback com state {} — possível CSRF. Fluxo abortado ANTES da troca do code.",
                    pre == null ? "sem login em andamento" : state == null ? "ausente" : "divergente");
            return fail(response, model, GENERIC_FAILURE);
        }
        if (code == null || code.isBlank()) {
            log.warn("Callback sem code");
            return fail(response, model, GENERIC_FAILURE);
        }
        try {
            UserAccount user = completion.complete(code, pre, request, response);
            log.info("Login concluído: user_id={} role={}", user.getId(), user.getRole());
            return "redirect:/";
        } catch (TokenExchangeException | ProviderUnavailableException e) {
            log.warn("Falha na troca do code: {}", e.getMessage());
        } catch (IdTokenValidationException e) {
            log.warn("ID Token rejeitado: {}", e.getMessage());
        }
        return fail(response, model, GENERIC_FAILURE);
    }

    private static String fail(HttpServletResponse response, Model model, String message) {
        response.setStatus(HttpStatus.BAD_REQUEST.value());
        model.addAttribute("message", message);
        return "login-error";
    }
}
