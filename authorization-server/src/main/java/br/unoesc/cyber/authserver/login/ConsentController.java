package br.unoesc.cyber.authserver.login;

import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import jakarta.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import br.unoesc.cyber.authserver.authorize.AsSessionKeys;
import br.unoesc.cyber.authserver.authorize.AuthorizationCodeService;
import br.unoesc.cyber.authserver.authorize.AuthorizationRequest;
import br.unoesc.cyber.authserver.error.ErrorPageException;

/**
 * Consentimento dos escopos (PDF §2.3). Se o usuário já consentiu os MESMOS escopos para o
 * mesmo cliente, o consentimento registrado é reaproveitado e o code é emitido direto.
 */
@Controller
class ConsentController {

    private static final Logger log = LoggerFactory.getLogger(ConsentController.class);
    static final Map<String, String> SCOPE_DESCRIPTIONS = Map.of(
            "openid", "Confirmar sua identidade (identificador único)",
            "profile", "Ver seu nome",
            "email", "Ver seu endereço de e-mail");

    private final UserConsentRepository consents;
    private final AuthorizationCodeService codes;
    private final Clock clock;

    ConsentController(UserConsentRepository consents, AuthorizationCodeService codes, Clock clock) {
        this.consents = consents;
        this.codes = codes;
        this.clock = clock;
    }

    @GetMapping("/consent")
    String form(HttpSession session, Model model) {
        AuthorizationRequest pending = pending(session);
        String sub = (String) session.getAttribute(AsSessionKeys.AUTHENTICATED_SUB);
        if (sub == null) {
            return "redirect:/login";
        }
        boolean alreadyGranted = consents.findById(new UserConsent.Key(sub, pending.clientId()))
                .map(c -> c.covers(pending.scopes())).orElse(false);
        if (alreadyGranted) {
            log.info("Consentimento já registrado reaproveitado: sub={} client_id={}", sub, pending.clientId());
            return finish(session, codes.approve(pending, sub));
        }
        model.addAttribute("clientId", pending.clientId());
        model.addAttribute("scopes", pending.scopes().stream()
                .map(s -> Map.entry(s, SCOPE_DESCRIPTIONS.getOrDefault(s, s))).toList());
        model.addAttribute("formToken", FormTokens.issue(session));
        return "consent";
    }

    @PostMapping("/consent")
    @Transactional
    public String decide(@RequestParam(required = false) String decision,
            @RequestParam(name = FormTokens.PARAM, required = false) String formToken, HttpSession session) {
        AuthorizationRequest pending = pending(session);
        String sub = (String) session.getAttribute(AsSessionKeys.AUTHENTICATED_SUB);
        if (sub == null) {
            return "redirect:/login";
        }
        if (!FormTokens.isValid(session, formToken)) {
            throw new ErrorPageException("Formulário expirado. Volte à aplicação e tente novamente.");
        }
        if ("approve".equals(decision)) {
            Set<String> scopes = new LinkedHashSet<>(pending.scopes());
            consents.save(new UserConsent(sub, pending.clientId(), scopes, Instant.now(clock)));
            log.info("Consentimento concedido: sub={} client_id={} scopes={}", sub, pending.clientId(), scopes);
            return finish(session, codes.approve(pending, sub));
        }
        return finish(session, codes.deny(pending));
    }

    /** A autorização pendente é de uso único: removida antes do redirect. */
    private static String finish(HttpSession session, String redirectUrl) {
        session.removeAttribute(AsSessionKeys.PENDING_AUTHORIZATION);
        return "redirect:" + redirectUrl;
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
