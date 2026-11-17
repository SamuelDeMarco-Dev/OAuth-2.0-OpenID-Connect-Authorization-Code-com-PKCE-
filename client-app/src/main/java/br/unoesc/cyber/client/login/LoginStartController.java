package br.unoesc.cyber.client.login;

import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.util.UriComponentsBuilder;

import br.unoesc.cyber.client.config.OidcClientProperties;
import br.unoesc.cyber.client.crypto.Hashes;
import br.unoesc.cyber.client.discovery.ProviderMetadataService;
import br.unoesc.cyber.client.discovery.ProviderUnavailableException;
import br.unoesc.cyber.client.session.SessionService;

/**
 * GET /login — clique em "Entrar" (PDF §4.2 passos 1–2). Gera state, nonce e code_verifier de 256 bits,
 * guarda os três na sessão pré-login e redireciona para o authorization_endpoint com PKCE S256.
 * A aplicação nunca exibe formulário de senha: o usuário digita a senha no Servidor de Autorização.
 */
@Controller
class LoginStartController {

    private static final Logger log = LoggerFactory.getLogger(LoginStartController.class);
    static final int RANDOM_BYTES = 32;

    private final ProviderMetadataService metadata;
    private final OidcClientProperties props;
    private final SecureRandom random;

    LoginStartController(ProviderMetadataService metadata, OidcClientProperties props, SecureRandom random) {
        this.metadata = metadata;
        this.props = props;
        this.random = random;
    }

    @GetMapping("/login")
    String login(HttpServletRequest request) {
        if (SessionService.currentUserId(request).isPresent()) {
            return "redirect:/";
        }
        String authorizationEndpoint = metadata.get().authorizationEndpoint();
        PreLoginState pre = new PreLoginState(Hashes.randomToken(random, RANDOM_BYTES),
                Hashes.randomToken(random, RANDOM_BYTES), Hashes.randomToken(random, RANDOM_BYTES));
        request.getSession(true).setAttribute(PreLoginState.SESSION_KEY, pre);

        Map<String, String> params = new LinkedHashMap<>();
        params.put("response_type", "code");
        params.put("client_id", props.clientId());
        params.put("redirect_uri", props.redirectUri());
        params.put("scope", String.join(" ", props.scopes()));
        params.put("state", pre.state());
        params.put("nonce", pre.nonce());
        params.put("code_challenge", Hashes.s256(pre.codeVerifier()));
        params.put("code_challenge_method", "S256");

        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(authorizationEndpoint);
        params.keySet().forEach(name -> builder.queryParam(name, "{" + name + "}"));
        String url = builder.encode().buildAndExpand(params).toUriString();
        log.info("Iniciando login: redirecionando para {}", authorizationEndpoint);
        return "redirect:" + url;
    }

    @ExceptionHandler(ProviderUnavailableException.class)
    String providerDown(ProviderUnavailableException e, HttpServletResponse response, Model model) {
        log.warn("Provedor indisponível ao iniciar login: {}", e.getMessage());
        response.setStatus(HttpStatus.SERVICE_UNAVAILABLE.value());
        model.addAttribute("message", "O provedor de identidade está indisponível no momento. Tente novamente em instantes.");
        return "login-error";
    }
}
