package br.unoesc.cyber.authserver.authorize;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import br.unoesc.cyber.authserver.client.ClientRegistry;
import br.unoesc.cyber.authserver.client.OAuthClient;
import br.unoesc.cyber.authserver.error.ErrorPageException;
import br.unoesc.cyber.authserver.error.OAuthError;

/**
 * GET/POST /authorize (PDF §2.2). Ordem das validações:
 * 1) client_id e redirect_uri — se inválidos, erro NA PÁGINA (sem redirect);
 * 2) demais parâmetros — erro devolvido por redirect para a redirect_uri já validada, com o state.
 */
@Controller
class AuthorizeController {

    private static final Logger log = LoggerFactory.getLogger(AuthorizeController.class);
    /** BASE64URL(SHA-256) sem padding tem exatamente 43 caracteres (RFC 7636 §4.2). */
    private static final Pattern S256_CHALLENGE = Pattern.compile("^[A-Za-z0-9_-]{43}$");

    private final ClientRegistry clients;

    AuthorizeController(ClientRegistry clients) {
        this.clients = clients;
    }

    @RequestMapping(path = "/authorize", method = { RequestMethod.GET, RequestMethod.POST })
    String authorize(HttpServletRequest request, HttpSession session) {
        Map<String, String[]> params = request.getParameterMap();

        // 1) Cliente e redirect_uri: nunca redirecionar se algo aqui falhar.
        String clientId = single(params, "client_id");
        OAuthClient client = clients.findById(clientId)
                .orElseThrow(() -> new ErrorPageException("Aplicação cliente desconhecida ou client_id inválido."));
        String redirectUri = single(params, "redirect_uri");
        if (redirectUri == null || !client.isRegisteredRedirectUri(redirectUri)) {
            log.warn("redirect_uri recusada para client_id={}: {}", clientId, redirectUri);
            throw new ErrorPageException("redirect_uri não corresponde exatamente à URI cadastrada para esta aplicação.");
        }

        // 2) Demais parâmetros: erro volta para a aplicação.
        String state = single(params, "state");
        String duplicated = params.entrySet().stream().filter(e -> e.getValue().length > 1).map(Map.Entry::getKey)
                .findFirst().orElse(null);
        if (duplicated != null) {
            return error(redirectUri, state, OAuthError.INVALID_REQUEST, "parâmetro repetido: " + duplicated);
        }
        String responseType = single(params, "response_type");
        if (responseType == null) {
            return error(redirectUri, state, OAuthError.INVALID_REQUEST, "response_type ausente");
        }
        if (!"code".equals(responseType)) {
            return error(redirectUri, state, OAuthError.UNSUPPORTED_RESPONSE_TYPE, "apenas response_type=code");
        }
        if (state == null || state.isEmpty()) {
            return error(redirectUri, null, OAuthError.INVALID_REQUEST, "state obrigatório");
        }
        String scope = single(params, "scope");
        if (scope == null || scope.isBlank()) {
            return error(redirectUri, state, OAuthError.INVALID_REQUEST, "scope ausente");
        }
        List<String> scopes = Arrays.stream(scope.split(" ")).filter(s -> !s.isEmpty()).distinct().toList();
        Set<String> allowed = client.allowedScopeSet();
        if (!scopes.contains("openid")) {
            return error(redirectUri, state, OAuthError.INVALID_SCOPE, "scope deve conter openid");
        }
        if (!allowed.containsAll(scopes)) {
            return error(redirectUri, state, OAuthError.INVALID_SCOPE, "escopo não permitido para o cliente");
        }
        String nonce = single(params, "nonce");
        if (nonce == null || nonce.isEmpty()) {
            return error(redirectUri, state, OAuthError.INVALID_REQUEST, "nonce obrigatório");
        }
        String challenge = single(params, "code_challenge");
        String method = single(params, "code_challenge_method");
        if (challenge == null || method == null) {
            return error(redirectUri, state, OAuthError.INVALID_REQUEST, "PKCE obrigatório (code_challenge e code_challenge_method)");
        }
        if (!"S256".equals(method)) {
            return error(redirectUri, state, OAuthError.INVALID_REQUEST, "code_challenge_method deve ser S256");
        }
        if (!S256_CHALLENGE.matcher(challenge).matches()) {
            return error(redirectUri, state, OAuthError.INVALID_REQUEST, "code_challenge malformado");
        }

        session.setAttribute(AsSessionKeys.PENDING_AUTHORIZATION,
                new AuthorizationRequest(clientId, redirectUri, scopes, state, nonce, challenge));
        boolean authenticated = session.getAttribute(AsSessionKeys.AUTHENTICATED_SUB) != null;
        return "redirect:" + (authenticated ? "/consent" : "/login");
    }

    private static String single(Map<String, String[]> params, String name) {
        String[] values = params.get(name);
        return values == null || values.length != 1 ? null : values[0];
    }

    private static String error(String redirectUri, String state, OAuthError error, String description) {
        log.info("/authorize recusado: {} ({})", error.code(), description);
        Map<String, String> p = new LinkedHashMap<>();
        p.put("error", error.code());
        p.put("error_description", description);
        p.put("state", state);
        return "redirect:" + RedirectUris.withParams(redirectUri, p);
    }
}
