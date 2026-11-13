package br.unoesc.cyber.authserver.token;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import br.unoesc.cyber.authserver.client.ClientRegistry;
import br.unoesc.cyber.authserver.client.OAuthClient;
import br.unoesc.cyber.authserver.error.OAuthError;
import br.unoesc.cyber.authserver.error.OAuthException;

/**
 * POST /token (PDF §2.4). Autentica o cliente (client_secret_basic ou client_secret_post),
 * despacha pelo grant_type e responde sempre com Cache-Control: no-store e Pragma: no-cache.
 */
@RestController
class TokenController {

    private final ClientRegistry clients;
    private final CodeExchangeService codeExchange;
    private final TokenService tokenService;

    TokenController(ClientRegistry clients, CodeExchangeService codeExchange, TokenService tokenService) {
        this.clients = clients;
        this.codeExchange = codeExchange;
        this.tokenService = tokenService;
    }

    @PostMapping(path = "/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    ResponseEntity<Map<String, Object>> token(HttpServletRequest request) {
        Map<String, String[]> params = request.getParameterMap();
        params.forEach((name, values) -> {
            if (values.length > 1) {
                throw new OAuthException(OAuthError.INVALID_REQUEST, "parâmetro repetido: " + name);
            }
        });
        OAuthClient client = authenticateClient(request, params);

        String grantType = single(params, "grant_type");
        if (grantType == null) {
            throw new OAuthException(OAuthError.INVALID_REQUEST, "grant_type ausente");
        }
        TokenResponse response = switch (grantType) {
            case "authorization_code" -> codeExchange.exchange(client.getClientId(), single(params, "code"),
                    single(params, "redirect_uri"), single(params, "code_verifier"));
            case "refresh_token" -> {
                String refresh = single(params, "refresh_token");
                if (refresh == null) {
                    throw new OAuthException(OAuthError.INVALID_REQUEST, "refresh_token ausente");
                }
                yield tokenService.refresh(refresh, client.getClientId());
            }
            default -> throw new OAuthException(OAuthError.UNSUPPORTED_GRANT_TYPE,
                    "grant_type não suportado: " + grantType);
        };
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .header(HttpHeaders.PRAGMA, "no-cache")
                .body(response.toJson());
    }

    private OAuthClient authenticateClient(HttpServletRequest request, Map<String, String[]> params) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        String bodyId = single(params, "client_id");
        String bodySecret = single(params, "client_secret");
        String clientId;
        String secret;
        if (header != null && header.regionMatches(true, 0, "Basic ", 0, 6)) {
            if (bodySecret != null) {
                throw new OAuthException(OAuthError.INVALID_REQUEST, "use apenas um método de autenticação do cliente");
            }
            String[] credentials = decodeBasic(header.substring(6).trim());
            clientId = credentials[0];
            secret = credentials[1];
            if (bodyId != null && !bodyId.equals(clientId)) {
                throw new OAuthException(OAuthError.INVALID_REQUEST, "client_id do corpo difere do Authorization");
            }
        } else if (bodySecret != null) {
            clientId = bodyId;
            secret = bodySecret;
        } else {
            throw new OAuthException(OAuthError.INVALID_CLIENT, "autenticação do cliente ausente");
        }
        return clients.authenticate(clientId, secret)
                .orElseThrow(() -> new OAuthException(OAuthError.INVALID_CLIENT, "falha na autenticação do cliente"));
    }

    /** client_secret_basic: Base64(urlencode(id) ":" urlencode(secret)) — RFC 6749 §2.3.1. */
    private static String[] decodeBasic(String value) {
        try {
            String decoded = new String(Base64.getDecoder().decode(value), StandardCharsets.UTF_8);
            int sep = decoded.indexOf(':');
            if (sep < 0) {
                throw new IllegalArgumentException();
            }
            return new String[] {
                    URLDecoder.decode(decoded.substring(0, sep), StandardCharsets.UTF_8),
                    URLDecoder.decode(decoded.substring(sep + 1), StandardCharsets.UTF_8) };
        } catch (IllegalArgumentException e) {
            throw new OAuthException(OAuthError.INVALID_CLIENT, "cabeçalho Authorization malformado");
        }
    }

    private static String single(Map<String, String[]> params, String name) {
        String[] values = params.get(name);
        return values == null ? null : values[0];
    }
}
