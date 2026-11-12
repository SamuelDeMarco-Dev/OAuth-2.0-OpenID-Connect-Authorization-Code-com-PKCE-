package br.unoesc.cyber.authserver.authorize;

import java.io.Serializable;
import java.util.List;

/**
 * Requisição de autorização JÁ VALIDADA, guardada na sessão do AS enquanto o usuário
 * faz login e consente. Nada aqui é confiável antes de passar pelo {@link AuthorizeController}.
 */
public record AuthorizationRequest(
        String clientId,
        String redirectUri,
        List<String> scopes,
        String state,
        String nonce,
        String codeChallenge) implements Serializable {

    public String scope() {
        return String.join(" ", scopes);
    }
}
