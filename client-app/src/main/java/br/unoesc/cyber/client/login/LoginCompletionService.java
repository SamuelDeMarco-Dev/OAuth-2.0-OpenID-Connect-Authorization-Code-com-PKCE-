package br.unoesc.cyber.client.login;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Service;

import br.unoesc.cyber.client.session.SessionService;
import br.unoesc.cyber.client.token.IdTokenValidator;
import br.unoesc.cyber.client.token.TokenClient;
import br.unoesc.cyber.client.token.TokenSet;
import br.unoesc.cyber.client.token.ValidatedIdToken;
import br.unoesc.cyber.client.user.UserAccount;
import br.unoesc.cyber.client.user.UserLinkService;

/**
 * Passos 6–11 do PDF §4.2, em ordem. Nenhum claim é usado antes da validação criptográfica (passo 8).
 * Qualquer exceção interrompe o fluxo SEM criar sessão.
 */
@Service
class LoginCompletionService {

    private final TokenClient tokenClient;
    private final IdTokenValidator validator;
    private final UserLinkService userLink;
    private final SessionService sessions;

    LoginCompletionService(TokenClient tokenClient, IdTokenValidator validator, UserLinkService userLink,
            SessionService sessions) {
        this.tokenClient = tokenClient;
        this.validator = validator;
        this.userLink = userLink;
        this.sessions = sessions;
    }

    UserAccount complete(String code, PreLoginState pre, HttpServletRequest request, HttpServletResponse response) {
        // Passo 6: troca do code (uma tentativa, com timeout)
        TokenSet tokens = tokenClient.exchange(code, pre.codeVerifier());

        // Passo 7 (issue #17): decompor o ID Token e registrar no log header, payload e assinatura.

        // Passo 8: checklist 4.3 itens 1–8 (lista fixa de algoritmos, JWKS pelo kid, iss, aud, azp, exp, iat, nonce)
        ValidatedIdToken idToken = validator.validate(tokens.idToken(), pre.nonce());

        // Checklist 4.3 item 10 (issue #23): GET /userinfo com o access token e exigir sub == idToken.sub().

        // Passos 9–10: sub validado → id interno (vínculo iss + sub)
        UserAccount user = userLink.link(idToken);

        // Passo 11: sessão local (rotaciona a sessão pré-login)
        sessions.start(user.getId(), request, response);
        return user;
    }
}
