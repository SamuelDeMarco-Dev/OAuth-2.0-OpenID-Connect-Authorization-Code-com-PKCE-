package br.unoesc.cyber.authserver.login;

import java.security.SecureRandom;

import jakarta.servlet.http.HttpSession;

import br.unoesc.cyber.authserver.crypto.Hashes;

/**
 * Token anti-CSRF dos formulários do AS (login e consentimento). Defesa em profundidade:
 * o cookie AS_SESSION já é SameSite=Lax, o que impede o envio em POST de outro site.
 */
public final class FormTokens {

    static final String SESSION_KEY = "AS_FORM_TOKEN";
    public static final String PARAM = "form_token";
    private static final SecureRandom RANDOM = new SecureRandom();

    private FormTokens() {
    }

    public static String issue(HttpSession session) {
        String token = (String) session.getAttribute(SESSION_KEY);
        if (token == null) {
            token = Hashes.randomToken(RANDOM, 32);
            session.setAttribute(SESSION_KEY, token);
        }
        return token;
    }

    public static boolean isValid(HttpSession session, String submitted) {
        return Hashes.constantTimeEquals((String) session.getAttribute(SESSION_KEY), submitted);
    }

    /** Novo token após mudança de privilégio (login). */
    public static void rotate(HttpSession session) {
        session.removeAttribute(SESSION_KEY);
    }
}
