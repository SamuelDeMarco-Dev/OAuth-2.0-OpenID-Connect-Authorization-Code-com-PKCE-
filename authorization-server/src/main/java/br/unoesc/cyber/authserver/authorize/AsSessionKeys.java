package br.unoesc.cyber.authserver.authorize;

/**
 * Contrato da sessão do AS (cookie AS_SESSION) entre /authorize, login e consentimento.
 *
 * <pre>
 * /authorize  → valida e grava PENDING_AUTHORIZATION → 302 /login (ou /consent se já autenticado)
 * /login      → autentica, ROTACIONA o id da sessão, grava AUTHENTICATED_SUB → 302 /consent
 * /consent    → aprova: AuthorizationCodeService.approve(...) → 302 redirect_uri?code&state
 *               nega:   AuthorizationCodeService.deny(...)    → 302 redirect_uri?error=access_denied&state
 * </pre>
 */
public final class AsSessionKeys {

    public static final String PENDING_AUTHORIZATION = "AS_PENDING_AUTHORIZATION";
    public static final String AUTHENTICATED_SUB = "AS_AUTHENTICATED_SUB";

    private AsSessionKeys() {
    }
}
