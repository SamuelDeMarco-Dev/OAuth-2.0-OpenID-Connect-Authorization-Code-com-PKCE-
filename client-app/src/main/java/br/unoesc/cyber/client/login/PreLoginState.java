package br.unoesc.cyber.client.login;

import java.io.Serializable;

/**
 * Valores gerados no clique em "Entrar" e guardados na sessão pré-login (cookie APP_PRELOGIN)
 * até o retorno em /callback (PDF §4.2 passo 1).
 *
 * <p><b>Contrato com a issue #15 (GET /login):</b> gerar {@code state} e {@code nonce} com
 * {@code Hashes.randomToken(random, 16)} ou mais, {@code codeVerifier} com
 * {@code Hashes.randomToken(random, 32)}, enviar {@code code_challenge = Hashes.s256(codeVerifier)}
 * e gravar {@code session.setAttribute(PreLoginState.SESSION_KEY, new PreLoginState(...))}.
 */
public record PreLoginState(String state, String nonce, String codeVerifier) implements Serializable {

    public static final String SESSION_KEY = "APP_PRELOGIN_STATE";
}
