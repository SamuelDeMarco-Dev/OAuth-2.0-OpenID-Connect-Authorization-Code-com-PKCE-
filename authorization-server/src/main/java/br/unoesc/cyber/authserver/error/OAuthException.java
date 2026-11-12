package br.unoesc.cyber.authserver.error;

/** Erro OAuth devolvido como JSON {@code {error, error_description}} (endpoints /token e /userinfo). */
public class OAuthException extends RuntimeException {

    private final OAuthError error;

    public OAuthException(OAuthError error, String description) {
        super(description);
        this.error = error;
    }

    public OAuthError error() {
        return error;
    }

    public String description() {
        return getMessage();
    }
}
