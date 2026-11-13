package br.unoesc.cyber.client.token;

/** Resposta do token_endpoint. Fica só na memória do servidor durante o callback; nunca vai ao navegador. */
public record TokenSet(String accessToken, String idToken, String refreshToken, long expiresIn) {

    @Override
    public String toString() {
        return "TokenSet[***]"; // evita vazar tokens em logs
    }
}
