package br.unoesc.cyber.authserver.token;

import java.util.LinkedHashMap;
import java.util.Map;

/** Resposta de sucesso do /token (PDF §2.4). {@code idToken} é nulo na rotação do refresh token. */
public record TokenResponse(String accessToken, long expiresIn, String scope, String refreshToken, String idToken) {

    public Map<String, Object> toJson() {
        Map<String, Object> json = new LinkedHashMap<>();
        json.put("access_token", accessToken);
        json.put("token_type", "Bearer");
        json.put("expires_in", expiresIn);
        json.put("scope", scope);
        json.put("refresh_token", refreshToken);
        if (idToken != null) {
            json.put("id_token", idToken);
        }
        return json;
    }
}
