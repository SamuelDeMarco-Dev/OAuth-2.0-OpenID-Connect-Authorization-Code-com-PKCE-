package br.unoesc.cyber.authserver.error;

import org.springframework.http.HttpStatus;

/** Códigos de erro do RFC 6749 §4.1.2.1 / §5.2 e RFC 6750 §3.1, com o status HTTP do PDF §2.8. */
public enum OAuthError {
    INVALID_REQUEST("invalid_request", HttpStatus.BAD_REQUEST),
    INVALID_CLIENT("invalid_client", HttpStatus.UNAUTHORIZED),
    INVALID_GRANT("invalid_grant", HttpStatus.BAD_REQUEST),
    UNAUTHORIZED_CLIENT("unauthorized_client", HttpStatus.BAD_REQUEST),
    UNSUPPORTED_GRANT_TYPE("unsupported_grant_type", HttpStatus.BAD_REQUEST),
    INVALID_SCOPE("invalid_scope", HttpStatus.BAD_REQUEST),
    UNSUPPORTED_RESPONSE_TYPE("unsupported_response_type", HttpStatus.BAD_REQUEST),
    ACCESS_DENIED("access_denied", HttpStatus.FORBIDDEN),
    INVALID_TOKEN("invalid_token", HttpStatus.UNAUTHORIZED),
    SERVER_ERROR("server_error", HttpStatus.INTERNAL_SERVER_ERROR);

    private final String code;
    private final HttpStatus status;

    OAuthError(String code, HttpStatus status) {
        this.code = code;
        this.status = status;
    }

    public String code() {
        return code;
    }

    public HttpStatus status() {
        return status;
    }
}
