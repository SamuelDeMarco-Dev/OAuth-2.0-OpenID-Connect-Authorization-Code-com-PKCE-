package br.unoesc.cyber.authserver.error;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;

class OAuthExceptionHandlerTest {

    OAuthExceptionHandler handler = new OAuthExceptionHandler();

    @Test
    void statusDeCadaErroConformePdf() {
        assertThat(OAuthError.INVALID_REQUEST.status()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(OAuthError.INVALID_CLIENT.status()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(OAuthError.INVALID_GRANT.status()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(OAuthError.UNAUTHORIZED_CLIENT.status()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(OAuthError.UNSUPPORTED_GRANT_TYPE.status()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(OAuthError.INVALID_SCOPE.status()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void corpoJsonComCabecalhosNoStore() {
        var resp = handler.oauth(new OAuthException(OAuthError.INVALID_GRANT, "code expirado"));
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(resp.getBody()).containsEntry("error", "invalid_grant").containsEntry("error_description", "code expirado");
        assertThat(resp.getHeaders().getCacheControl()).isEqualTo("no-store");
        assertThat(resp.getHeaders().getFirst(HttpHeaders.PRAGMA)).isEqualTo("no-cache");
        assertThat(resp.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE)).isNull();
    }

    @Test
    void invalidClientTraz401ComWwwAuthenticate() {
        var resp = handler.oauth(new OAuthException(OAuthError.INVALID_CLIENT, "falha na autenticação do cliente"));
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(resp.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE)).startsWith("Basic realm=");
    }

    @Test
    void invalidTokenTrazBearer() {
        var resp = handler.oauth(new OAuthException(OAuthError.INVALID_TOKEN, "expirado"));
        assertThat(resp.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
                .startsWith("Bearer").contains("error=\"invalid_token\"");
    }

    @Test
    void erroDePaginaRenderizaTemplateSemRedirect() {
        var mv = handler.page(new ErrorPageException("redirect_uri não cadastrada"));
        assertThat(mv.getViewName()).isEqualTo("error");
        assertThat(mv.getModel()).containsEntry("message", "redirect_uri não cadastrada");
    }
}
