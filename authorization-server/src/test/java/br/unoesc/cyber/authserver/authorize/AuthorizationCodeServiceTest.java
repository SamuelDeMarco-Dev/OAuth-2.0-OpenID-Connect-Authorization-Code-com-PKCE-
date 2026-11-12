package br.unoesc.cyber.authserver.authorize;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.util.UriComponentsBuilder;

import br.unoesc.cyber.authserver.crypto.Hashes;
import br.unoesc.cyber.authserver.support.AbstractIntegrationTest;

class AuthorizationCodeServiceTest extends AbstractIntegrationTest {

    static final String STATE = "abc&def=1+2/3?ç%";

    @Autowired
    AuthorizationCodeService service;
    @Autowired
    AuthorizationCodeRepository codes;

    static AuthorizationRequest request() {
        return new AuthorizationRequest(CLIENT_ID, REDIRECT_URI, List.of("openid", "profile", "email"), STATE,
                "nonce-xyz", AuthorizeControllerTest.CHALLENGE);
    }

    static String param(String url, String name) {
        String raw = UriComponentsBuilder.fromUriString(url).build(true).getQueryParams().getFirst(name);
        return raw == null ? null : URLDecoder.decode(raw, StandardCharsets.UTF_8);
    }

    @Test
    void aprovaEmiteCodeVinculadoEStateIdentico() {
        Instant antes = Instant.now();
        String url = service.approve(request(), "sub-123");

        assertThat(url).startsWith(REDIRECT_URI + "?code=");
        assertThat(param(url, "state")).isEqualTo(STATE);
        String code = param(url, "code");
        assertThat(code).hasSize(43);

        assertThat(codes.findById(code)).as("valor bruto não é armazenado").isEmpty();
        AuthorizationCode saved = codes.findById(Hashes.sha256Hex(code)).orElseThrow();
        assertThat(saved.getClientId()).isEqualTo(CLIENT_ID);
        assertThat(saved.getRedirectUri()).isEqualTo(REDIRECT_URI);
        assertThat(saved.getCodeChallenge()).isEqualTo(AuthorizeControllerTest.CHALLENGE);
        assertThat(saved.getUserSub()).isEqualTo("sub-123");
        assertThat(saved.getNonce()).isEqualTo("nonce-xyz");
        assertThat(saved.getScope()).isEqualTo("openid profile email");
        assertThat(saved.getUsedAt()).isNull();
        assertThat(Duration.between(antes, saved.getExpiresAt())).isLessThanOrEqualTo(Duration.ofSeconds(61));
    }

    @Test
    void codesSaoUnicos() {
        assertThat(param(service.approve(request(), "s"), "code")).isNotEqualTo(param(service.approve(request(), "s"), "code"));
    }

    @Test
    void negacaoRetornaAccessDeniedComState() {
        String url = service.deny(request());
        assertThat(param(url, "error")).isEqualTo("access_denied");
        assertThat(param(url, "state")).isEqualTo(STATE);
        assertThat(param(url, "code")).isNull();
    }
}
