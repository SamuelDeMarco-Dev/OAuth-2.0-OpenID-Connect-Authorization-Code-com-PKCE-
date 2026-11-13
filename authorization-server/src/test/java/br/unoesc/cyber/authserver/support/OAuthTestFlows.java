package br.unoesc.cyber.authserver.support;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.util.UriComponentsBuilder;

import br.unoesc.cyber.authserver.authorize.AuthorizationCodeService;
import br.unoesc.cyber.authserver.authorize.AuthorizationRequest;

/** Atalhos para os testes do /token e /userinfo. */
public final class OAuthTestFlows {

    /** Vetor do RFC 7636, apêndice B. */
    public static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    public static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private OAuthTestFlows() {
    }

    /** Emite um code real via serviço (equivale a login + consentimento concluídos). */
    public static String issueCode(AuthorizationCodeService service, String sub) {
        String url = service.approve(new AuthorizationRequest(AbstractIntegrationTest.CLIENT_ID,
                AbstractIntegrationTest.REDIRECT_URI, List.of("openid", "profile", "email"), "state-1", "nonce-1",
                CHALLENGE), sub);
        String raw = UriComponentsBuilder.fromUriString(url).build(true).getQueryParams().getFirst("code");
        return URLDecoder.decode(raw, StandardCharsets.UTF_8);
    }

    public static String basic(String id, String secret) {
        return "Basic " + Base64.getEncoder().encodeToString((id + ":" + secret).getBytes(StandardCharsets.UTF_8));
    }

    public static MockHttpServletRequestBuilder tokenRequest(String code, String verifier) {
        return post("/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.AUTHORIZATION, basic(AbstractIntegrationTest.CLIENT_ID, AbstractIntegrationTest.CLIENT_SECRET))
                .param("grant_type", "authorization_code")
                .param("code", code)
                .param("redirect_uri", AbstractIntegrationTest.REDIRECT_URI)
                .param("code_verifier", verifier);
    }
}
