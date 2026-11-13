package br.unoesc.cyber.authserver.userinfo;

import static br.unoesc.cyber.authserver.support.OAuthTestFlows.VERIFIER;
import static br.unoesc.cyber.authserver.support.OAuthTestFlows.issueCode;
import static br.unoesc.cyber.authserver.support.OAuthTestFlows.tokenRequest;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Date;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.PlainHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

import br.unoesc.cyber.authserver.authorize.AuthorizationCodeService;
import br.unoesc.cyber.authserver.jwk.JwtSigner;
import br.unoesc.cyber.authserver.support.AbstractIntegrationTest;
import br.unoesc.cyber.authserver.token.TokenService;
import br.unoesc.cyber.authserver.user.AppUser;
import br.unoesc.cyber.authserver.user.AppUserRepository;

class UserInfoControllerTest extends AbstractIntegrationTest {

    @Autowired
    MockMvc mvc;
    @Autowired
    AuthorizationCodeService codeService;
    @Autowired
    AppUserRepository users;
    @Autowired
    JwtSigner signer;

    String tokens(AppUser user) throws Exception {
        return mvc.perform(tokenRequest(issueCode(codeService, user.getSub()), VERIFIER))
                .andReturn().getResponse().getContentAsString();
    }

    ResultActions userinfo(String bearer) throws Exception {
        return mvc.perform(get("/userinfo").header(HttpHeaders.AUTHORIZATION, "Bearer " + bearer));
    }

    static void expectInvalidToken(ResultActions r) throws Exception {
        r.andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, startsWith("Bearer")))
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("invalid_token")));
    }

    JWTClaimsSet.Builder claims(AppUser user) {
        return new JWTClaimsSet.Builder().issuer(ISSUER).subject(user.getSub()).audience(ISSUER)
                .jwtID(UUID.randomUUID().toString()).issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 60_000));
    }

    @Test
    void devolveSubIgualAoDoIdTokenComNameEEmail() throws Exception {
        AppUser admin = users.findByUsername(ADMIN).orElseThrow();
        String body = tokens(admin);
        String access = JsonPath.read(body, "$.access_token");
        String idSub = SignedJWT.parse(JsonPath.<String>read(body, "$.id_token")).getJWTClaimsSet().getSubject();

        userinfo(access).andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
                .andExpect(jsonPath("$.sub").value(idSub))
                .andExpect(jsonPath("$.name").value(admin.getFullName()))
                .andExpect(jsonPath("$.email").value(admin.getEmail()))
                .andExpect(jsonPath("$.email_verified").value(true));
        mvc.perform(post("/userinfo").header(HttpHeaders.AUTHORIZATION, "Bearer " + access))
                .andExpect(status().isOk()).andExpect(jsonPath("$.sub").value(idSub));
    }

    /** Teste negativo #14 (sem token). */
    @Test
    void negativo14a_semToken_401ComWwwAuthenticate() throws Exception {
        mvc.perform(get("/userinfo"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Bearer realm=\"authorization-server\""));
    }

    /** Teste negativo #14 (token expirado). */
    @Test
    void negativo14b_tokenExpirado_401ComWwwAuthenticate() throws Exception {
        AppUser user = users.findByUsername(USER).orElseThrow();
        String expired = signer.sign(claims(user).issueTime(new Date(System.currentTimeMillis() - 1_000_000))
                .expirationTime(new Date(System.currentTimeMillis() - 1000)).build(), TokenService.ACCESS_TOKEN_TYPE);
        expectInvalidToken(userinfo(expired));
    }

    @Test
    void assinaturaAlterada401() throws Exception {
        String access = JsonPath.read(tokens(users.findByUsername(USER).orElseThrow()), "$.access_token");
        char last = access.charAt(access.length() - 5);
        String tampered = access.substring(0, access.length() - 5) + (last == 'A' ? 'B' : 'A')
                + access.substring(access.length() - 4);
        expectInvalidToken(userinfo(tampered));
    }

    @Test
    void idTokenNaoServeComoAccessToken() throws Exception {
        String id = JsonPath.read(tokens(users.findByUsername(USER).orElseThrow()), "$.id_token");
        expectInvalidToken(userinfo(id));
    }

    @Test
    void algNoneRejeitado() throws Exception {
        AppUser user = users.findByUsername(USER).orElseThrow();
        String none = new PlainJWT(new PlainHeader.Builder().type(TokenService.ACCESS_TOKEN_TYPE).build(),
                claims(user).build()).serialize();
        expectInvalidToken(userinfo(none));
    }

    @Test
    void hs256ComChavePublicaComoSegredoRejeitado() throws Exception {
        AppUser user = users.findByUsername(USER).orElseThrow();
        SignedJWT hs = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).type(TokenService.ACCESS_TOKEN_TYPE)
                .keyID(KID).build(), claims(user).build());
        hs.sign(new MACSigner(SIGNING_KEYS.getPublic().getEncoded()));
        expectInvalidToken(userinfo(hs.serialize()));
    }

    @Test
    void tokenNaoEmitidoPeloServidorRejeitado() throws Exception {
        // assinatura válida, mas jti nunca registrado
        String forged = signer.sign(claims(users.findByUsername(USER).orElseThrow()).build(),
                TokenService.ACCESS_TOKEN_TYPE);
        expectInvalidToken(userinfo(forged));
    }

    @Test
    void lixoNoBearerRejeitado() throws Exception {
        expectInvalidToken(userinfo("abc.def"));
        expectInvalidToken(mvc.perform(get("/userinfo").header(HttpHeaders.AUTHORIZATION, "Bearer x"
                + JOSEObjectType.JWT)));
    }
}
