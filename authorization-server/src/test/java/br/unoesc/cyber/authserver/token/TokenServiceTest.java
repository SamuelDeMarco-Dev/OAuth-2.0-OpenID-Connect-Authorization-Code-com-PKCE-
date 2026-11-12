package br.unoesc.cyber.authserver.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import br.unoesc.cyber.authserver.authorize.AuthorizationCode;
import br.unoesc.cyber.authserver.authorize.AuthorizationCodeRepository;
import br.unoesc.cyber.authserver.authorize.AuthorizationRequest;
import br.unoesc.cyber.authserver.crypto.Hashes;
import br.unoesc.cyber.authserver.error.OAuthException;
import br.unoesc.cyber.authserver.support.AbstractIntegrationTest;
import br.unoesc.cyber.authserver.user.AppUser;
import br.unoesc.cyber.authserver.user.AppUserRepository;

class TokenServiceTest extends AbstractIntegrationTest {

    @Autowired
    TokenService service;
    @Autowired
    AuthorizationCodeRepository codes;
    @Autowired
    IssuedTokenRepository tokens;
    @Autowired
    AppUserRepository users;

    AuthorizationCode savedCode(AppUser user) {
        var req = new AuthorizationRequest(CLIENT_ID, REDIRECT_URI, List.of("openid", "profile", "email"), "st", "n-123",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        return codes.save(new AuthorizationCode(Hashes.sha256Hex(Hashes.randomToken(new java.security.SecureRandom(), 32)),
                req, user.getSub(), Instant.now().plusSeconds(60)));
    }

    static SignedJWT verified(String jwt) throws Exception {
        SignedJWT parsed = SignedJWT.parse(jwt);
        assertThat(parsed.verify(new RSASSAVerifier((RSAPublicKey) SIGNING_KEYS.getPublic()))).isTrue();
        return parsed;
    }

    @Test
    void idTokenComTodosOsClaimsObrigatorios() throws Exception {
        AppUser admin = users.findByUsername(ADMIN).orElseThrow();
        TokenResponse resp = service.issueForCode(savedCode(admin));

        SignedJWT id = verified(resp.idToken());
        assertThat(id.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        assertThat(id.getHeader().getType()).isEqualTo(JOSEObjectType.JWT);
        assertThat(id.getHeader().getKeyID()).isEqualTo(KID);
        JWTClaimsSet c = id.getJWTClaimsSet();
        assertThat(c.getIssuer()).isEqualTo(ISSUER);
        assertThat(c.getSubject()).isEqualTo(admin.getSub());
        assertThat(c.getAudience()).containsExactly(CLIENT_ID);
        assertThat(c.getStringClaim("azp")).isEqualTo(CLIENT_ID);
        assertThat(c.getStringClaim("nonce")).isEqualTo("n-123");
        assertThat(c.getStringClaim("name")).isEqualTo(admin.getFullName());
        assertThat(c.getStringClaim("email")).isEqualTo(admin.getEmail());
        assertThat(c.getBooleanClaim("email_verified")).isTrue();
        assertThat(c.getStringClaim("role")).isEqualTo("admin");
        assertThat(c.getExpirationTime().getTime() - c.getIssueTime().getTime()).isEqualTo(900_000L);
    }

    @Test
    void accessTokenDistintoDoIdToken() throws Exception {
        TokenResponse resp = service.issueForCode(savedCode(users.findByUsername(USER).orElseThrow()));
        SignedJWT at = verified(resp.accessToken());
        assertThat(at.getHeader().getType()).isEqualTo(TokenService.ACCESS_TOKEN_TYPE);
        assertThat(at.getJWTClaimsSet().getAudience()).containsExactly(ISSUER);
        assertThat(at.getJWTClaimsSet().getStringClaim("scope")).isEqualTo("openid profile email");
        assertThat(resp.expiresIn()).isEqualTo(900);
        assertThat(resp.toJson()).containsKeys("access_token", "token_type", "expires_in", "scope", "refresh_token",
                "id_token").containsEntry("token_type", "Bearer");
        assertThat(tokens.findById(at.getJWTClaimsSet().getJWTID())).get()
                .extracting(IssuedToken::getTokenType).isEqualTo(IssuedToken.ACCESS);
        assertThat(tokens.findById(resp.refreshToken())).as("refresh só como hash").isEmpty();
    }

    @Test
    void refreshRotativoEVinculadoAoCliente() {
        TokenResponse first = service.issueForCode(savedCode(users.findByUsername(USER).orElseThrow()));

        assertThatThrownBy(() -> service.refresh(first.refreshToken(), "outro-cliente"))
                .isInstanceOf(OAuthException.class).hasMessageContaining("cliente");

        TokenResponse second = service.refresh(first.refreshToken(), CLIENT_ID);
        assertThat(second.refreshToken()).isNotEqualTo(first.refreshToken());
        assertThat(second.idToken()).isNull();
        assertThat(tokens.findById(Hashes.sha256Hex(first.refreshToken())).orElseThrow().isRevoked()).isTrue();

        // reutilizar o refresh antigo revoga a família inteira, inclusive o novo
        assertThatThrownBy(() -> service.refresh(first.refreshToken(), CLIENT_ID)).isInstanceOf(OAuthException.class);
        assertThat(tokens.findById(Hashes.sha256Hex(second.refreshToken())).orElseThrow().isRevoked()).isTrue();
    }
}
