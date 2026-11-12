package br.unoesc.cyber.authserver.token;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jwt.JWTClaimsSet;

import br.unoesc.cyber.authserver.authorize.AuthorizationCode;
import br.unoesc.cyber.authserver.config.AuthServerProperties;
import br.unoesc.cyber.authserver.crypto.Hashes;
import br.unoesc.cyber.authserver.error.OAuthError;
import br.unoesc.cyber.authserver.error.OAuthException;
import br.unoesc.cyber.authserver.jwk.JwtSigner;
import br.unoesc.cyber.authserver.user.AppUser;
import br.unoesc.cyber.authserver.user.AppUserRepository;

/**
 * Emissão de tokens (PDF §2.4 e §2.5).
 * <ul>
 *   <li>ID Token: JWT RS256, {@code typ=JWT}, prova de identidade para o cliente.</li>
 *   <li>Access token: JWT RS256, {@code typ=at+jwt} (RFC 9068), credencial do /userinfo.
 *       O typ diferente impede que um ID Token seja aceito como access token.</li>
 *   <li>Refresh token: opaco, só o hash no banco, rotativo e vinculado ao cliente (RFC 9700 §4.14).</li>
 * </ul>
 */
@Service
public class TokenService {

    private static final Logger log = LoggerFactory.getLogger(TokenService.class);
    public static final JOSEObjectType ACCESS_TOKEN_TYPE = new JOSEObjectType("at+jwt");

    private final JwtSigner signer;
    private final IssuedTokenRepository tokens;
    private final AppUserRepository users;
    private final AuthServerProperties props;
    private final SecureRandom random;
    private final Clock clock;

    TokenService(JwtSigner signer, IssuedTokenRepository tokens, AppUserRepository users, AuthServerProperties props,
            SecureRandom random, Clock clock) {
        this.signer = signer;
        this.tokens = tokens;
        this.users = users;
        this.props = props;
        this.random = random;
        this.clock = clock;
    }

    /** Tokens para um authorization code já validado (code, cliente, redirect_uri e PKCE conferidos pelo /token). */
    @Transactional
    public TokenResponse issueForCode(AuthorizationCode code) {
        AppUser user = users.findBySub(code.getUserSub())
                .orElseThrow(() -> new OAuthException(OAuthError.INVALID_GRANT, "usuário do code não existe mais"));
        Instant now = Instant.now(clock);
        String idToken = idToken(user, code.getClientId(), code.getNonce(), code.getCodeHash(), code.getScope(), now);
        return accessAndRefresh(user.getSub(), code.getClientId(), code.getScope(), code.getCodeHash(), now, idToken);
    }

    /**
     * grant_type=refresh_token com rotação: o refresh apresentado é revogado e um novo é emitido.
     * Refresh já revogado = reutilização → revoga a família inteira (RFC 9700 §4.14.2).
     */
    @Transactional(noRollbackFor = OAuthException.class)
    public TokenResponse refresh(String refreshToken, String authenticatedClientId) {
        Instant now = Instant.now(clock);
        IssuedToken current = tokens.findById(Hashes.sha256Hex(refreshToken))
                .filter(t -> IssuedToken.REFRESH.equals(t.getTokenType()))
                .orElseThrow(() -> new OAuthException(OAuthError.INVALID_GRANT, "refresh_token inválido"));
        if (!current.getClientId().equals(authenticatedClientId)) {
            throw new OAuthException(OAuthError.INVALID_GRANT, "refresh_token não pertence a este cliente");
        }
        if (current.isRevoked()) {
            int n = tokens.revokeFamily(current.getCodeHash());
            log.warn("Reutilização de refresh_token detectada (client_id={}): {} tokens revogados",
                    authenticatedClientId, n);
            throw new OAuthException(OAuthError.INVALID_GRANT, "refresh_token já utilizado");
        }
        if (!current.isActive(now)) {
            throw new OAuthException(OAuthError.INVALID_GRANT, "refresh_token expirado");
        }
        current.revoke();
        return accessAndRefresh(current.getUserSub(), current.getClientId(), current.getScope(), current.getCodeHash(),
                now, null);
    }

    private TokenResponse accessAndRefresh(String sub, String clientId, String scope, String codeHash, Instant now,
            String idToken) {
        Instant accessExp = now.plus(props.accessTokenTtl());
        String accessJti = UUID.randomUUID().toString();
        String accessToken = signer.sign(new JWTClaimsSet.Builder()
                .issuer(props.issuer())
                .subject(sub)
                .audience(props.issuer())
                .claim("client_id", clientId)
                .claim("scope", scope)
                .jwtID(accessJti)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(accessExp))
                .build(), ACCESS_TOKEN_TYPE);
        tokens.save(new IssuedToken(accessJti, IssuedToken.ACCESS, codeHash, clientId, sub, scope, accessExp));

        String refreshToken = Hashes.randomToken(random, 32);
        tokens.save(new IssuedToken(Hashes.sha256Hex(refreshToken), IssuedToken.REFRESH, codeHash, clientId, sub, scope,
                now.plus(props.refreshTokenTtl())));

        return new TokenResponse(accessToken, props.accessTokenTtl().toSeconds(), scope, refreshToken, idToken);
    }

    private String idToken(AppUser user, String clientId, String nonce, String codeHash, String scope, Instant now) {
        Instant exp = now.plus(props.idTokenTtl());
        String jti = UUID.randomUUID().toString();
        String jwt = signer.sign(new JWTClaimsSet.Builder()
                .issuer(props.issuer())
                .subject(user.getSub())
                .audience(clientId)
                .expirationTime(Date.from(exp))
                .issueTime(Date.from(now))
                .jwtID(jti)
                .claim("nonce", nonce)
                .claim("azp", clientId)
                .claim("name", user.getFullName())
                .claim("email", user.getEmail())
                .claim("email_verified", user.isEmailVerified())
                .claim("role", user.getRole())
                .build(), JOSEObjectType.JWT);
        tokens.save(new IssuedToken(jti, IssuedToken.ID, codeHash, clientId, user.getSub(), scope, exp));
        return jwt;
    }
}
