package br.unoesc.cyber.authserver.token;

import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.util.Set;

import org.springframework.stereotype.Component;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import br.unoesc.cyber.authserver.config.AuthServerProperties;
import br.unoesc.cyber.authserver.error.OAuthError;
import br.unoesc.cyber.authserver.error.OAuthException;
import br.unoesc.cyber.authserver.jwk.SigningKeys;

/**
 * Valida access tokens apresentados como Bearer. A lista de algoritmos é FIXA (RFC 8725 §3.1):
 * o header {@code alg} só é comparado, nunca usado para escolher o verificador.
 */
@Component
public class AccessTokenVerifier {

    private static final Set<JWSAlgorithm> ACCEPTED = Set.of(JWSAlgorithm.RS256);

    private final SigningKeys keys;
    private final IssuedTokenRepository tokens;
    private final AuthServerProperties props;
    private final Clock clock;

    AccessTokenVerifier(SigningKeys keys, IssuedTokenRepository tokens, AuthServerProperties props, Clock clock) {
        this.keys = keys;
        this.tokens = tokens;
        this.props = props;
        this.clock = clock;
    }

    public VerifiedAccessToken verify(String token) {
        SignedJWT jwt;
        JWTClaimsSet claims;
        try {
            jwt = SignedJWT.parse(token);
            claims = jwt.getJWTClaimsSet();
        } catch (ParseException e) {
            throw invalid("token malformado");
        }
        if (!ACCEPTED.contains(jwt.getHeader().getAlgorithm())) {
            throw invalid("algoritmo não aceito");
        }
        if (!TokenService.ACCESS_TOKEN_TYPE.equals(jwt.getHeader().getType())) {
            throw invalid("não é um access token");
        }
        String kid = jwt.getHeader().getKeyID();
        RSAKey key = kid == null ? null : keys.publicKey(kid).orElse(null);
        if (key == null) {
            throw invalid("kid desconhecido");
        }
        try {
            if (!jwt.verify(new RSASSAVerifier(key))) {
                throw invalid("assinatura inválida");
            }
        } catch (JOSEException e) {
            throw invalid("assinatura inválida");
        }
        Instant now = Instant.now(clock);
        if (!props.issuer().equals(claims.getIssuer())
                || claims.getAudience() == null || !claims.getAudience().contains(props.issuer())) {
            throw invalid("emissor ou audiência inválidos");
        }
        if (claims.getExpirationTime() == null || !now.isBefore(claims.getExpirationTime().toInstant())) {
            throw invalid("token expirado");
        }
        IssuedToken record = claims.getJWTID() == null ? null : tokens.findById(claims.getJWTID())
                .filter(t -> IssuedToken.ACCESS.equals(t.getTokenType())).orElse(null);
        if (record == null || !record.isActive(now)) {
            throw invalid("token revogado ou desconhecido");
        }
        return new VerifiedAccessToken(record.getUserSub(), record.getClientId(), record.getScope());
    }

    private static OAuthException invalid(String description) {
        return new OAuthException(OAuthError.INVALID_TOKEN, description);
    }

    public record VerifiedAccessToken(String sub, String clientId, String scope) {

        public boolean hasScope(String s) {
            return Set.of(scope.split(" ")).contains(s);
        }
    }
}
