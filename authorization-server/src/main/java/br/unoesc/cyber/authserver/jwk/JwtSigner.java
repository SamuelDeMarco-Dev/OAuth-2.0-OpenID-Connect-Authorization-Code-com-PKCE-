package br.unoesc.cyber.authserver.jwk;

import org.springframework.stereotype.Component;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/** Assina JWTs com RS256 e o kid da chave atual. HS256 nunca é usado (PDF §2.5). */
@Component
public class JwtSigner {

    private final SigningKeys keys;
    private final RSASSASigner signer;

    public JwtSigner(SigningKeys keys) {
        this.keys = keys;
        try {
            this.signer = new RSASSASigner(keys.current());
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    public String sign(JWTClaimsSet claims, JOSEObjectType type) {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(type)
                .keyID(keys.current().getKeyID())
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        try {
            jwt.sign(signer);
        } catch (JOSEException e) {
            throw new IllegalStateException("Falha ao assinar JWT", e);
        }
        return jwt.serialize();
    }
}
