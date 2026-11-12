package br.unoesc.cyber.authserver.jwk;

import java.nio.file.Path;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

import br.unoesc.cyber.authserver.config.AuthServerProperties;

/**
 * Chaves de assinatura. A chave atual assina; a anterior (opcional) só é publicada no JWKS
 * para que tokens emitidos antes da rotação continuem verificáveis (PDF §2.7).
 */
@Component
public class SigningKeys {

    private final RSAKey current;
    private final List<RSAKey> published;

    @Autowired
    public SigningKeys(AuthServerProperties props) {
        this(props.signingKey());
    }

    SigningKeys(AuthServerProperties.SigningKey cfg) {
        RSAPrivateCrtKey privateKey = PemKeys.readPrivateKey(Path.of(cfg.privateKeyPath()));
        this.current = new RSAKey.Builder(PemKeys.publicKeyOf(privateKey))
                .privateKey(privateKey)
                .keyID(cfg.kid())
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .build();

        List<RSAKey> keys = new ArrayList<>();
        keys.add(current.toPublicJWK());
        if (StringUtils.hasText(cfg.previousKid()) && StringUtils.hasText(cfg.previousPublicKeyPath())) {
            if (cfg.previousKid().equals(cfg.kid())) {
                throw new IllegalStateException("previous-kid deve ser diferente do kid atual");
            }
            keys.add(new RSAKey.Builder(PemKeys.readPublicKey(Path.of(cfg.previousPublicKeyPath())))
                    .keyID(cfg.previousKid())
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.RS256)
                    .build());
        }
        this.published = List.copyOf(keys);
    }

    /** Chave privada atual (uso exclusivo do assinador). */
    RSAKey current() {
        return current;
    }

    /** JWKS público: nunca contém parâmetros privados. */
    public JWKSet publicJwkSet() {
        return new JWKSet(List.copyOf(published));
    }

    /** Chave pública pelo kid (atual ou anterior), para verificar tokens emitidos por este servidor. */
    public Optional<RSAKey> publicKey(String kid) {
        return published.stream().filter(k -> k.getKeyID().equals(kid)).findFirst();
    }
}
