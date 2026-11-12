package br.unoesc.cyber.authserver.jwk;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import br.unoesc.cyber.authserver.config.AuthServerProperties;
import br.unoesc.cyber.authserver.support.TestKeys;

class SigningKeysTest {

    static AuthServerProperties.SigningKey props(String kid, String path, String prevKid, String prevPath) {
        return new AuthServerProperties.SigningKey(kid, path, prevKid, prevPath);
    }

    @Test
    void rotacaoPublicaChaveAtualEAnterior() {
        KeyPair atual = TestKeys.generate();
        KeyPair anterior = TestKeys.generate();
        SigningKeys keys = new SigningKeys(props("2026-11", TestKeys.writePrivatePem(atual).toString(),
                "2026-10", TestKeys.writePublicPem(anterior).toString()));

        assertThat(keys.publicJwkSet().getKeys()).extracting(k -> k.getKeyID()).containsExactly("2026-11", "2026-10");
        assertThat(keys.publicJwkSet().getKeys()).allMatch(k -> !k.isPrivate());
        assertThat(keys.publicKey("2026-10")).get().extracting(k -> {
            try {
                return k.toRSAPublicKey();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }).isEqualTo((RSAPublicKey) anterior.getPublic());
        assertThat(keys.publicKey("desconhecido")).isEmpty();
    }

    @Test
    void tokenAssinadoEVerificavelPelaChavePublicadaNoKid() throws Exception {
        SigningKeys keys = new SigningKeys(props("k1", TestKeys.writePrivatePem(TestKeys.generate()).toString(), null, null));
        String jwt = new JwtSigner(keys).sign(new JWTClaimsSet.Builder().subject("123").build(), JOSEObjectType.JWT);

        SignedJWT parsed = SignedJWT.parse(jwt);
        assertThat(parsed.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        assertThat(parsed.getHeader().getKeyID()).isEqualTo("k1");
        assertThat(parsed.getHeader().getType()).isEqualTo(JOSEObjectType.JWT);
        RSAKey pub = keys.publicKey("k1").orElseThrow();
        assertThat(parsed.verify(new RSASSAVerifier(pub))).isTrue();
    }

    @Test
    void falhaComMensagemClaraSemArquivoDeChave() {
        assertThatThrownBy(() -> new SigningKeys(props("k1", "/nao/existe.pem", null, null)))
                .hasMessageContaining("gen-dev-secrets.sh");
    }
}
