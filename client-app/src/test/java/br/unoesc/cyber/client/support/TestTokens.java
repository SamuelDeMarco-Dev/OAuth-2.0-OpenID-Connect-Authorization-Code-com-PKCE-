package br.unoesc.cyber.client.support;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.PlainHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

import br.unoesc.cyber.client.discovery.JwksCache;
import br.unoesc.cyber.client.discovery.ProviderMetadata;
import br.unoesc.cyber.client.discovery.ProviderMetadataService;

/**
 * Fábrica de ID Tokens (válidos e forjados) com uma chave RSA gerada no teste — os testes
 * do validador não dependem do Servidor de Autorização rodando.
 */
public final class TestTokens {

    public static final String KID = "test-kid";
    public static final String SUB = "sub-123";
    public static final String NONCE = "nonce-abc";
    public static final RSAKey KEY = generate(KID);

    private TestTokens() {
    }

    public static RSAKey generate(String kid) {
        try {
            return new RSAKeyGenerator(2048).keyID(kid).keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.RS256).generate();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** Claims de um ID Token válido emitido "agora". */
    public static JWTClaimsSet.Builder validClaims(Instant now) {
        return new JWTClaimsSet.Builder()
                .issuer(TestProperties.ISSUER)
                .subject(SUB)
                .audience(TestProperties.CLIENT_ID)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(900)))
                .claim("nonce", NONCE)
                .claim("azp", TestProperties.CLIENT_ID)
                .claim("name", "Joao Silva")
                .claim("email", "joao@example.com")
                .claim("email_verified", true)
                .claim("role", "admin");
    }

    public static String rs256(JWTClaimsSet claims) {
        return rs256(claims, KEY);
    }

    public static String rs256(JWTClaimsSet claims, RSAKey key) {
        try {
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT)
                    .keyID(key.getKeyID()).build(), claims);
            jwt.sign(new RSASSASigner(key));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static String algNone(JWTClaimsSet claims) {
        return new PlainJWT(new PlainHeader.Builder().type(JOSEObjectType.JWT).build(), claims).serialize();
    }

    /** Ataque de confusão de algoritmo: HS256 usando a chave PÚBLICA como segredo HMAC. */
    public static String hs256WithPublicKey(JWTClaimsSet claims) {
        try {
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).type(JOSEObjectType.JWT)
                    .keyID(KID).build(), claims);
            jwt.sign(new MACSigner(KEY.toRSAPublicKey().getEncoded()));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** Altera um byte da assinatura (último segmento). */
    public static String tamperSignature(String jwt) {
        int i = jwt.length() - 5;
        return jwt.substring(0, i) + (jwt.charAt(i) == 'A' ? 'B' : 'A') + jwt.substring(i + 1);
    }

    /** Provedor fictício: descoberta fixa e JWKS com as chaves informadas. */
    public static ProviderMetadataService metadata() {
        ProviderMetadata m = new ProviderMetadata(TestProperties.ISSUER, TestProperties.ISSUER + "/authorize",
                TestProperties.ISSUER + "/token", TestProperties.ISSUER + "/userinfo",
                TestProperties.ISSUER + "/jwks.json", TestProperties.ISSUER + "/logout");
        return new ProviderMetadataService(null, TestProperties.props()) {
            @Override
            public ProviderMetadata get() {
                return m;
            }
        };
    }

    public static JwksCache jwks(RSAKey... keys) {
        Map<String, RSAKey> byKid = new java.util.HashMap<>();
        for (RSAKey k : keys) {
            byKid.put(k.getKeyID(), k.toPublicJWK());
        }
        return new JwksCache(null, null, null) {
            @Override
            public Optional<RSAKey> find(String kid) {
                return Optional.ofNullable(kid == null ? null : byKid.get(kid));
            }
        };
    }

    public static List<String> audience(String... values) {
        return List.of(values);
    }
}
