package br.unoesc.cyber.client.token;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;

import br.unoesc.cyber.client.config.OidcClientProperties;
import br.unoesc.cyber.client.discovery.JwksCache;
import br.unoesc.cyber.client.discovery.ProviderMetadataService;

/**
 * Validação do ID Token conforme o checklist §4.3 (OIDC Core §3.1.3.7, RFC 8725).
 *
 * <p>Regra central (RFC 8725 §3.1): o algoritmo vem de uma LISTA FIXA da configuração. O {@code alg}
 * do cabeçalho só é COMPARADO com essa lista; o verificador é sempre RSA e a chave vem do JWKS do
 * emissor pelo {@code kid}. Assim {@code alg=none} e HS256 "assinado com a chave pública" são recusados.
 */
@Component
public class IdTokenValidator {

    private static final Logger log = LoggerFactory.getLogger(IdTokenValidator.class);

    private final OidcClientProperties props;
    private final ProviderMetadataService metadata;
    private final JwksCache jwks;
    private final Clock clock;
    private final Set<JWSAlgorithm> accepted;

    public IdTokenValidator(OidcClientProperties props, ProviderMetadataService metadata, JwksCache jwks, Clock clock) {
        this.props = props;
        this.metadata = metadata;
        this.jwks = jwks;
        this.clock = clock;
        this.accepted = props.acceptedAlgorithms().stream().map(JWSAlgorithm::parse).collect(Collectors.toUnmodifiableSet());
        if (accepted.isEmpty() || !JWSAlgorithm.Family.RSA.containsAll(accepted)) {
            throw new IllegalStateException("accepted-algorithms deve conter apenas algoritmos RSA (ex.: RS256)");
        }
    }

    public ValidatedIdToken validate(String idToken, String expectedNonce) {
        List<String> evidence = new ArrayList<>();
        try {
            ValidatedIdToken result = doValidate(idToken, expectedNonce, evidence);
            log.info("ID Token válido (sub={}):\n  {}", result.sub(), String.join("\n  ", evidence));
            return result;
        } catch (IdTokenValidationException e) {
            log.warn("ID Token REJEITADO — {} (verificações anteriores: {})", e.getMessage(), evidence);
            throw e;
        }
    }

    private ValidatedIdToken doValidate(String idToken, String expectedNonce, List<String> evidence) {
        JWT jwt;
        try {
            jwt = JWTParser.parse(idToken);
        } catch (ParseException | NullPointerException e) {
            throw new IdTokenValidationException(1, "token malformado");
        }

        // #2 — algoritmo na lista fixa; "none" (JWT não assinado) sempre rejeitado
        if (!(jwt instanceof SignedJWT signed)) {
            throw new IdTokenValidationException(2, "alg=none (token sem assinatura) não é aceito");
        }
        JWSAlgorithm alg = signed.getHeader().getAlgorithm();
        if (!accepted.contains(alg)) {
            throw new IdTokenValidationException(2, "alg " + alg + " fora da lista fixa " + accepted);
        }
        evidence.add("#2 alg " + alg + " está na lista fixa " + accepted);

        // #1 — assinatura com a chave pública do emissor, localizada pelo kid
        String kid = signed.getHeader().getKeyID();
        RSAKey key = jwks.find(kid)
                .orElseThrow(() -> new IdTokenValidationException(1, "chave não encontrada no JWKS para kid=" + kid));
        try {
            if (!signed.verify(new RSASSAVerifier(key.toRSAPublicKey()))) {
                throw new IdTokenValidationException(1, "assinatura inválida");
            }
        } catch (JOSEException e) {
            throw new IdTokenValidationException(1, "assinatura inválida");
        }
        evidence.add("#1 assinatura " + alg + " conferida com a chave kid=" + kid + " do JWKS do emissor");

        JWTClaimsSet claims;
        try {
            claims = signed.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new IdTokenValidationException(1, "payload malformado");
        }

        // #3 — iss idêntico ao issuer da descoberta
        String issuer = metadata.get().issuer();
        if (!issuer.equals(claims.getIssuer())) {
            throw new IdTokenValidationException(3, "iss '" + claims.getIssuer() + "' difere de '" + issuer + "'");
        }
        evidence.add("#3 iss == " + issuer);

        // #4 — aud contém o client_id
        List<String> aud = claims.getAudience();
        if (aud == null || !aud.contains(props.clientId())) {
            throw new IdTokenValidationException(4, "aud " + aud + " não contém " + props.clientId());
        }
        evidence.add("#4 aud " + aud + " contém " + props.clientId());

        // #5 — vários destinatários exigem azp == client_id (azp presente também precisa conferir)
        String azp = claim(claims, "azp");
        if (aud.size() > 1 && azp == null) {
            throw new IdTokenValidationException(5, "aud com vários valores e azp ausente");
        }
        if (azp != null && !azp.equals(props.clientId())) {
            throw new IdTokenValidationException(5, "azp '" + azp + "' difere de " + props.clientId());
        }
        evidence.add("#5 " + (aud.size() > 1 ? "aud múltiplo e azp == " + azp : "aud único" + (azp != null ? ", azp == " + azp : "")));

        Instant now = clock.instant();
        Duration skew = props.clockSkew();
        // #6 — exp no futuro (tolerância)
        Date exp = claims.getExpirationTime();
        if (exp == null || !now.isBefore(exp.toInstant().plus(skew))) {
            throw new IdTokenValidationException(6, "token expirado (exp=" + (exp == null ? null : exp.toInstant()) + ")");
        }
        evidence.add("#6 exp " + exp.toInstant() + " está no futuro (tolerância " + skew.toSeconds() + " s)");

        // #7 — iat não está no futuro
        Date iat = claims.getIssueTime();
        if (iat == null || iat.toInstant().isAfter(now.plus(skew))) {
            throw new IdTokenValidationException(7, "iat ausente ou no futuro (iat=" + (iat == null ? null : iat.toInstant()) + ")");
        }
        evidence.add("#7 iat " + iat.toInstant() + " não está no futuro");

        // #8 — nonce idêntico ao enviado
        String nonce = claim(claims, "nonce");
        if (expectedNonce == null || nonce == null || !MessageDigest.isEqual(
                nonce.getBytes(StandardCharsets.UTF_8), expectedNonce.getBytes(StandardCharsets.UTF_8))) {
            throw new IdTokenValidationException(8, "nonce diferente do enviado");
        }
        evidence.add("#8 nonce idêntico ao enviado no /authorize");

        String sub = claims.getSubject();
        if (sub == null || sub.isBlank()) {
            throw new IdTokenValidationException(9, "sub ausente");
        }
        Boolean emailVerified = bool(claims, "email_verified");
        return new ValidatedIdToken(issuer, sub, claim(claims, "name"), claim(claims, "email"),
                Boolean.TRUE.equals(emailVerified), claim(claims, "role"), List.copyOf(evidence));
    }

    private static String claim(JWTClaimsSet claims, String name) {
        try {
            return claims.getStringClaim(name);
        } catch (ParseException e) {
            return null;
        }
    }

    private static Boolean bool(JWTClaimsSet claims, String name) {
        try {
            return claims.getBooleanClaim(name);
        } catch (ParseException e) {
            return null;
        }
    }
}
