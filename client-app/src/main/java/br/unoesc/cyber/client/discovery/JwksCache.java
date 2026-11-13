package br.unoesc.cyber.client.discovery;

import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

/**
 * Chaves públicas do provedor indexadas por {@code kid}. Um {@code kid} desconhecido provoca UMA
 * nova leitura do JWKS (o provedor pode ter girado a chave), limitada a uma a cada 10 s para que
 * tokens forjados com kids aleatórios não virem um amplificador de requisições.
 */
@Component
public class JwksCache {

    private static final Logger log = LoggerFactory.getLogger(JwksCache.class);
    static final Duration MIN_REFRESH_INTERVAL = Duration.ofSeconds(10);

    private final RestClient http;
    private final ProviderMetadataService metadata;
    private final Clock clock;
    private volatile Map<String, RSAKey> keys = Map.of();
    private volatile Instant lastFetch;

    public JwksCache(RestClient oidcRestClient, ProviderMetadataService metadata, Clock clock) {
        this.http = oidcRestClient;
        this.metadata = metadata;
        this.clock = clock;
    }

    /** Chave RSA de assinatura com esse kid. Vazio = chave não encontrada (erro de validação). */
    public Optional<RSAKey> find(String kid) {
        if (kid == null) {
            return Optional.empty();
        }
        RSAKey key = keys.get(kid);
        if (key == null && mayRefresh()) {
            refresh();
            key = keys.get(kid);
        }
        return Optional.ofNullable(key);
    }

    private synchronized boolean mayRefresh() {
        Instant now = clock.instant();
        return lastFetch == null || !now.isBefore(lastFetch.plus(MIN_REFRESH_INTERVAL));
    }

    private synchronized void refresh() {
        lastFetch = clock.instant();
        String uri = metadata.get().jwksUri();
        try {
            JWKSet set = JWKSet.parse(http.get().uri(uri).retrieve().body(String.class));
            keys = set.getKeys().stream()
                    .filter(k -> k instanceof RSAKey)
                    .filter(k -> k.getKeyUse() == null || KeyUse.SIGNATURE.equals(k.getKeyUse()))
                    .filter(k -> k.getKeyID() != null)
                    .collect(Collectors.toUnmodifiableMap(JWK::getKeyID, k -> ((RSAKey) k).toPublicJWK(), (a, b) -> a));
            log.info("JWKS carregado de {}: kids={}", uri, keys.keySet());
        } catch (RestClientException | ParseException e) {
            throw new ProviderUnavailableException("Falha ao ler o JWKS em " + uri, e);
        }
    }
}
