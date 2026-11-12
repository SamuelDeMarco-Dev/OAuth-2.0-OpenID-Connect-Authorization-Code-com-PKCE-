package br.unoesc.cyber.authserver.client;

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ClientRegistry {

    private final OAuthClientRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final Clock clock;
    /** Hash fixo usado quando o client_id não existe, para não vazar a existência pelo tempo de resposta. */
    private final String dummyHash;

    ClientRegistry(OAuthClientRepository repository, PasswordEncoder passwordEncoder, Clock clock) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
        this.clock = clock;
        this.dummyHash = passwordEncoder.encode("dummy-secret-for-timing");
    }

    public Optional<OAuthClient> findById(String clientId) {
        return clientId == null ? Optional.empty() : repository.findById(clientId);
    }

    /** Autentica o cliente pelo segredo. Vazio = invalid_client. */
    public Optional<OAuthClient> authenticate(String clientId, String clientSecret) {
        Optional<OAuthClient> client = findById(clientId);
        String hash = client.map(OAuthClient::getClientSecretHash).orElse(dummyHash);
        boolean ok = clientSecret != null && passwordEncoder.matches(clientSecret, hash);
        return ok ? client : Optional.empty();
    }

    /** Cria ou atualiza o cliente a partir do .env (idempotente). */
    @Transactional
    public void upsert(String clientId, String clientSecret, String redirectUri, String scopes) {
        repository.findById(clientId).ifPresentOrElse(existing -> {
            if (!passwordEncoder.matches(clientSecret, existing.getClientSecretHash())
                    || !existing.isRegisteredRedirectUri(redirectUri)) {
                existing.update(passwordEncoder.encode(clientSecret), redirectUri, scopes);
            }
        }, () -> repository.save(new OAuthClient(clientId, passwordEncoder.encode(clientSecret), redirectUri, scopes,
                Instant.now(clock))));
    }
}
