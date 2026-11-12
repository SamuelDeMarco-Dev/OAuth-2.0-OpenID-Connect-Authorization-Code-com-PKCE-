package br.unoesc.cyber.authserver.client;

import java.time.Instant;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** Aplicação cadastrada. O client_secret só existe como hash BCrypt. */
@Entity
@Table(name = "oauth_client")
public class OAuthClient {

    @Id
    @Column(name = "client_id")
    private String clientId;

    @Column(name = "client_secret_hash", nullable = false)
    private String clientSecretHash;

    @Column(name = "redirect_uri", nullable = false)
    private String redirectUri;

    @Column(name = "allowed_scopes", nullable = false)
    private String allowedScopes;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected OAuthClient() {
    }

    public OAuthClient(String clientId, String clientSecretHash, String redirectUri, String allowedScopes, Instant createdAt) {
        this.clientId = clientId;
        this.clientSecretHash = clientSecretHash;
        this.redirectUri = redirectUri;
        this.allowedScopes = allowedScopes;
        this.createdAt = createdAt;
    }

    /** Comparação EXATA de string (RFC 9700 §2.1): sem curinga, prefixo ou normalização. */
    public boolean isRegisteredRedirectUri(String candidate) {
        return redirectUri.equals(candidate);
    }

    public Set<String> allowedScopeSet() {
        return Arrays.stream(allowedScopes.split(" ")).filter(s -> !s.isBlank()).collect(Collectors.toUnmodifiableSet());
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecretHash() {
        return clientSecretHash;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    void update(String clientSecretHash, String redirectUri, String allowedScopes) {
        this.clientSecretHash = clientSecretHash;
        this.redirectUri = redirectUri;
        this.allowedScopes = allowedScopes;
    }
}
