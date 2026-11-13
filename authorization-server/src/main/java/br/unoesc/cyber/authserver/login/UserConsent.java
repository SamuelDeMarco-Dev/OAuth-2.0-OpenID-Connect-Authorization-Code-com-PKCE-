package br.unoesc.cyber.authserver.login;

import java.io.Serializable;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;

/** Registro explícito do consentimento do usuário para um cliente (PDF §2.3). */
@Entity
@Table(name = "user_consent")
@IdClass(UserConsent.Key.class)
public class UserConsent {

    @Id
    @Column(name = "user_sub")
    private String userSub;

    @Id
    @Column(name = "client_id")
    private String clientId;

    @Column(nullable = false)
    private String scopes;

    @Column(name = "granted_at", nullable = false)
    private Instant grantedAt;

    protected UserConsent() {
    }

    public UserConsent(String userSub, String clientId, Collection<String> scopes, Instant grantedAt) {
        this.userSub = userSub;
        this.clientId = clientId;
        this.scopes = String.join(" ", scopes);
        this.grantedAt = grantedAt;
    }

    public boolean covers(Collection<String> requested) {
        return scopeSet().containsAll(requested);
    }

    public Set<String> scopeSet() {
        return Arrays.stream(scopes.split(" ")).filter(s -> !s.isBlank()).collect(Collectors.toSet());
    }

    public Instant getGrantedAt() {
        return grantedAt;
    }

    public record Key(String userSub, String clientId) implements Serializable {

        public Key() {
            this(null, null);
        }
    }
}
