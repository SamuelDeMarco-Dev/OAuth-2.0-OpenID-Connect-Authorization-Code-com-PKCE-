package br.unoesc.cyber.client.session;

import java.time.Duration;
import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** Sessão local gravada no servidor. A chave é o SHA-256 do sessionID: o valor bruto só existe no cookie. */
@Entity
@Table(name = "local_session")
public class LocalSession {

    @Id
    @Column(name = "session_id")
    private String sessionIdHash;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "last_access_at", nullable = false)
    private Instant lastAccessAt;

    @Column(name = "absolute_exp", nullable = false)
    private Instant absoluteExp;

    protected LocalSession() {
    }

    LocalSession(String sessionIdHash, Long userId, Instant now, Duration absoluteTimeout) {
        this.sessionIdHash = sessionIdHash;
        this.userId = userId;
        this.createdAt = now;
        this.lastAccessAt = now;
        this.absoluteExp = now.plus(absoluteTimeout);
    }

    boolean isExpired(Instant now, Duration idleTimeout) {
        return !now.isBefore(absoluteExp) || !now.isBefore(lastAccessAt.plus(idleTimeout));
    }

    void touch(Instant now) {
        this.lastAccessAt = now;
    }

    public Long getUserId() {
        return userId;
    }

    public Instant getAbsoluteExp() {
        return absoluteExp;
    }

    public Instant getLastAccessAt() {
        return lastAccessAt;
    }
}
