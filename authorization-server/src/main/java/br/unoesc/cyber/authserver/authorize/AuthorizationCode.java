package br.unoesc.cyber.authserver.authorize;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** Authorization code: só o hash SHA-256 é persistido; uso único e validade de 60 s (PDF §2.2). */
@Entity
@Table(name = "authorization_code")
public class AuthorizationCode {

    @Id
    @Column(name = "code_hash")
    private String codeHash;

    @Column(name = "client_id", nullable = false)
    private String clientId;

    @Column(name = "redirect_uri", nullable = false)
    private String redirectUri;

    @Column(name = "code_challenge", nullable = false)
    private String codeChallenge;

    @Column(name = "user_sub", nullable = false)
    private String userSub;

    @Column(nullable = false)
    private String nonce;

    @Column(nullable = false)
    private String scope;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "used_at")
    private Instant usedAt;

    protected AuthorizationCode() {
    }

    public AuthorizationCode(String codeHash, AuthorizationRequest req, String userSub, Instant expiresAt) {
        this.codeHash = codeHash;
        this.clientId = req.clientId();
        this.redirectUri = req.redirectUri();
        this.codeChallenge = req.codeChallenge();
        this.userSub = userSub;
        this.nonce = req.nonce();
        this.scope = req.scope();
        this.expiresAt = expiresAt;
    }

    public boolean isExpired(Instant now) {
        return !now.isBefore(expiresAt);
    }

    public String getCodeHash() {
        return codeHash;
    }

    public String getClientId() {
        return clientId;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public String getCodeChallenge() {
        return codeChallenge;
    }

    public String getUserSub() {
        return userSub;
    }

    public String getNonce() {
        return nonce;
    }

    public String getScope() {
        return scope;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Instant getUsedAt() {
        return usedAt;
    }
}
