package br.unoesc.cyber.authserver.token;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * Registro de cada token emitido. Para access/id token o {@code jti} é o claim do JWT;
 * para o refresh token (opaco) é o SHA-256 do valor. {@code codeHash} liga todos os tokens
 * à "família" do authorization code, permitindo revogação em bloco (PDF §2.4).
 */
@Entity
@Table(name = "issued_token")
public class IssuedToken {

    public static final String ACCESS = "access";
    public static final String REFRESH = "refresh";
    public static final String ID = "id";

    @Id
    private String jti;

    @Column(name = "token_type", nullable = false)
    private String tokenType;

    @Column(name = "code_hash")
    private String codeHash;

    @Column(name = "client_id", nullable = false)
    private String clientId;

    @Column(name = "user_sub", nullable = false)
    private String userSub;

    @Column(nullable = false)
    private String scope;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(nullable = false)
    private boolean revoked;

    protected IssuedToken() {
    }

    IssuedToken(String jti, String tokenType, String codeHash, String clientId, String userSub, String scope,
            Instant expiresAt) {
        this.jti = jti;
        this.tokenType = tokenType;
        this.codeHash = codeHash;
        this.clientId = clientId;
        this.userSub = userSub;
        this.scope = scope;
        this.expiresAt = expiresAt;
    }

    public boolean isActive(Instant now) {
        return !revoked && now.isBefore(expiresAt);
    }

    void revoke() {
        this.revoked = true;
    }

    public String getJti() {
        return jti;
    }

    public String getTokenType() {
        return tokenType;
    }

    public String getCodeHash() {
        return codeHash;
    }

    public String getClientId() {
        return clientId;
    }

    public String getUserSub() {
        return userSub;
    }

    public String getScope() {
        return scope;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public boolean isRevoked() {
        return revoked;
    }
}
