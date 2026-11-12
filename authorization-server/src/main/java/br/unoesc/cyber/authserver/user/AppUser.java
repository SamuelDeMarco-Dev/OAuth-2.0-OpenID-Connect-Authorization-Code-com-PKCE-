package br.unoesc.cyber.authserver.user;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** Usuário do provedor. {@code sub} é gerado uma vez e nunca reatribuído (OIDC Core §2). */
@Entity
@Table(name = "app_user")
public class AppUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, updatable = false)
    private String sub;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    @Column(name = "full_name", nullable = false)
    private String fullName;

    private String email;

    @Column(name = "email_verified", nullable = false)
    private boolean emailVerified;

    @Column(nullable = false)
    private String role;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected AppUser() {
    }

    public AppUser(String sub, String username, String passwordHash, String fullName, String email,
            boolean emailVerified, String role, Instant createdAt) {
        this.sub = sub;
        this.username = username;
        this.passwordHash = passwordHash;
        this.fullName = fullName;
        this.email = email;
        this.emailVerified = emailVerified;
        this.role = role;
        this.createdAt = createdAt;
    }

    public Long getId() {
        return id;
    }

    public String getSub() {
        return sub;
    }

    public String getUsername() {
        return username;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public String getFullName() {
        return fullName;
    }

    public String getEmail() {
        return email;
    }

    public boolean isEmailVerified() {
        return emailVerified;
    }

    public String getRole() {
        return role;
    }
}
