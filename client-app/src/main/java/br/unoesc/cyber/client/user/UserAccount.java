package br.unoesc.cyber.client.user;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** Tabela {@code users} do PDF §4.1 (+ {@code oidc_iss}: o vínculo é iss + sub, OIDC Core §5.7). */
@Entity
@Table(name = "users")
public class UserAccount {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_name", nullable = false, unique = true)
    private String userName;

    @Column(name = "full_name")
    private String fullName;

    @Column(name = "oidc_iss", nullable = false, updatable = false)
    private String oidcIss;

    @Column(name = "oidc_sub", nullable = false, unique = true, updatable = false)
    private String oidcSub;

    @Column(nullable = false)
    private String role;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    protected UserAccount() {
    }

    UserAccount(String userName, String fullName, String oidcIss, String oidcSub, String role, Instant createdAt) {
        this.userName = userName;
        this.fullName = fullName;
        this.oidcIss = oidcIss;
        this.oidcSub = oidcSub;
        this.role = role;
        this.createdAt = createdAt;
    }

    void refresh(String fullName, String role) {
        this.fullName = fullName;
        this.role = role;
    }

    public Long getId() {
        return id;
    }

    public String getUserName() {
        return userName;
    }

    public String getFullName() {
        return fullName;
    }

    public String getOidcIss() {
        return oidcIss;
    }

    public String getOidcSub() {
        return oidcSub;
    }

    public String getRole() {
        return role;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
