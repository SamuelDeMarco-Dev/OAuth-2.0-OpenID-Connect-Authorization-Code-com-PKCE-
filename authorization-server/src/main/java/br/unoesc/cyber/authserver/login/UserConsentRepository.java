package br.unoesc.cyber.authserver.login;

import org.springframework.data.jpa.repository.JpaRepository;

public interface UserConsentRepository extends JpaRepository<UserConsent, UserConsent.Key> {
}
