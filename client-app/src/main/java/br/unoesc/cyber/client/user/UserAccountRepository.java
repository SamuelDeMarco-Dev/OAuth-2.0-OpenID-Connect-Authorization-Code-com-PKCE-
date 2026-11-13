package br.unoesc.cyber.client.user;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface UserAccountRepository extends JpaRepository<UserAccount, Long> {

    Optional<UserAccount> findByOidcIssAndOidcSub(String oidcIss, String oidcSub);

    boolean existsByUserName(String userName);
}
