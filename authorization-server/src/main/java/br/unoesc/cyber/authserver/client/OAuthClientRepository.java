package br.unoesc.cyber.authserver.client;

import org.springframework.data.jpa.repository.JpaRepository;

public interface OAuthClientRepository extends JpaRepository<OAuthClient, String> {
}
