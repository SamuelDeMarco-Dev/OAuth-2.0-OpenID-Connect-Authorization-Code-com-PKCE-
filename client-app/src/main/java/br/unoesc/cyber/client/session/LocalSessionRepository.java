package br.unoesc.cyber.client.session;

import org.springframework.data.jpa.repository.JpaRepository;

public interface LocalSessionRepository extends JpaRepository<LocalSession, String> {
}
