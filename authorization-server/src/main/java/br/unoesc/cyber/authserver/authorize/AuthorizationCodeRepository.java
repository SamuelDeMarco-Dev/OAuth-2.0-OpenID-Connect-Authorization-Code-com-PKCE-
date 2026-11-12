package br.unoesc.cyber.authserver.authorize;

import java.time.Instant;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AuthorizationCodeRepository extends JpaRepository<AuthorizationCode, String> {

    /**
     * Marca o code como usado de forma ATÔMICA. Retorna 0 se já tinha sido usado
     * (inclusive por uma requisição concorrente) — sinal de reutilização.
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("update AuthorizationCode c set c.usedAt = :now where c.codeHash = :hash and c.usedAt is null")
    int markUsed(@Param("hash") String codeHash, @Param("now") Instant now);
}
