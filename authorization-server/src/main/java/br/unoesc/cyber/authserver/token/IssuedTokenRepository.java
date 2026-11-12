package br.unoesc.cyber.authserver.token;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface IssuedTokenRepository extends JpaRepository<IssuedToken, String> {

    /** Revoga todos os tokens emitidos a partir de um authorization code. */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("update IssuedToken t set t.revoked = true where t.codeHash = :codeHash and t.revoked = false")
    int revokeFamily(@Param("codeHash") String codeHash);

    List<IssuedToken> findByCodeHash(String codeHash);
}
