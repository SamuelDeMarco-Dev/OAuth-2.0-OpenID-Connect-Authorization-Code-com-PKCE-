package br.unoesc.cyber.client.user;

import java.time.Clock;
import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import br.unoesc.cyber.client.token.ValidatedIdToken;

/**
 * Converte o {@code sub} de um ID Token JÁ VALIDADO no {@code id} interno (PDF §4.2 passos 9–10).
 *
 * <p>Política para usuário inexistente (documentada em docs/ARQUITETURA.md): o registro é criado
 * apenas com dados validados — {@code oidc_iss}/{@code oidc_sub} do token aprovado; {@code user_name}
 * é o e-mail SOMENTE se {@code email_verified=true} (senão, derivado do sub). O e-mail nunca é usado
 * para localizar o usuário. A role do provedor é atualizada a cada login.
 */
@Service
public class UserLinkService {

    private static final Logger log = LoggerFactory.getLogger(UserLinkService.class);
    static final String DEFAULT_ROLE = "user";

    private final UserAccountRepository users;
    private final Clock clock;

    UserLinkService(UserAccountRepository users, Clock clock) {
        this.users = users;
        this.clock = clock;
    }

    @Transactional
    public UserAccount link(ValidatedIdToken token) {
        String role = token.role() == null || token.role().isBlank() ? DEFAULT_ROLE : token.role();
        String fullName = token.name();
        return users.findByOidcIssAndOidcSub(token.issuer(), token.sub())
                .map(existing -> {
                    existing.refresh(fullName, role);
                    log.info("Login vinculado: iss={} sub={} -> id={} role={}", token.issuer(), token.sub(),
                            existing.getId(), role);
                    return existing;
                })
                .orElseGet(() -> {
                    UserAccount created = users.save(new UserAccount(userName(token), fullName, token.issuer(),
                            token.sub(), role, Instant.now(clock)));
                    log.info("Usuário criado a partir de ID Token validado: iss={} sub={} -> id={} user_name={}",
                            token.issuer(), token.sub(), created.getId(), created.getUserName());
                    return created;
                });
    }

    /** Nome de exibição único; e-mail só se verificado. Colisão (mesmo e-mail, outro sub) recebe sufixo. */
    private String userName(ValidatedIdToken token) {
        String base = token.emailVerified() && token.email() != null ? token.email() : "usuario-" + shortSub(token.sub());
        return users.existsByUserName(base) ? base + " (" + shortSub(token.sub()) + ")" : base;
    }

    private static String shortSub(String sub) {
        return sub.length() <= 8 ? sub : sub.substring(0, 8);
    }
}
