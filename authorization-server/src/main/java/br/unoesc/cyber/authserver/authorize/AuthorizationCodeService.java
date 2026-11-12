package br.unoesc.cyber.authserver.authorize;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import br.unoesc.cyber.authserver.config.AuthServerProperties;
import br.unoesc.cyber.authserver.crypto.Hashes;
import br.unoesc.cyber.authserver.error.OAuthError;

/**
 * Emissão do authorization code após login + consentimento (PDF §2.2).
 * Chamado pela tela de consentimento (issue #8); devolve a URL do redirect 302.
 */
@Service
public class AuthorizationCodeService {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationCodeService.class);
    private static final int CODE_BYTES = 32;

    private final AuthorizationCodeRepository codes;
    private final AuthServerProperties props;
    private final SecureRandom random;
    private final Clock clock;

    AuthorizationCodeService(AuthorizationCodeRepository codes, AuthServerProperties props, SecureRandom random,
            Clock clock) {
        this.codes = codes;
        this.props = props;
        this.random = random;
        this.clock = clock;
    }

    /** Consentimento aprovado: gera o code (256 bits, uso único, ≤ 60 s) e monta {@code redirect_uri?code&state}. */
    @Transactional
    public String approve(AuthorizationRequest request, String userSub) {
        String code = Hashes.randomToken(random, CODE_BYTES);
        Instant expiresAt = Instant.now(clock).plus(props.authorizationCodeTtl());
        codes.save(new AuthorizationCode(Hashes.sha256Hex(code), request, userSub, expiresAt));
        log.info("Authorization code emitido para client_id={} sub={} (expira {})", request.clientId(), userSub, expiresAt);

        Map<String, String> params = new LinkedHashMap<>();
        params.put("code", code);
        params.put("state", request.state());
        return RedirectUris.withParams(request.redirectUri(), params);
    }

    /** Consentimento negado: {@code redirect_uri?error=access_denied&state}. */
    public String deny(AuthorizationRequest request) {
        log.info("Consentimento negado para client_id={}", request.clientId());
        Map<String, String> params = new LinkedHashMap<>();
        params.put("error", OAuthError.ACCESS_DENIED.code());
        params.put("error_description", "o usuário negou o consentimento");
        params.put("state", request.state());
        return RedirectUris.withParams(request.redirectUri(), params);
    }
}
