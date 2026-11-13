package br.unoesc.cyber.authserver.token;

import java.time.Clock;
import java.time.Instant;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import br.unoesc.cyber.authserver.authorize.AuthorizationCode;
import br.unoesc.cyber.authserver.authorize.AuthorizationCodeRepository;
import br.unoesc.cyber.authserver.crypto.Hashes;
import br.unoesc.cyber.authserver.error.OAuthError;
import br.unoesc.cyber.authserver.error.OAuthException;

/**
 * grant_type=authorization_code (PDF §2.4). O code é consumido ATOMICAMENTE antes das demais
 * verificações: qualquer segunda apresentação — mesmo concorrente — é tratada como reutilização.
 */
@Service
class CodeExchangeService {

    private static final Logger log = LoggerFactory.getLogger(CodeExchangeService.class);
    /** code_verifier: 43–128 caracteres "unreserved" (RFC 7636 §4.1). */
    private static final Pattern VERIFIER = Pattern.compile("^[A-Za-z0-9\\-._~]{43,128}$");

    private final AuthorizationCodeRepository codes;
    private final IssuedTokenRepository issuedTokens;
    private final TokenService tokenService;
    private final Clock clock;

    CodeExchangeService(AuthorizationCodeRepository codes, IssuedTokenRepository issuedTokens,
            TokenService tokenService, Clock clock) {
        this.codes = codes;
        this.issuedTokens = issuedTokens;
        this.tokenService = tokenService;
        this.clock = clock;
    }

    /** noRollbackFor: o code marcado como usado permanece usado mesmo quando a troca falha. */
    @Transactional(noRollbackFor = OAuthException.class)
    TokenResponse exchange(String clientId, String code, String redirectUri, String codeVerifier) {
        if (code == null || redirectUri == null || codeVerifier == null) {
            throw new OAuthException(OAuthError.INVALID_REQUEST, "code, redirect_uri e code_verifier são obrigatórios");
        }
        if (!VERIFIER.matcher(codeVerifier).matches()) {
            throw new OAuthException(OAuthError.INVALID_REQUEST, "code_verifier malformado");
        }
        Instant now = Instant.now(clock);
        String codeHash = Hashes.sha256Hex(code);
        AuthorizationCode stored = codes.findById(codeHash)
                .orElseThrow(() -> new OAuthException(OAuthError.INVALID_GRANT, "code inválido"));
        if (!stored.getClientId().equals(clientId)) {
            throw new OAuthException(OAuthError.INVALID_GRANT, "code não pertence a este cliente");
        }
        if (codes.markUsed(codeHash, now) == 0) {
            onReuse(stored);
            throw new OAuthException(OAuthError.INVALID_GRANT, "code já utilizado");
        }
        if (stored.isExpired(now)) {
            throw new OAuthException(OAuthError.INVALID_GRANT, "code expirado");
        }
        if (!stored.getRedirectUri().equals(redirectUri)) {
            throw new OAuthException(OAuthError.INVALID_GRANT, "redirect_uri difere da usada em /authorize");
        }
        if (!Hashes.constantTimeEquals(Hashes.s256(codeVerifier), stored.getCodeChallenge())) {
            throw new OAuthException(OAuthError.INVALID_GRANT, "code_verifier incorreto");
        }
        return tokenService.issueForCode(stored);
    }

    /**
     * Reutilização do code (RFC 6749 §4.1.2, PDF §2.4): revoga IMEDIATAMENTE todos os tokens
     * emitidos a partir dele — access, ID e refresh (inclusive os já rotacionados).
     */
    private void onReuse(AuthorizationCode stored) {
        int revoked = issuedTokens.revokeFamily(stored.getCodeHash());
        log.warn("Reutilização de authorization code detectada (client_id={}, sub={}): {} tokens revogados",
                stored.getClientId(), stored.getUserSub(), revoked);
    }
}
