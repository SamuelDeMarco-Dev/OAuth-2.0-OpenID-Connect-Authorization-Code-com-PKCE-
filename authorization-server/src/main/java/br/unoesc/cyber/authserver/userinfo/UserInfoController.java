package br.unoesc.cyber.authserver.userinfo;

import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import br.unoesc.cyber.authserver.error.OAuthError;
import br.unoesc.cyber.authserver.error.OAuthException;
import br.unoesc.cyber.authserver.token.AccessTokenVerifier;
import br.unoesc.cyber.authserver.token.AccessTokenVerifier.VerifiedAccessToken;
import br.unoesc.cyber.authserver.user.AppUser;
import br.unoesc.cyber.authserver.user.AppUserRepository;

/** GET/POST /userinfo protegido por Bearer access token (PDF §2.6, RFC 6750). */
@RestController
class UserInfoController {

    private static final String REALM = "authorization-server";

    private final AccessTokenVerifier verifier;
    private final AppUserRepository users;

    UserInfoController(AccessTokenVerifier verifier, AppUserRepository users) {
        this.verifier = verifier;
        this.users = users;
    }

    @RequestMapping(path = "/userinfo", method = { RequestMethod.GET, RequestMethod.POST })
    ResponseEntity<Map<String, Object>> userinfo(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.regionMatches(true, 0, "Bearer ", 0, 7) || header.substring(7).isBlank()) {
            // Sem credencial: 401 sem código de erro (RFC 6750 §3.1).
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .header(HttpHeaders.WWW_AUTHENTICATE, "Bearer realm=\"" + REALM + "\"")
                    .cacheControl(CacheControl.noStore())
                    .build();
        }
        VerifiedAccessToken token = verifier.verify(header.substring(7).trim());
        AppUser user = users.findBySub(token.sub())
                .orElseThrow(() -> new OAuthException(OAuthError.INVALID_TOKEN, "usuário não existe mais"));

        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("sub", user.getSub());
        if (token.hasScope("profile")) {
            claims.put("name", user.getFullName());
        }
        if (token.hasScope("email")) {
            claims.put("email", user.getEmail());
            claims.put("email_verified", user.isEmailVerified());
        }
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(claims);
    }
}
