package br.unoesc.cyber.authserver.jwk;

import java.time.Duration;
import java.util.Map;

import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class JwksController {

    private final SigningKeys keys;

    JwksController(SigningKeys keys) {
        this.keys = keys;
    }

    @GetMapping("/jwks.json")
    ResponseEntity<Map<String, Object>> jwks() {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(Duration.ofMinutes(5)).cachePublic())
                .body(keys.publicJwkSet().toJSONObject(true));
    }
}
