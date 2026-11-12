package br.unoesc.cyber.authserver.authorize;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.web.util.UriComponentsBuilder;

/** Monta a URI de retorno codificando cada valor de forma estrita (state volta byte a byte idêntico). */
public final class RedirectUris {

    private RedirectUris() {
    }

    public static String withParams(String redirectUri, Map<String, String> params) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectUri);
        Map<String, String> vars = new LinkedHashMap<>();
        params.forEach((name, value) -> {
            if (value != null) {
                builder.queryParam(name, "{" + name + "}");
                vars.put(name, value);
            }
        });
        return builder.encode().buildAndExpand(vars).toUriString();
    }
}
