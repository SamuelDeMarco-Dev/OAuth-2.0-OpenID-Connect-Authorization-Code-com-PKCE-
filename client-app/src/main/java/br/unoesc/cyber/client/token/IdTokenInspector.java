package br.unoesc.cyber.client.token;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.nimbusds.jose.util.JSONObjectUtils;

/**
 * Passo 7 do PDF §4.2: decompõe o ID Token em cabeçalho, payload e assinatura e registra as três
 * partes decodificadas no log (marcador {@code [ID_TOKEN]}) — evidência para o relatório.
 * Feito ANTES da validação: o conteúdo é apenas exibido, nunca usado para decidir nada.
 */
@Component
public class IdTokenInspector {

    private static final Logger log = LoggerFactory.getLogger(IdTokenInspector.class);
    private static final Base64.Decoder B64URL = Base64.getUrlDecoder();

    public DecodedIdToken decompose(String idToken) {
        String[] parts = idToken == null ? new String[0] : idToken.split("\\.", -1);
        if (parts.length != 3) {
            log.warn("[ID_TOKEN] formato inválido: esperado header.payload.assinatura ({} partes)", parts.length);
            return null;
        }
        try {
            DecodedIdToken decoded = new DecodedIdToken(pretty(parts[0]), pretty(parts[1]), parts[2]);
            log.info("""
                    [ID_TOKEN] decomposto (ainda NÃO validado)
                    --- cabeçalho ---
                    {}
                    --- payload ---
                    {}
                    --- assinatura (Base64URL, {} bytes) ---
                    {}""", decoded.header(), decoded.payload(), B64URL.decode(parts[2]).length, decoded.signature());
            return decoded;
        } catch (IllegalArgumentException | java.text.ParseException e) {
            log.warn("[ID_TOKEN] não foi possível decodificar: {}", e.getMessage());
            return null;
        }
    }

    /** JSON de uma parte Base64URL, um claim por linha. */
    static String pretty(String part) throws java.text.ParseException {
        Map<String, Object> json = JSONObjectUtils.parse(new String(B64URL.decode(part), StandardCharsets.UTF_8));
        return json.entrySet().stream()
                .map(e -> "  " + JSONObjectUtils.toJSONString(Map.of(e.getKey(), e.getValue()))
                        .replaceAll("^\\{|\\}$", ""))
                .collect(Collectors.joining(",\n", "{\n", "\n}"));
    }

    public record DecodedIdToken(String header, String payload, String signature) {
    }
}
