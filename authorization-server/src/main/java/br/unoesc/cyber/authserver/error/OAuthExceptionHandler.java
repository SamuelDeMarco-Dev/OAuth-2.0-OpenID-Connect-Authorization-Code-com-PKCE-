package br.unoesc.cyber.authserver.error;

import java.util.LinkedHashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.ModelAndView;

/** Formata os erros conforme o PDF §2.8. Nunca expõe stacktrace ou detalhe interno. */
@ControllerAdvice
public class OAuthExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(OAuthExceptionHandler.class);
    static final String REALM = "authorization-server";

    @ExceptionHandler(OAuthException.class)
    public ResponseEntity<Map<String, String>> oauth(OAuthException ex) {
        log.info("Erro OAuth {}: {}", ex.error().code(), ex.description());
        return body(ex.error(), ex.description());
    }

    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<Map<String, String>> mediaType(HttpMediaTypeNotSupportedException ex) {
        return body(OAuthError.INVALID_REQUEST, "Content-Type deve ser application/x-www-form-urlencoded");
    }

    @ExceptionHandler(ErrorPageException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ModelAndView page(ErrorPageException ex) {
        log.info("Requisição recusada na página: {}", ex.getMessage());
        ModelAndView mv = new ModelAndView("error");
        mv.addObject("message", ex.getMessage());
        return mv;
    }

    static ResponseEntity<Map<String, String>> body(OAuthError error, String description) {
        Map<String, String> json = new LinkedHashMap<>();
        json.put("error", error.code());
        if (description != null) {
            json.put("error_description", description);
        }
        ResponseEntity.BodyBuilder builder = ResponseEntity.status(error.status())
                .cacheControl(CacheControl.noStore())
                .header(HttpHeaders.PRAGMA, "no-cache");
        if (error == OAuthError.INVALID_CLIENT) {
            builder.header(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"" + REALM + "\"");
        } else if (error == OAuthError.INVALID_TOKEN) {
            builder.header(HttpHeaders.WWW_AUTHENTICATE,
                    "Bearer realm=\"" + REALM + "\", error=\"invalid_token\"");
        }
        return builder.body(json);
    }
}
