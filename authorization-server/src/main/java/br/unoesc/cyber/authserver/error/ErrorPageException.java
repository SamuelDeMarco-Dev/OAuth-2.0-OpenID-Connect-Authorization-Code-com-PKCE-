package br.unoesc.cyber.authserver.error;

/**
 * Erro exibido na PRÓPRIA página do servidor, sem redirecionar.
 * Usado quando client_id ou redirect_uri são inválidos (RFC 6749 §4.1.2.1): redirecionar
 * transformaria o /authorize em vetor de redirecionamento aberto.
 */
public class ErrorPageException extends RuntimeException {

    public ErrorPageException(String userMessage) {
        super(userMessage);
    }
}
