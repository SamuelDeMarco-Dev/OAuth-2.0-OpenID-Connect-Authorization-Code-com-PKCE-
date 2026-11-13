package br.unoesc.cyber.client.token;

/** A troca do code falhou (recusa do provedor, rede ou timeout). Não há nova tentativa. */
public class TokenExchangeException extends RuntimeException {

    public TokenExchangeException(String message, Throwable cause) {
        super(message, cause);
    }

    public TokenExchangeException(String message) {
        super(message);
    }
}
