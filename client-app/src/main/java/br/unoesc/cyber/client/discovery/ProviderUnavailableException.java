package br.unoesc.cyber.client.discovery;

/** O provedor não respondeu ou respondeu algo inaceitável. Vira mensagem amigável na UI. */
public class ProviderUnavailableException extends RuntimeException {

    public ProviderUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }

    public ProviderUnavailableException(String message) {
        super(message);
    }
}
