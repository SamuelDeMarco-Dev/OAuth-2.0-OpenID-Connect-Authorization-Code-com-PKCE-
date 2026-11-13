package br.unoesc.cyber.client.discovery;

/** Metadados do provedor obtidos na descoberta. Trocar de provedor (Opção 2) muda só estes valores. */
public record ProviderMetadata(
        String issuer,
        String authorizationEndpoint,
        String tokenEndpoint,
        String userinfoEndpoint,
        String jwksUri,
        String endSessionEndpoint) {
}
