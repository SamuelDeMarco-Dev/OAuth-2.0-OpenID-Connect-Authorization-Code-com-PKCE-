package br.unoesc.cyber.client.token;

import java.util.List;

/**
 * ID Token APROVADO no checklist §4.3. Só a partir deste objeto os claims podem ser usados
 * (vínculo do usuário, role). {@code evidence} descreve cada verificação feita, para o log e o relatório.
 */
public record ValidatedIdToken(
        String issuer,
        String sub,
        String name,
        String email,
        boolean emailVerified,
        String role,
        List<String> evidence) {
}
