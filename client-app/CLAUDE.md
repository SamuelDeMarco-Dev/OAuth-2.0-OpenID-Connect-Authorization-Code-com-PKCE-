# client-app (Relying Party) — https://localhost:8443

Requisitos: `docs/REQUISITOS.md` seções §4.x e §5. Config: `oidc.client.*` → `config/OidcClientProperties`.

| Pacote | Escopo |
|---|---|
| `discovery` | lê descoberta do AS; `RestClient` com truststore e timeout |
| `login` | `/login` (state/nonce/PKCE) e `/callback` |
| `token` | decomposição + `IdTokenValidator` (checklist §4.3) |
| `user` | tabela `users`, vínculo `iss`+`sub` |
| `session` | sessão local `APP_SID` (tabela `local_session`) |
| `authz` | interceptor de role, `/admin` → 403 |

Regras do módulo:
- Algoritmos aceitos = `acceptedAlgorithms` (fixo `[RS256]`). Verificar ANTES de qualquer outra coisa; `none`/HS* → rejeita.
- Nenhuma decisão (role, sub) com claims não verificados.
- Tokens nunca vão para o navegador (nem em template, nem em cookie, nem em URL).
- Troca do code: uma tentativa só, com timeout; falha = mensagem amigável e sem sessão.
- Testes negativos do token: gerar tokens forjados com chave RSA de teste (não depende do AS rodando).
