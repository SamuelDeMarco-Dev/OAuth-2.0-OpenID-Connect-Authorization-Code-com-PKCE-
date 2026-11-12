# authorization-server (OpenID Provider) — https://localhost:9443

Requisitos: `docs/REQUISITOS.md` seções §2.x. Config: `oidc.server.*` → `config/AuthServerProperties`.

| Pacote | Escopo |
|---|---|
| `discovery` | `/.well-known/openid-configuration` |
| `jwk` | carga do PEM, assinador RS256, `/jwks.json`, rotação |
| `client` | `oauth_client`, autenticação basic/post (hash BCrypt do secret) |
| `user` | `app_user`, seed a partir do `.env` |
| `authorize` | `/authorize`, emissão do code |
| `login` | login, sessão `AS_SESSION`, rate limiting, consentimento |
| `token` | `/token`, emissão/revogação, refresh rotativo |
| `userinfo` | `/userinfo` Bearer |
| `error` | `OAuthError` + handler padronizado (§2.8) |

Regras do módulo:
- `issuer` vem SÓ de `AuthServerProperties.issuer()`; nunca montar a partir do request.
- Guardar só o **hash SHA-256** do authorization code e do refresh token.
- Respostas de `/token` sempre com `Cache-Control: no-store` e `Pragma: no-cache`.
- Erro de client_id/redirect_uri no `/authorize` → template `error`, **nunca** redirect.
- Esquema em `db/migration`; mudanças = nova migration `V<n>__*.sql` (não editar V1 após merge).
