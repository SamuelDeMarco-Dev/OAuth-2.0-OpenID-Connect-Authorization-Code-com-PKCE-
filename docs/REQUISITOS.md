# Requisitos condensados — A1/3 Cyber Security (Opção 1)

> Resumo fiel do PDF da avaliação. **Use este arquivo em vez do PDF** (economia de tokens).
> Numeração `§x.y` = seção do PDF. Entrega e apresentação: **26/11/2026**.

## Proibições (§1.2) — violar qualquer uma derruba a nota
- Sem grant *password* (ROPC): a aplicação nunca recebe/vê/armazena a senha.
- Sem fluxo *implicit* (`response_type=token`).
- Rejeitar `alg=none`. **Não** escolher algoritmo pelo `alg` do token: lista fixa (RFC 8725 §3.1).
- Identificador do usuário = `iss` + `sub`. Nunca e-mail, `preferred_username` ou `name`.
- TLS obrigatório (exceto localhost em dev — usamos TLS mesmo em localhost).
- Nunca versionar `client_secret`, chave privada ou senhas.
- Sem JavaScript/Node no back-end; páginas renderizadas no servidor; token nunca exposto ao navegador (§7).

## Servidor de Autorização (§2)
| Endpoint | Método | Função |
|---|---|---|
| `/.well-known/openid-configuration` | GET | Descoberta |
| `/authorize` | GET (e POST) | Autentica usuário e emite code |
| `/token` | POST | Autentica cliente, valida code + verifier, emite tokens |
| `/userinfo` | GET/POST | Claims do usuário (Bearer) |
| `/jwks.json` | GET | Chave(s) pública(s) JWK |
| `/logout` | POST | Encerra sessão no AS |

**§2.1 Descoberta** — mínimo: `issuer` (URL HTTPS absoluta, idêntica em todos os tokens), `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `jwks_uri`, `scopes_supported` ⊇ {openid, profile, email}, `response_types_supported` ⊇ {code}, `grant_types_supported` ⊇ {authorization_code}, `code_challenge_methods_supported` ⊇ {S256}, `id_token_signing_alg_values_supported` ⊇ {RS256}, `token_endpoint_auth_methods_supported`.

**§2.2 /authorize** — todos obrigatórios: `response_type=code`; `client_id` cadastrado; `redirect_uri` **comparação exata de string** (sem curinga/prefixo/normalização); `scope` contém `openid`; `state`; `nonce`; `code_challenge`; `code_challenge_method=S256` (`plain` recusado).
- client_id ou redirect_uri inválidos → **erro na própria página, sem redirecionar** (§4.1.2.1 RFC 6749).
- Só após validar o cliente mostra o login. Senha só trafega navegador ↔ AS.
- Code: uso único, **≤ 60 s**, vinculado a client_id, redirect_uri, code_challenge, sub, nonce.
- 302 para redirect_uri com `code` e `state` **byte a byte idêntico**.

**§2.3 Autenticação** — senha com bcrypt custo ≥ 12 (ou Argon2id); rate limiting + mensagem genérica (não revela se usuário existe); cookie de sessão HttpOnly, Secure, SameSite=Lax, id aleatório ≥ 128 bits; consentimento dos escopos (tela ou registro explícito).

**§2.4 /token** — `application/x-www-form-urlencoded`; `grant_type=authorization_code`, `code`, `redirect_uri` (idêntica), `code_verifier`, credenciais por `client_secret_basic` ou `client_secret_post`.
Validar: code existe, não expirou, não usado, pertence ao cliente autenticado; redirect_uri exata; `BASE64URL(SHA256(verifier)) == challenge`. **Reuso de code → revogar todos os tokens emitidos a partir dele.**
Resposta 200 JSON com `Cache-Control: no-store` e `Pragma: no-cache`: `access_token`, `token_type=Bearer`, `expires_in` (900), `scope`, `refresh_token` (rotativo, vinculado ao cliente), `id_token`.

**§2.5 ID Token** — JWS RS256, header `{alg:RS256, typ:JWT, kid}`; payload obrigatório: `iss, sub, aud, exp, iat, nonce, azp, name, email, email_verified, role`. `exp = iat + 900`. **HS256 proibido.**

**§2.6 /userinfo** — Bearer; devolve `sub` (= sub do ID Token), `name`, `email`. Sem token / expirado / assinatura inválida → **401 + `WWW-Authenticate: Bearer`**.

**§2.7 /jwks.json** — JWK com `kid, kty, use, alg`; rotação mantendo a chave anterior publicada.

**§2.8 Erros** — `invalid_request` 400 · `invalid_client` 401 (+WWW-Authenticate) · `invalid_grant` 400 · `unauthorized_client` 400 · `unsupported_grant_type` 400 · `invalid_scope` 400.

## Aplicação cliente (§4)
**§4.1 Tabela `users`** (nomes obrigatórios): `id` PK int, `user_name` texto único, `full_name`, `oidc_sub` texto único, `role`, `created_at`. Hash de senha local pode existir mas nunca é usado no fluxo.

**§4.2 Passo a passo**
1. "Entrar": gera `state`, `nonce` (≥128 bits), `code_verifier`; `code_challenge = BASE64URL(SHA256(verifier))`; guarda os três na sessão.
2. Redireciona para `authorization_endpoint` com todos os parâmetros + `scope=openid profile email` + `S256`.
3. Usuário digita senha **no AS**.
4. AS volta com `code` + `state`.
5. Compara `state`; divergente/ausente → aborta (CSRF).
6. POST `/token` (code, redirect_uri, verifier, credenciais).
7. **Decompõe o id_token em header/payload/assinatura e loga as três partes** (vai pro relatório).
8. Valida pelo checklist §4.3 com JWKS e lista fixa de algoritmos.
9. Só então extrai `sub`.
10. Busca `oidc_sub` → id interno. Inexistente: recusar **ou** criar só com dados validados — **documentar a escolha**.
11. Cria sessão local (sessionID + id do usuário) gravada no servidor.
12. Libera áreas por `role`, revalidado a cada requisição.

**§4.3 Checklist do ID Token** (cada linha vale nota; relatório precisa de evidência)
1. Assinatura com chave do emissor via `kid`; `kid` desconhecido = erro.
2. Algoritmo na lista fixa; `none` sempre rejeitado.
3. `iss` == issuer da descoberta.
4. `aud` contém o client_id.
5. `aud` com vários valores → valida `azp`.
6. `exp` no futuro (tolerância de poucos minutos).
7. `iat` não está no futuro.
8. `nonce` == enviado.
9. `sub` localizado na tabela → id interno.
10. Se usar `/userinfo`, `sub` igual ao do ID Token.

**§4.4 Sessão local** — sessionID aleatório ≥128 bits (não é JWT nem access token); cookie HttpOnly, Secure, SameSite=Lax, Path=/; **rotacionar no login**; inatividade 30 min, absoluta 8 h; logout invalida no servidor e descarta tokens.

**§4.5 Autorização** — rota `/admin` só para `role=admin`; demais → **403**. Decisão só após validação criptográfica; controle no servidor.

**§4.6 Erros no callback** — `error`/`error_description` (ex.: `access_denied`): mensagem amigável, registra evento, não cria sessão. Rede no `/token`: timeout e **nunca** repetir a troca do code.

## Testes negativos obrigatórios (§5) — metade da nota de segurança
| # | Cenário | Esperado |
|---|---|---|
| 1 | ID Token com `alg=none` | Rejeitado |
| 2 | Reassinado em HS256 com a chave pública como segredo | Rejeitado |
| 3 | `aud` de outro client_id | Rejeitado |
| 4 | `iss` diferente | Rejeitado |
| 5 | `exp` vencido | Rejeitado |
| 6 | `iat` no futuro | Rejeitado |
| 7 | `nonce` diferente | Rejeitado |
| 8 | Callback com `state` divergente/ausente | Aborta antes da troca do code |
| 9 | Reuso do authorization code | `invalid_grant` + revogação dos tokens |
| 10 | `code_verifier` incorreto | `invalid_grant` |
| 11 | redirect_uri com `/` final, parâmetro extra ou subcaminho | Rejeitado |
| 12 | Um byte alterado na assinatura | Rejeitado |
| 13 | `/admin` com `role=user` | 403 |
| 14 | `/userinfo` sem token ou expirado | 401 + WWW-Authenticate |
| 15 | Força bruta no login | Bloqueio por rate limiting |

## Entregáveis (§6)
- Código dos dois componentes em repositório com histórico de commits **do grupo**.
- README (execução + variáveis) e `.env.example` sem segredos.
- Coleção de requisições (Insomnia/Postman/curl).
- Relatório ≤ 6 páginas: diagrama do fluxo; 3 partes do ID Token decodificadas; checklist §4.3 preenchido; tabela §5 com evidências; justificativa de algoritmo e tempos de vida.
- Demo ao vivo ≤ 10 min executando os testes negativos.

## Rubrica (§8)
Descoberta+JWKS 0,5 · /authorize PKCE/state/nonce 1,5 · Autenticação no AS 1,0 · /token 1,5 · ID Token 1,5 · Validação no cliente 1,5 · Sessão + vínculo sub 1,0 · Autorização por role 0,5 · Relatório/README/demo 1,0 = **10,0**
