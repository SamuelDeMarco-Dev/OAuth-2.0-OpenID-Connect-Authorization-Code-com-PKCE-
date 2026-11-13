# Testando os endpoints no Postman

Arquivos (em `collections/postman/`):

| Arquivo | O que é |
|---|---|
| `oidc-pkce.postman_collection.json` | Coleção com todos os endpoints, scripts que geram PKCE/state/nonce e asserções automáticas |
| `localhost.postman_environment.json` | Ambiente com as URLs e o `client_id` (o `client_secret` vem **vazio** — você preenche localmente) |

## Situação atual

| Pasta | Pode rodar agora? |
|---|---|
| 1. Descoberta e JWKS | ✅ sim |
| 2. /authorize | ✅ sim |
| 3. Fluxo completo (/token, /userinfo, refresh, reuso) | ⏳ precisa de um `code` → depende do login (#6) e do consentimento (#8) |
| 4. Erros do /token | ✅ sim |
| 5. Negativo #10 e redirect_uri divergente | ⏳ precisa de um `code` novo (#6, #8) |
| 6. /userinfo sem token ou expirado | ✅ 14a sim · ⏳ 14b precisa de um access token |
| 7. Aplicação cliente | ⏳ depois das issues do cliente (#14–#23) |

Requests que dependem de algo ainda inexistente **são pulados automaticamente** (aparecem como `PULADO` no console e nos resultados, sem falhar).

---

## 1. Preparar

1. Gere os segredos e suba o Servidor de Autorização:
   ```bash
   ./scripts/gen-dev-secrets.sh
   ./mvnw -pl authorization-server spring-boot:run
   ```
2. No Postman: **Import** → arraste os dois arquivos de `collections/postman/`.
3. No canto superior direito, selecione o ambiente **“A1/3 — localhost”**.
4. Abra o ambiente (ícone de olho → *Edit*) e preencha `client_secret` com o valor de `OIDC_CLIENT_SECRET` do seu `.env`.
   - Preencha só a coluna **Current value**: ela fica apenas na sua máquina. **Não** coloque o segredo em *Initial value* (essa coluna é sincronizada com a nuvem do Postman e é exportada).

## 2. Confiar no certificado HTTPS de desenvolvimento

O certificado é autoassinado (gerado pelo script). Escolha uma opção:

- **Recomendado:** *Settings* (engrenagem) → **Certificates** → ative **CA Certificates** → selecione `secrets/tls/localhost.crt`.
- **Alternativa rápida (só em dev):** *Settings* → **General** → desligue **SSL certificate verification**.

## 3. Ver o que os scripts registram

Abra o console: **View → Show Postman Console** (ou `Ctrl/Cmd + Alt + C`). É lá que aparecem:
- a URL do `/authorize` para abrir no navegador;
- **as três partes do ID Token decodificadas** (header, payload e assinatura) — evidência pedida no relatório;
- os requests pulados e o motivo.

## 4. Obter um authorization code

O login acontece **no navegador**, nunca no Postman — a senha só trafega entre o navegador e o Servidor de Autorização (PDF §1.2). Por isso o `code` é obtido assim:

1. Rode **2. /authorize › Requisição válida → /login**. O script gera `code_verifier`, `code_challenge`, `state` e `nonce` novos e imprime no console a URL completa do `/authorize`.
2. Copie essa URL do console e abra no navegador.
3. Faça login (usuário `admin` ou `aluno`; as senhas estão no seu `.env`, em `SEED_ADMIN_PASSWORD` / `SEED_USER_PASSWORD`) e aprove o consentimento.
4. O navegador vai para `https://localhost:8443/callback?code=...&state=...`.
   - Se a aplicação cliente não estiver rodando, o navegador mostra erro de conexão — **tudo bem**: o `code` está na barra de endereço.
   - Se o cliente estiver rodando, ele recusa o callback (o `state` foi gerado pelo Postman, não por ele) **sem** gastar o code.
5. Copie o valor de `code` da barra de endereço → na coleção, aba **Variables**, cole em `code` (*Current value*) → **Save**.
6. **Em até 60 segundos** (validade do code), rode a pasta **3** inteira, na ordem: botão direito na pasta → **Run folder** → *Run*.

> Para os requests da pasta **5**, repita os passos 1–5 para cada request (cada um gasta um code novo).

### Alternativa: assistente OAuth 2.0 do próprio Postman

Útil para a demonstração. Ele abre a tela de login, captura o code e faz a troca sozinho:

Em uma request nova → aba **Authorization** → *Type* **OAuth 2.0** → *Configure New Token*:

| Campo | Valor |
|---|---|
| Grant type | **Authorization Code (With PKCE)** |
| Callback URL | `https://localhost:8443/callback` (desmarque *Authorize using browser*) |
| Auth URL | `https://localhost:9443/authorize` |
| Access Token URL | `https://localhost:9443/token` |
| Client ID / Client Secret | `{{client_id}}` / `{{client_secret}}` |
| Code Challenge Method | **SHA-256** |
| Scope | `openid profile email` |
| State | qualquer valor aleatório |
| Client Authentication | **Send as Basic Auth header** |
| Advanced → Auth Request | adicione a chave `nonce` com um valor aleatório |

Clique em **Get New Access Token**. O Postman mostra `access_token`, `id_token` e `refresh_token`.
Este caminho não alimenta as variáveis da coleção; para os testes negativos #9 e #10 use o roteiro manual acima.

## 5. Mapa dos testes negativos (PDF §5)

| # | Cenário | Onde testar | Resultado esperado |
|---|---|---|---|
| 1–7, 12 | ID Token forjado (`alg=none`, HS256, `aud`, `iss`, `exp`, `iat`, `nonce`, assinatura) | **Validação no cliente** — testes JUnit do `client-app` (issue #19). O Postman não valida ID Token como cliente. | Rejeitado |
| 8 | Callback com `state` divergente/ausente | Pasta **7** (após o cliente) | Fluxo abortado, sem sessão |
| 9 | Reutilização do code | Pasta **3**, passos 6 e 7 | `invalid_grant` + `/userinfo` 401 |
| 10 | `code_verifier` incorreto | Pasta **5**, passo 2 | `invalid_grant` |
| 11 | redirect_uri com barra final, parâmetro extra, subcaminho | Pasta **2** (#11a, #11b, #11c) | 400 na página, sem `Location` |
| 13 | `/admin` com `role=user` | Navegador, após o cliente (#22) | 403 |
| 14 | `/userinfo` sem token / expirado | Pasta **6** | 401 + `WWW-Authenticate: Bearer` |
| 15 | Força bruta no login | Navegador, após o login (#6) — 6 senhas erradas seguidas | Bloqueio |

Extras também cobertos: `plain` e `response_type=token` recusados, escopo sem `openid`, `grant_type=password` recusado, segredo do cliente errado (401 + `WWW-Authenticate: Basic`), assinatura alterada e ID Token usado como access token no `/userinfo`, rotação e reuso de refresh token.

### Token expirado (#14b) sem esperar 15 minutos
Suba o Servidor de Autorização com um tempo de vida curto só para este teste:
```bash
OIDC_SERVER_ACCESSTOKENTTL=30s ./mvnw -pl authorization-server spring-boot:run
```
Faça o fluxo (pasta 3, só o passo 1), espere 30 s e rode **6 › Negativo #14b**.

## 6. Gerar evidências para o relatório

- **No Postman:** botão direito na coleção ou pasta → **Run** → *Run* → ao final, **Export Results** (JSON) e tire um print da tela de resultados.
- **Pela linha de comando** (Newman, opcional; precisa de Node.js só como ferramenta de teste):
  ```bash
  npx newman run collections/postman/oidc-pkce.postman_collection.json \
    -e collections/postman/localhost.postman_environment.json \
    --env-var "client_secret=<OIDC_CLIENT_SECRET do .env>" \
    --ssl-extra-ca-certs secrets/tls/localhost.crt \
    --folder "1. Descoberta e JWKS (§2.1, §2.7)" --folder "2. /authorize (§2.2)"
  ```

## 7. Problemas comuns

| Sintoma | Causa provável |
|---|---|
| `Error: self signed certificate` | Passo 2 (certificado) não feito |
| `invalid_client` em tudo | `client_secret` vazio ou diferente do `.env` |
| `invalid_grant` no passo 1 da pasta 3 | O code passou de 60 s, já foi usado, ou o `/authorize` foi gerado de novo depois do login (verifier diferente) |
| `/authorize` mostra página de erro | `redirect_uri` do ambiente diferente de `OIDC_REDIRECT_URI` do `.env` |
| Requests aparecem como `PULADO` | Falta o pré-requisito indicado no console (`code`, `access_token`…) |
