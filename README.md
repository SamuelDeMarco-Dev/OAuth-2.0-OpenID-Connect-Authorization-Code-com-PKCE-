# OAuth 2.0 + OpenID Connect — Authorization Code com PKCE

Avaliação A1/3 — 33506 Cyber Security (Unoesc) · **Opção 1: Servidor de Autorização próprio**.

Dois componentes independentes que implementam, sem bibliotecas prontas de OAuth, o fluxo Authorization Code (RFC 6749) com PKCE S256 (RFC 7636) e a camada de identidade do OpenID Connect Core 1.0:

| Componente | Papel | URL |
|---|---|---|
| [`authorization-server`](authorization-server) | **OpenID Provider**: descoberta, `/authorize`, login, consentimento, `/token`, `/userinfo`, `/jwks.json`, `/logout` | https://localhost:9443 |
| [`client-app`](client-app) | **Relying Party**: botão Entrar, `/callback`, validação do ID Token, vínculo `iss`+`sub`, sessão local, `/perfil`, `/admin` | https://localhost:8443 |

Stack: Java 21 · Spring Boot 4.1 (MVC + Thymeleaf, renderizado no servidor) · Nimbus JOSE+JWT · BCrypt · H2 + Flyway · Maven Wrapper.

Documentação: [requisitos](docs/REQUISITOS.md) · [arquitetura, diagrama e decisões](docs/ARQUITETURA.md) · [relatório](docs/relatorio/RELATORIO.md) ([PDF](docs/relatorio/RELATORIO.pdf)) · [testes no Postman](docs/TESTES-POSTMAN.md) · [roteiro da demonstração](docs/DEMO.md)

---

## Executar

### Pré-requisitos
- JDK 21 ou mais recente (`java -version`). Maven **não** precisa estar instalado: use `./mvnw` (`mvnw.cmd` no Windows).
- `openssl` e `keytool` (o `keytool` vem com o JDK). No Windows, rode os scripts `.sh` no **Git Bash**.
- Opcional: VS Code com as extensões recomendadas (o VS Code oferece instalar ao abrir a pasta).

### 1. Gerar os segredos de desenvolvimento
```bash
./scripts/gen-dev-secrets.sh
```
Cria, **fora do git**: `.env` (senhas e `client_secret` aleatórios), `secrets/tls/` (certificado HTTPS autoassinado para `localhost` e truststore do cliente) e `secrets/keys/` (chave privada RSA 2048 da assinatura RS256). Cada máquina gera os seus.

### 2. Compilar e rodar os testes
```bash
./mvnw -B verify
```

### 3. Subir os dois apps
- **VS Code:** aba *Run and Debug* → **“AS + Cliente”** → F5.
- **Terminal** (um por app):
  ```bash
  ./mvnw -pl authorization-server spring-boot:run
  ./mvnw -pl client-app spring-boot:run
  ```

### 4. Usar no navegador
1. Abra https://localhost:9443 e https://localhost:8443 e aceite o aviso do certificado autoassinado (uma vez por navegador).
2. Em https://localhost:8443 clique em **Entrar**.
3. No Servidor de Autorização, entre com um dos usuários de demonstração e **Permita** o consentimento:

   | Usuário | Senha | Role |
   |---|---|---|
   | `admin` | valor de `SEED_ADMIN_PASSWORD` no seu `.env` | `admin` |
   | `aluno` | valor de `SEED_USER_PASSWORD` no seu `.env` | `user` |

4. De volta à aplicação: **Meu perfil** mostra o registro da tabela `users`; **Área administrativa** abre para `admin` e responde **403** para `aluno`.
5. O log do cliente mostra o ID Token decomposto (`[ID_TOKEN]`) e cada verificação do checklist 4.3 (`#1` … `#10`).

---

## Testes

| O quê | Como |
|---|---|
| Testes automatizados (AS + cliente) | `./mvnw -B verify` |
| **15 testes negativos do PDF §5**, ponta a ponta contra os apps rodando | `./collections/negative-tests.sh` → tabela salva em `evidencias/` |
| Só os ataques ao ID Token (§5 #1–#7, #12) | `./mvnw -pl client-app test -Dtest=NegativeIdTokenTests` |
| Endpoints um a um | Postman: importe `collections/postman/` e siga [docs/TESTES-POSTMAN.md](docs/TESTES-POSTMAN.md) · VS Code: `collections/requests.http` |

> O cenário #15 do script bloqueia o usuário `aluno` por 15 minutos (é o rate limiting funcionando). Reinicie o Servidor de Autorização para zerar.

---

## Endpoints

**Servidor de Autorização** (`https://localhost:9443`)

| Endpoint | Método | Função |
|---|---|---|
| `/.well-known/openid-configuration` | GET | Metadados de descoberta |
| `/jwks.json` | GET | Chave(s) pública(s) RS256 (com `kid`; mantém a anterior durante a rotação) |
| `/authorize` | GET, POST | Valida cliente, `redirect_uri` exata, PKCE S256, `state`, `nonce` → login |
| `/login` | GET, POST | Formulário de login (BCrypt 12, mensagem genérica, rate limiting) |
| `/consent` | GET, POST | Consentimento dos escopos → emite o code (60 s, uso único) |
| `/token` | POST | `authorization_code` e `refresh_token` (rotativo); `client_secret_basic`/`client_secret_post` |
| `/userinfo` | GET, POST | Claims do usuário com Bearer access token |
| `/logout` | POST | Encerra a sessão no Servidor de Autorização |

**Aplicação cliente** (`https://localhost:8443`)

| Endpoint | Função |
|---|---|
| `/` | Início (mostra o usuário da sessão) |
| `/login` | Gera `state`, `nonce`, `code_verifier` e redireciona ao `/authorize` |
| `/callback` | Confere `state`, troca o code, valida o ID Token, confere `/userinfo`, vincula `iss`+`sub`, cria a sessão |
| `/perfil` | Qualquer usuário autenticado |
| `/admin` | Somente `role = admin` (senão **403**) |
| `/logout` (POST) | Invalida a sessão local no servidor |

---

## Variáveis de ambiente
Todas em [`.env.example`](.env.example) (sem segredos reais); o script de segredos gera o `.env`.

| Variável | Uso |
|---|---|
| `AS_PORT`, `APP_PORT` | Portas HTTPS (9443 e 8443) |
| `AS_ISSUER` | `issuer` publicado na descoberta e em todos os tokens; o cliente exige o mesmo valor |
| `TLS_KEYSTORE_PATH`, `TLS_KEYSTORE_PASSWORD` | Certificado HTTPS dos dois apps |
| `TLS_TRUSTSTORE_PATH`, `TLS_TRUSTSTORE_PASSWORD` | Truststore com que o cliente valida o TLS do AS |
| `AS_SIGNING_KID`, `AS_SIGNING_KEY_PATH` | Chave RSA de assinatura e seu `kid` |
| `AS_PREVIOUS_KID`, `AS_PREVIOUS_PUBLIC_KEY_PATH` | Chave pública anterior, publicada durante a rotação |
| `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URI` | Cadastro do cliente (lido pelos dois apps) |
| `SEED_ADMIN_*`, `SEED_USER_*` | Usuários de demonstração criados no boot do AS |

Ajustes opcionais via variável de ambiente (formato do Spring), por exemplo `OIDC_SERVER_ACCESSTOKENTTL=30s` para testar token expirado sem esperar 15 minutos.

### Rotação da chave de assinatura (§2.7)
1. Exporte a pública da chave atual: `openssl pkey -in secrets/keys/signing-2026-11.pem -pubout -out secrets/keys/signing-2026-11.pub.pem`
2. Gere a nova: `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out secrets/keys/signing-2026-12.pem`
3. No `.env`: `AS_SIGNING_KID=2026-12`, `AS_SIGNING_KEY_PATH=secrets/keys/signing-2026-12.pem`, `AS_PREVIOUS_KID=2026-11`, `AS_PREVIOUS_PUBLIC_KEY_PATH=secrets/keys/signing-2026-11.pub.pem`
4. Reinicie o AS: os tokens novos saem com `kid=2026-12` e o `/jwks.json` publica as duas chaves. Depois que os tokens antigos expirarem, limpe `AS_PREVIOUS_*`.

---

## Segurança — resumo das proibições do PDF (§1.2)
| Proibição | Como o projeto atende |
|---|---|
| Grant *password* / implicit | Só `authorization_code` (+ `refresh_token`); `response_type=token` → `unsupported_response_type`; a aplicação não tem formulário de senha |
| `alg=none` / algoritmo vindo do token | Lista fixa `[RS256]` na configuração; o header só é comparado; verificador sempre RSA |
| Identificar usuário por e-mail/nome | Vínculo por `oidc_iss` + `oidc_sub` |
| Tráfego sem TLS | HTTPS também em localhost; cliente valida o certificado do AS via truststore |
| Segredos no repositório | `.env`, `secrets/`, `data/` e `evidencias/` no `.gitignore`; o CI falha se algum for versionado |

Detalhes e justificativas: [docs/ARQUITETURA.md](docs/ARQUITETURA.md) e [docs/relatorio/RELATORIO.md](docs/relatorio/RELATORIO.md).

---

## Estrutura
```
authorization-server/   OpenID Provider (pacotes por funcionalidade; ver authorization-server/CLAUDE.md)
client-app/             Relying Party (ver client-app/CLAUDE.md)
collections/            Postman (postman/), REST Client (requests.http) e negative-tests.sh
docs/                   requisitos, arquitetura, relatório, guia do Postman, roteiro da demo
scripts/                geração dos segredos de desenvolvimento
.claude/                subagentes e permissões do Claude Code
```

## Fluxo de trabalho da dupla
1. Pegue uma issue do [board](../../issues) (milestone *Entrega A1/3*).
2. `git switch -c feat/<nº>-descricao` a partir da `main` atualizada.
3. Commits pequenos referenciando a issue: `feat(as): valida redirect_uri exata (#7)`.
4. PR com `Closes #<nº>` e o checklist de segurança preenchido. O CI (`./mvnw verify` + checagem de segredos) precisa passar.

### Uso do Claude Code (economia de tokens)
- `CLAUDE.md` na raiz e em cada módulo: contexto mínimo, carregado só onde se trabalha; `docs/REQUISITOS.md` substitui a leitura do PDF.
- Subagentes em `.claude/agents/`: `as-dev`, `client-dev`, `test-writer` (Sonnet), `doc-writer` (Haiku), `security-reviewer` (Opus, só leitura).
- `.claude/settings.json` libera `./mvnw` e `gh issue view` e **bloqueia a leitura** de `.env`, `secrets/`, `data/` e `target/`.
