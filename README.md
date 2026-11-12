# OAuth 2.0 + OpenID Connect — Authorization Code com PKCE

Avaliação A1/3 — 33506 Cyber Security (Unoesc) · **Opção 1: Servidor de Autorização próprio**.

| Componente | Papel | URL |
|---|---|---|
| [`authorization-server`](authorization-server) | OpenID Provider (`/authorize`, `/token`, `/userinfo`, `/jwks.json`, descoberta, `/logout`) | https://localhost:9443 |
| [`client-app`](client-app) | Relying Party (login, callback, validação do ID Token, sessão local, `/admin`) | https://localhost:8443 |

Stack: Java 21 · Spring Boot 4.1 (MVC + Thymeleaf) · Nimbus JOSE+JWT · H2 + Flyway · Maven Wrapper.
Requisitos resumidos em [`docs/REQUISITOS.md`](docs/REQUISITOS.md); decisões e diagrama em [`docs/ARQUITETURA.md`](docs/ARQUITETURA.md).

## Pré-requisitos
- JDK 21 ou mais recente (`java -version`). Maven **não** precisa estar instalado (`./mvnw`).
- `openssl` e `keytool` (vem com o JDK).
- VS Code com as extensões recomendadas (o VS Code sugere ao abrir a pasta): *Extension Pack for Java*, *Spring Boot Extension Pack*, *REST Client*.

## Primeira execução
```bash
git clone https://github.com/SamuelDeMarco-Dev/OAuth-2.0-OpenID-Connect-Authorization-Code-com-PKCE-.git
cd OAuth-2.0-OpenID-Connect-Authorization-Code-com-PKCE-
./scripts/gen-dev-secrets.sh      # cria .env, certificado TLS e chave RS256 (nada disso é versionado)
./mvnw -B verify                  # build + testes
```

### Rodando no VS Code
1. `code .` → aceite instalar as extensões recomendadas e aguarde o Java importar o projeto Maven.
2. Aba **Run and Debug** → selecione **“AS + Cliente”** → F5 (sobe os dois apps com o `.env`).
3. Abra https://localhost:9443 e https://localhost:8443 e aceite o certificado autoassinado (uma vez por navegador).

Alternativa por terminal (ou *Terminal → Run Task*):
```bash
./mvnw -pl authorization-server spring-boot:run
./mvnw -pl client-app spring-boot:run
```

## Variáveis de ambiente
Todas em [`.env.example`](.env.example). O script copia para `.env` gerando valores aleatórios. Principais:

| Variável | Uso |
|---|---|
| `AS_ISSUER` | `issuer` publicado na descoberta e em todos os tokens |
| `TLS_KEYSTORE_*` / `TLS_TRUSTSTORE_*` | certificado HTTPS dos apps e truststore do cliente |
| `AS_SIGNING_KID`, `AS_SIGNING_KEY_PATH` | chave RSA de assinatura RS256 (e `AS_PREVIOUS_*` para rotação) |
| `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URI` | cadastro do cliente (lidos pelos dois apps) |
| `SEED_*` | usuários de demonstração (`admin` com role admin, `aluno` com role user) |

## Rotação da chave de assinatura (§2.7)
1. Exporte a pública da chave atual: `openssl pkey -in secrets/keys/signing-2026-11.pem -pubout -out secrets/keys/signing-2026-11.pub.pem`
2. Gere a nova: `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out secrets/keys/signing-2026-12.pem`
3. No `.env`: `AS_SIGNING_KID=2026-12`, `AS_SIGNING_KEY_PATH=secrets/keys/signing-2026-12.pem`, `AS_PREVIOUS_KID=2026-11`, `AS_PREVIOUS_PUBLIC_KEY_PATH=secrets/keys/signing-2026-11.pub.pem`
4. Reinicie o AS: novos tokens saem com `kid=2026-12` e o `/jwks.json` publica as duas chaves. Depois que os tokens antigos expirarem, limpe `AS_PREVIOUS_*`.

## Estrutura
```
authorization-server/   OpenID Provider (pacotes por endpoint, ver authorization-server/CLAUDE.md)
client-app/             Relying Party (ver client-app/CLAUDE.md)
collections/            requests.http (REST Client) + negative-tests.sh (curl, testes do §5)
docs/                   requisitos, arquitetura, relatório
scripts/                geração de segredos de desenvolvimento
.claude/                subagentes e permissões do Claude Code
```

## Fluxo de trabalho da dupla
1. Pegue uma issue atribuída a você no [board de issues](../../issues) (milestone *Entrega A1/3*).
2. `git switch -c feat/<nº>-descricao` a partir de `main` atualizada.
3. Commits pequenos referenciando a issue: `feat(as): valida redirect_uri exata (#7)`.
4. Abra PR com `Closes #<nº>`, preencha o checklist de segurança; o outro dev revisa. CI (`./mvnw verify` + checagem de segredos) precisa passar.
5. Nunca commitar `.env`, `secrets/`, `data/`.

### Contrato entre os dois módulos
Para trabalharmos em paralelo sem depender um do outro, o contrato é o do PDF: o cliente só conhece o AS pela descoberta (`AS_ISSUER/.well-known/openid-configuration`) e pelo JWKS. O cliente testa a validação do ID Token com **tokens forjados localmente** (chave RSA de teste), sem precisar do AS rodando.

## Uso do Claude Code (economia de tokens)
- `CLAUDE.md` na raiz e em cada módulo: contexto mínimo carregado só onde se trabalha.
- `docs/REQUISITOS.md` substitui a leitura do PDF.
- Subagentes em `.claude/agents/`: `as-dev`, `client-dev`, `test-writer` (Sonnet), `doc-writer` (Haiku), `security-reviewer` (Opus, só leitura). Ex.: *“use o subagente client-dev para a issue #20”*.
- `.claude/settings.json` libera `./mvnw`/`gh issue view` e **bloqueia leitura** de `.env`, `secrets/`, `data/` e `target/`.
