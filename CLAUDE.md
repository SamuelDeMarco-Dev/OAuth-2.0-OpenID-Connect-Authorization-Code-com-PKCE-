# CLAUDE.md — A1/3 OAuth 2.0 + OIDC (Authorization Code + PKCE), Opção 1

Dois módulos Maven independentes: `authorization-server` (OP, :9443) e `client-app` (RP, :8443).
Java 21 · Spring Boot 4.1 (MVC + Thymeleaf) · Nimbus JOSE+JWT · H2 + Flyway. OAuth/OIDC implementado à mão.

## Fonte de verdade (leia SÓ o necessário)
- Requisitos: `docs/REQUISITOS.md` (resumo do PDF — **não abra o PDF**).
- Decisões e fluxo: `docs/ARQUITETURA.md`.
- Regras do módulo: `authorization-server/CLAUDE.md` ou `client-app/CLAUDE.md`.
- Tarefa atual: a issue do GitHub (`gh issue view <n>`). Não leia outras issues sem necessidade.

## Comandos
- Segredos de dev: `./scripts/gen-dev-secrets.sh`
- Build + testes: `./mvnw -q -B verify` · só um módulo: `./mvnw -q -B -pl client-app test`
- Um teste: `./mvnw -q -B -pl authorization-server test -Dtest=NomeDoTest`
- Rodar: `./mvnw -pl authorization-server spring-boot:run` (idem `client-app`)

## Regras invioláveis (PDF §1.2)
- Nunca: grant password, implicit, `alg=none`, algoritmo escolhido pelo header `alg`, HS256, e-mail/nome como id.
- Vínculo de usuário = `iss` + `sub`. redirect_uri = comparação exata de `String`.
- Nunca ler, imprimir ou commitar `.env` ou `secrets/`.
- Todo requisito novo vem com teste do caminho feliz **e** do teste negativo correspondente (§5).

## Economia de tokens
- Use `-q` no Maven e `| tail -n 40` em saídas longas; nunca despeje logs inteiros.
- Leia arquivos por trecho (offset/limit) quando souber onde está; prefira `grep -n` antes de `Read`.
- Trabalhe em um módulo por vez; não explore o outro módulo sem motivo.
- Delegue para subagentes (`.claude/agents/`) tarefas isoladas: eles rodam com modelo mais barato e devolvem só o resumo.
- Não reescreva arquivos inteiros para mudar poucas linhas — use edição pontual.

## Convenções
- Branch: `feat/<issue>-slug` · Commit: `feat(as): ... (#12)` / `fix(client): ...` · PR com `Closes #<n>`.
- Código e identificadores em inglês; comentários, mensagens de UI e docs em português.
- Pacotes por funcionalidade (`authorize`, `token`, `session`...). Cada pacote tem `package-info.java` dizendo seu escopo.
