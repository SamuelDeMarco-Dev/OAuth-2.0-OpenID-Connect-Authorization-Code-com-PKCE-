# Roteiro da demonstração ao vivo (≤ 10 min)

**Formato:** dois apresentadores — **A** conduz o Servidor de Autorização, **B** conduz a aplicação cliente. Quem não está com o teclado narra.

## Antes de entrar na sala (checklist)
- [ ] `git pull` e `./mvnw -B verify` passando
- [ ] `./scripts/gen-dev-secrets.sh` já rodado; certificado aceito em https://localhost:9443 e https://localhost:8443 no navegador da apresentação
- [ ] Banco limpo para a demo começar sem usuários no cliente: apague a pasta `data/`
- [ ] Os dois apps no ar (VS Code → **AS + Cliente**), com os **terminais/consoles de log visíveis**
- [ ] Navegador em janela anônima (sem cookies antigos), zoom 125%
- [ ] Terminal extra aberto na raiz do projeto, fonte grande
- [ ] Senhas de `admin` e `aluno` à mão (estão no `.env`) — **não** projetar o `.env`
- [ ] Plano B aberto em outra aba: o relatório (`docs/relatorio/RELATORIO.md`) e o último arquivo de `evidencias/`

## Cronograma

| Tempo | Quem | O que mostrar | O que dizer |
|---|---|---|---|
| 0:00–1:00 | A | Diagrama em `docs/ARQUITETURA.md` | Dois componentes independentes; Authorization Code + PKCE S256 + OIDC; a senha só trafega entre o navegador e o AS; nenhuma biblioteca pronta de OAuth. |
| 1:00–2:00 | A | Navegador: `https://localhost:9443/.well-known/openid-configuration` e `/jwks.json` | `issuer` HTTPS idêntico em todos os tokens; só `code` e `S256`; JWKS só com a parte pública e o `kid` que aparece no header do token. |
| 2:00–4:00 | B | `https://localhost:8443` → **Entrar** → login `admin` → consentimento → volta logado | Antes do redirect o cliente gerou `state`, `nonce` e `code_verifier` de 256 bits. Mostrar a URL do `/authorize` na barra (só o `code_challenge` sai do servidor). No retorno, o `state` é conferido antes de qualquer coisa. |
| 4:00–5:30 | B | Log do cliente: bloco `[ID_TOKEN]` e as linhas `#1`…`#10` | As três partes do ID Token decodificadas; cada linha é um item do checklist 4.3; o algoritmo vem da lista fixa `[RS256]`, nunca do header; `sub` do `/userinfo` igual ao do ID Token; vínculo por `iss`+`sub`. |
| 5:30–6:30 | B | **Meu perfil** (tabela `users`) → **Sair** → entrar como `aluno` → **Área administrativa** → 403 | Sessão própria `APP_SID` (HttpOnly, Secure, SameSite=Lax, 256 bits, rotacionada no login); a role é lida do servidor a cada requisição — o link aparece para todos de propósito. |
| 6:30–9:00 | A | Terminal: `./collections/negative-tests.sh` | Os 15 cenários do §5 contra os apps reais. Comentar enquanto roda: #8 aborta antes da troca, #9 revoga os tokens, #11 nem redireciona, #15 bloqueia até a senha correta. Terminar mostrando a tabela **20 OK, 0 falhas**. |
| 9:00–10:00 | A e B | Perguntas | — |

> O script leva cerca de 30–60 s (inclui os testes JUnit do ID Token). Se o tempo apertar, rode-o **antes** da sessão de perguntas enquanto B fala do item 4:00–5:30.

## Perguntas prováveis (respostas curtas)
- **Por que RS256 e não HS256?** Com HS256 o cliente teria o mesmo segredo que assina: poderia forjar tokens, e o segredo teria de ser distribuído. Com RS256 o cliente só tem a chave pública (JWKS). O ataque de “reassinar em HS256 com a chave pública” é o teste #2 e é recusado porque o algoritmo vem da lista fixa.
- **Por que PKCE se o cliente tem segredo?** Protege contra interceptação do code (quem não tem o `code_verifier` não troca); o RFC 9700 recomenda PKCE para todos os clientes.
- **Para que serve o `nonce` se já existe `state`?** `state` protege o *callback* contra CSRF; `nonce` liga o *ID Token* à requisição que o pediu e impede replay de um token antigo.
- **Por que não usar o e-mail para identificar?** E-mail muda e pode ser reatribuído; `sub` é único e nunca reatribuído no emissor (OIDC Core §5.7).
- **O que acontece se o code vazar?** Vale 60 s, uso único, exige o `code_verifier` e a autenticação do cliente; se for reutilizado, o AS revoga todos os tokens emitidos a partir dele (teste #9).
- **Onde ficam os tokens no cliente?** Só na memória do servidor durante o callback; não vão para o navegador nem para o banco. A sessão é um id aleatório próprio.
- **E se o AS girar a chave?** O `kid` novo provoca uma releitura do JWKS no cliente; o AS mantém a chave anterior publicada durante a transição.

## Plano B
| Falha | O que fazer |
|---|---|
| Certificado recusado no navegador | Aceitar o aviso de novo; em último caso mostrar o fluxo pelo Postman (`docs/TESTES-POSTMAN.md`) |
| `aluno` bloqueado (script rodado antes) | É o #15 funcionando; reiniciar o AS zera o bloqueio |
| App não sobe | Mostrar a saída salva em `evidencias/` e as seções 3–5 do relatório |
| Login demora a voltar | Conferir se os dois apps estão no ar; o code expira em 60 s — recomeçar pelo **Entrar** |
