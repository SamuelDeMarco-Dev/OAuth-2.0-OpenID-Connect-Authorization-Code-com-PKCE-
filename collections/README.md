# Coleção de requisições

- **`postman/`** — coleção e ambiente do Postman, com scripts de PKCE/state/nonce e asserções automáticas.
  Guia passo a passo: [`docs/TESTES-POSTMAN.md`](../docs/TESTES-POSTMAN.md).
- `requests.http` — atalhos para a extensão **REST Client** do VS Code (`humao.rest-client`).
- **`negative-tests.sh`** — executa os 15 testes negativos do PDF (item 5) contra os dois apps rodando, simulando o navegador com curl, e salva a tabela de evidências em `evidencias/` (fora do git). Os cenários de ID Token forjado (#1–#7, #12) rodam via JUnit no cliente.

Todos usam `secrets/tls/localhost.crt` para validar o TLS (gerado por `scripts/gen-dev-secrets.sh`).
