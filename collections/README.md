# Coleção de requisições

- **`postman/`** — coleção e ambiente do Postman, com scripts de PKCE/state/nonce e asserções automáticas.
  Guia passo a passo: [`docs/TESTES-POSTMAN.md`](../docs/TESTES-POSTMAN.md).
- `requests.http` — atalhos para a extensão **REST Client** do VS Code (`humao.rest-client`).
- `negative-tests.sh` — script curl dos testes negativos do PDF (item 5) — issue #24.

Todos usam `secrets/tls/localhost.crt` para validar o TLS (gerado por `scripts/gen-dev-secrets.sh`).
