# Coleção de requisições

- `requests.http` — abra no VS Code com a extensão **REST Client** (`humao.rest-client`) e clique em *Send Request*.
- `negative-tests.sh` — script curl que executa os testes negativos do PDF (item 5) e imprime a evidência.

Ambos usam `secrets/tls/localhost.crt` para validar o TLS (gerado por `scripts/gen-dev-secrets.sh`).
