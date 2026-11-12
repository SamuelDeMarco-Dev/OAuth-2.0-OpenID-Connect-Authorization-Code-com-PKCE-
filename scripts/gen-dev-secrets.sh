#!/usr/bin/env bash
# Gera os segredos de desenvolvimento (NUNCA versionados):
#   .env                              -> valores aleatórios a partir de .env.example
#   secrets/tls/localhost.p12         -> certificado TLS autoassinado (localhost/127.0.0.1)
#   secrets/tls/truststore.p12        -> truststore para o cliente confiar no AS
#   secrets/keys/signing-<kid>.pem    -> chave privada RSA 2048 (PKCS#8) para RS256
# Idempotente: não sobrescreve o que já existe. Use --force para regenerar tudo.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ "${1:-}" == "--force" ]]; then rm -rf secrets .env; fi
mkdir -p secrets/tls secrets/keys

rand() { openssl rand -hex 24; }

if [[ ! -f .env ]]; then
  sed -e "s/^TLS_KEYSTORE_PASSWORD=.*/TLS_KEYSTORE_PASSWORD=$(rand)/" \
      -e "s/^TLS_TRUSTSTORE_PASSWORD=.*/TLS_TRUSTSTORE_PASSWORD=$(rand)/" \
      -e "s/^OIDC_CLIENT_SECRET=.*/OIDC_CLIENT_SECRET=$(rand)/" \
      -e "s/^SEED_ADMIN_PASSWORD=.*/SEED_ADMIN_PASSWORD=$(rand)/" \
      -e "s/^SEED_USER_PASSWORD=.*/SEED_USER_PASSWORD=$(rand)/" \
      .env.example > .env
  chmod 600 .env
  echo "[ok] .env criado (senhas de demonstração estão nele)"
fi

# shellcheck disable=SC1091
set -a; source .env; set +a

if [[ ! -f "$TLS_KEYSTORE_PATH" ]]; then
  keytool -genkeypair -alias localhost -keyalg RSA -keysize 2048 -validity 365 \
    -dname "CN=localhost, OU=A1-3 CyberSecurity, O=Unoesc" \
    -ext "SAN=dns:localhost,ip:127.0.0.1" \
    -storetype PKCS12 -keystore "$TLS_KEYSTORE_PATH" -storepass "$TLS_KEYSTORE_PASSWORD" >/dev/null 2>&1
  keytool -exportcert -alias localhost -keystore "$TLS_KEYSTORE_PATH" -storepass "$TLS_KEYSTORE_PASSWORD" \
    -rfc -file secrets/tls/localhost.crt >/dev/null 2>&1
  rm -f "$TLS_TRUSTSTORE_PATH"
  keytool -importcert -noprompt -alias localhost -file secrets/tls/localhost.crt \
    -storetype PKCS12 -keystore "$TLS_TRUSTSTORE_PATH" -storepass "$TLS_TRUSTSTORE_PASSWORD" >/dev/null 2>&1
  echo "[ok] TLS: $TLS_KEYSTORE_PATH e $TLS_TRUSTSTORE_PATH"
fi

if [[ ! -f "$AS_SIGNING_KEY_PATH" ]]; then
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$AS_SIGNING_KEY_PATH" 2>/dev/null
  chmod 600 "$AS_SIGNING_KEY_PATH"
  echo "[ok] Chave RS256: $AS_SIGNING_KEY_PATH (kid=$AS_SIGNING_KID)"
fi

echo "Pronto. Para o navegador aceitar o certificado autoassinado, abra https://localhost:9443 e https://localhost:8443 uma vez e aceite o aviso."
