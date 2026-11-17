#!/usr/bin/env bash
# Testes negativos obrigatórios do PDF (item 5), executados contra os dois apps RODANDO.
# Simula o navegador com curl (cookies por "navegador") e imprime a tabela de evidências.
#
#   ./mvnw -pl authorization-server spring-boot:run   # terminal 1
#   ./mvnw -pl client-app spring-boot:run             # terminal 2
#   ./collections/negative-tests.sh                   # terminal 3
#
# A saída também é gravada em evidencias/testes-negativos-<data>.txt (pasta fora do git).
# Atenção: o cenário #15 bloqueia o usuário "aluno" por 15 min (reinicie o AS para zerar).
set -uo pipefail
cd "$(dirname "$0")/.."
[[ -f .env ]] || { echo "Rode antes: ./scripts/gen-dev-secrets.sh"; exit 1; }
set -a; source .env; set +a

AS="${AS_ISSUER:-https://localhost:9443}"
APP="https://localhost:${APP_PORT:-8443}"
CA="secrets/tls/localhost.crt"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
mkdir -p evidencias
OUT="evidencias/testes-negativos-$(date +%Y%m%d-%H%M%S).txt"
exec > >(tee "$OUT") 2>&1

# ---------- utilitários ----------
c()      { local jar=$1; shift; curl -s --cacert "$CA" -b "$TMP/$jar" -c "$TMP/$jar" "$@"; }
loc()    { local jar=$1; shift; c "$jar" -o /dev/null -w '%{redirect_url}' "$@"; }
code_of(){ local jar=$1; shift; c "$jar" -o /dev/null -w '%{http_code}' "$@"; }
token()  { grep -o 'name="form_token" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"$//'; }
qp()     { python3 -I -c 'import sys,urllib.parse as u;print(u.parse_qs(u.urlsplit(sys.argv[1]).query).get(sys.argv[2],[""])[0])' "$1" "$2"; }
json()   { python3 -I -c 'import sys,json;print(json.load(sys.stdin).get(sys.argv[1],""))' "$1"; }
pkce()   { python3 -I -c 'import secrets,hashlib,base64;v=secrets.token_urlsafe(32);print(v, base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode())'; }

PASS=0; FAIL=0; ROWS=()
row() { # numero cenario esperado obtido ok(0/1)
  local st="OK"; if [[ $5 -eq 0 ]]; then PASS=$((PASS+1)); else st="FALHOU"; FAIL=$((FAIL+1)); fi
  ROWS+=("$(printf '%-4s | %-58s | %-36s | %-36s | %s' "$1" "$2" "$3" "$4" "$st")")
  printf '  [%s] #%s %s → %s\n' "$st" "$1" "$2" "$4"
}

# Login + consentimento no AS a partir de uma autorização já pendente. Ecoa a URL de callback.
as_login_consent() {
  local jar=$1 user=$2 pass=$3 t l
  t=$(c "$jar" "$AS/login" | token)
  l=$(loc "$jar" -X POST "$AS/login" --data-urlencode "username=$user" --data-urlencode "password=$pass" --data-urlencode "form_token=$t")
  [[ "$l" == "$AS/consent" ]] || { echo "LOGIN_FALHOU:$l"; return 1; }
  l=$(loc "$jar" "$AS/consent")                  # consentimento já registrado → redirect direto
  [[ -n "$l" ]] && { echo "$l"; return 0; }
  t=$(c "$jar" "$AS/consent" | token)
  loc "$jar" -X POST "$AS/consent" -d decision=approve --data-urlencode "form_token=$t"
}

# Login completo pela aplicação cliente (como no navegador). Ecoa o destino final.
app_login() {
  local jar=$1 user=$2 pass=$3 l cb
  l=$(loc "$jar" "$APP/login"); loc "$jar" "$l" >/dev/null
  cb=$(as_login_consent "$jar" "$user" "$pass") || { echo "$cb"; return 1; }
  loc "$jar" "$cb"
}

# Fluxo direto no AS (curl no papel do cliente) para obter um authorization code. Ecoa "code verifier".
direct_code() {
  local jar=$1 v ch state cb
  read -r v ch < <(pkce); state=$(python3 -I -c 'import secrets;print(secrets.token_urlsafe(16))')
  loc "$jar" -G "$AS/authorize" --data-urlencode response_type=code --data-urlencode "client_id=$OIDC_CLIENT_ID" \
    --data-urlencode "redirect_uri=$OIDC_REDIRECT_URI" --data-urlencode "scope=openid profile email" \
    --data-urlencode "state=$state" --data-urlencode nonce=n-script --data-urlencode "code_challenge=$ch" \
    --data-urlencode code_challenge_method=S256 >/dev/null
  cb=$(as_login_consent "$jar" "$SEED_ADMIN_USERNAME" "$SEED_ADMIN_PASSWORD") || return 1
  echo "$(qp "$cb" code) $v"
}

token_req() { # code verifier
  curl -s --cacert "$CA" -u "$OIDC_CLIENT_ID:$OIDC_CLIENT_SECRET" "$AS/token" -w '\n%{http_code}' \
    -d grant_type=authorization_code --data-urlencode "code=$1" --data-urlencode "redirect_uri=$OIDC_REDIRECT_URI" \
    --data-urlencode "code_verifier=$2"
}

# ---------- pré-condições ----------
echo "== Testes negativos — A1/3 OAuth 2.0 + OIDC — $(date '+%d/%m/%Y %H:%M:%S')"
for u in "$AS/.well-known/openid-configuration" "$APP/"; do
  [[ "$(code_of x "$u")" == "200" ]] || { echo "Serviço fora do ar: $u (suba os dois apps)"; exit 1; }
done

echo "== Fluxo feliz"
dest=$(app_login admin "$SEED_ADMIN_USERNAME" "$SEED_ADMIN_PASSWORD")
home=$(c admin "$APP/" | tr -s ' \n' ' ')
[[ "$dest" == "$APP/" && "$home" == *"perfil <code>admin</code>"* ]]; row "-" "Login admin pelo cliente (PKCE, state, nonce, ID Token)" "sessão local criada" "destino $dest" $?

echo "== Testes que dependem do ID Token (JUnit no cliente: tokens forjados)"
junit=$(./mvnw -q -B -pl client-app test -Dtest=NegativeIdTokenTests -Dsurefire.printSummary=true 2>&1; echo "exit=$?")
ok=1; [[ "$junit" == *"exit=0"* ]] && ok=0
for n in "1:alg \"none\"" "2:HS256 com a chave pública como segredo" "3:aud de outro client_id" "4:iss diferente" \
         "5:exp vencido" "6:iat no futuro" "7:nonce diferente" "12:um byte alterado na assinatura"; do
  row "${n%%:*}" "ID Token com ${n#*:}" "Rejeitado" "$([[ $ok -eq 0 ]] && echo 'rejeitado (NegativeIdTokenTests)' || echo 'ver saída do Maven')" $ok
done

echo "== #8 state divergente/ausente no callback"
loc s8 "$APP/login" >/dev/null   # login em andamento (state guardado na sessão pré-login)
st=$(code_of s8 -D "$TMP/h8" "$APP/callback?code=qualquer&state=state-forjado")
! grep -qi 'set-cookie: APP_SID=[^;]' "$TMP/h8" && [[ "$st" == "400" ]]
row 8 "Callback com state divergente" "Abortado antes da troca do code" "HTTP $st, sem APP_SID" $?
loc s8b "$APP/login" >/dev/null
st=$(code_of s8b -D "$TMP/h8b" "$APP/callback?code=qualquer")
! grep -qi 'set-cookie: APP_SID=[^;]' "$TMP/h8b" && [[ "$st" == "400" ]]
row 8 "Callback sem state" "Abortado antes da troca do code" "HTTP $st, sem APP_SID" $?

echo "== #9 reutilização do authorization code"
read -r code9 v9 < <(direct_code d9)
r1=$(token_req "$code9" "$v9"); at=$(echo "$r1" | head -1 | json access_token)
r2=$(token_req "$code9" "$v9"); e2=$(echo "$r2" | head -1 | json error); s2=$(echo "$r2" | tail -1)
ui=$(code_of x -H "Authorization: Bearer $at" "$AS/userinfo")
[[ "$(echo "$r1" | tail -1)" == "200" && "$s2" == "400" && "$e2" == "invalid_grant" && "$ui" == "401" ]]
row 9 "Reutilização do mesmo code (+ /userinfo com o token da 1ª troca)" "invalid_grant e revogação" "2ª troca $s2 $e2; /userinfo $ui" $?

echo "== #10 code_verifier incorreto"
read -r code10 v10 < <(direct_code d10)
wrong=$(pkce | cut -d' ' -f1)
r=$(token_req "$code10" "$wrong"); e=$(echo "$r" | head -1 | json error); s=$(echo "$r" | tail -1)
[[ "$s" == "400" && "$e" == "invalid_grant" ]]; row 10 "code_verifier incorreto no /token" "invalid_grant" "HTTP $s $e" $?

echo "== #11 redirect_uri sem correspondência exata"
for v in "barra final:$OIDC_REDIRECT_URI/" "parâmetro adicional:$OIDC_REDIRECT_URI?x=1" "subcaminho:$OIDC_REDIRECT_URI/sub"; do
  hdr=$(curl -s --cacert "$CA" -o /dev/null -D - -G "$AS/authorize" --data-urlencode "client_id=$OIDC_CLIENT_ID" \
        --data-urlencode "redirect_uri=${v#*:}" --data-urlencode response_type=code --data-urlencode scope=openid \
        --data-urlencode state=s --data-urlencode nonce=n --data-urlencode code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM \
        --data-urlencode code_challenge_method=S256)
  s=$(echo "$hdr" | head -1 | awk '{print $2}')
  ! echo "$hdr" | grep -qi '^location:' && [[ "$s" == "400" ]]
  row 11 "redirect_uri com ${v%%:*}" "Rejeitado (comparação exata)" "HTTP $s, sem redirect" $?
done

echo "== #13 /admin com role = user"
dest=$(app_login aluno "$SEED_USER_USERNAME" "$SEED_USER_PASSWORD")
s_user=$(code_of aluno "$APP/admin"); s_admin=$(code_of admin "$APP/admin")
[[ "$s_user" == "403" && "$s_admin" == "200" ]]
row 13 "Acesso a /admin com role = user (controle: admin)" "HTTP 403" "user $s_user · admin $s_admin" $?

echo "== #14 /userinfo sem token ou com token inválido"
hdr=$(curl -s --cacert "$CA" -o /dev/null -D - "$AS/userinfo")
s=$(echo "$hdr" | head -1 | awk '{print $2}'); wa=$(echo "$hdr" | grep -i '^www-authenticate' | tr -d '\r')
[[ "$s" == "401" && "$wa" == *Bearer* ]]; row 14 "/userinfo sem token" "HTTP 401 + WWW-Authenticate" "HTTP $s, ${wa:0:40}" $?
hdr=$(curl -s --cacert "$CA" -o /dev/null -D - -H "Authorization: Bearer ${at%?????}AAAAA" "$AS/userinfo")
s=$(echo "$hdr" | head -1 | awk '{print $2}'); wa=$(echo "$hdr" | grep -i '^www-authenticate' | tr -d '\r')
[[ "$s" == "401" && "$wa" == *invalid_token* ]]; row 14 "/userinfo com token adulterado (expirado: JUnit/Postman)" "HTTP 401 + WWW-Authenticate" "HTTP $s, invalid_token" $?

echo "== #15 força bruta no formulário de login (por último: bloqueia '$SEED_USER_USERNAME' por 15 min)"
l=$(loc bf "$APP/login"); loc bf "$l" >/dev/null   # autorização pendente no AS (pré-requisito do formulário)
t=$(c bf "$AS/login" | token); codes=""
for i in 1 2 3 4 5; do
  codes+="$(code_of bf -X POST "$AS/login" --data-urlencode "username=$SEED_USER_USERNAME" --data-urlencode "password=errada$i" --data-urlencode "form_token=$t") "
done
s6=$(code_of bf -X POST "$AS/login" --data-urlencode "username=$SEED_USER_USERNAME" --data-urlencode "password=$SEED_USER_PASSWORD" --data-urlencode "form_token=$t")
[[ "$s6" == "429" ]]; row 15 "5 senhas erradas e depois a CORRETA" "Bloqueio por rate limiting" "erradas: ${codes% }; correta: $s6" $?

echo
printf '%-4s | %-58s | %-36s | %-36s | %s\n' "#" "Cenário" "Esperado" "Obtido" "Resultado"
printf -- '-%.0s' {1..160}; echo
printf '%s\n' "${ROWS[@]}"
echo; echo "Total: $PASS OK, $FAIL falha(s). Evidência salva em $OUT"
[[ $FAIL -eq 0 ]]
