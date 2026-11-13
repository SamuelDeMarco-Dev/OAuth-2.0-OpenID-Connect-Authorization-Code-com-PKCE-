# Arquitetura e decisões

## Componentes
| Módulo | Papel OIDC | URL | Pacote base |
|---|---|---|---|
| `authorization-server` | OpenID Provider + Resource Server (`/userinfo`) | `https://localhost:9443` | `br.unoesc.cyber.authserver` |
| `client-app` | Relying Party | `https://localhost:8443` | `br.unoesc.cyber.client` |

Os dois módulos são **independentes** (nenhum depende do outro em Maven). Comunicação só por HTTP(S).

## Fluxo implementado
```mermaid
sequenceDiagram
    autonumber
    actor U as Usuário (navegador)
    participant C as Cliente :8443
    participant AS as Servidor de Autorização :9443
    U->>C: GET /login ("Entrar")
    C->>C: gera state, nonce, code_verifier; challenge = B64URL(SHA256(verifier))
    C-->>U: 302 → AS /authorize?response_type=code&client_id&redirect_uri&scope&state&nonce&code_challenge&S256
    U->>AS: GET /authorize
    AS->>AS: valida client_id + redirect_uri (exata). Inválido → página de erro, sem redirect
    AS-->>U: formulário de login (senha só aqui)
    U->>AS: POST login (rate limiting, bcrypt 12)
    AS-->>U: tela de consentimento
    U->>AS: POST consentimento
    AS-->>U: 302 → /callback?code&state (code: 60 s, uso único)
    U->>C: GET /callback?code&state
    C->>C: confere state (senão aborta)
    C->>AS: POST /token (basic auth + code + redirect_uri + code_verifier)
    AS-->>C: 200 {access_token, id_token, refresh_token} no-store
    C->>AS: GET /jwks.json (cache por kid)
    C->>C: decompõe e valida ID Token (checklist 4.3)
    C->>AS: GET /userinfo (Bearer) → confere sub
    C->>C: iss+sub → users.id; cria sessão local (APP_SID), rotaciona id
    C-->>U: 302 → área logada; /admin exige role=admin (senão 403)
```

## Decisões técnicas
| Decisão | Escolha | Motivo |
|---|---|---|
| Linguagem / framework | Java 21 + Spring Boot 4.1 (Spring MVC + Thymeleaf) | Permitido no PDF; SSR atende "token nunca exposto ao navegador". |
| OAuth/OIDC | **Implementação própria** (sem Spring Authorization Server nem `spring-security-oauth2-client`) | A avaliação mede o domínio do protocolo; bibliotecas prontas esconderiam exatamente o que é corrigido. |
| JOSE/JWT | Nimbus JOSE+JWT | Biblioteca madura para JWS/JWK; o código decide o algoritmo (lista fixa), não a biblioteca. |
| Hash de senha | BCrypt custo 12 (`spring-security-crypto`) | Exigência §2.3. Só o módulo crypto, sem a cadeia de filtros do Spring Security. |
| Banco | H2 em arquivo (`data/`) + Flyway | Zero instalação para os dois devs; esquema versionado. |
| TLS | Certificado autoassinado gerado por script, compartilhado pelos dois apps | TLS também em localhost; cliente confia via truststore próprio. |
| Assinatura | RS256, RSA 2048, `kid` = `AAAA-MM` | Exigência §2.5; rotação mantém a anterior no JWKS (§2.7). |
| Tempos de vida | code 60 s · access 15 min · id 15 min · refresh 8 h (rotativo) · sessão 30 min ociosa / 8 h absoluta | Sugestões do PDF; justificar no relatório. |
| Cookies | AS: `AS_SESSION` · Cliente: `APP_SID` (sessão local) e `APP_PRELOGIN` (state/nonce/verifier) | **Cookies não são isolados por porta**: nomes distintos evitam que um app sobrescreva o outro em `localhost`. |
| Consentimento | Registrado em `user_consent`; reaproveitado se o usuário já consentiu os mesmos escopos para o mesmo cliente | Registro explícito exigido pelo §2.3 |
| Usuário inexistente no cliente (passo 10) | **Cria o registro só com dados validados**: `oidc_iss` + `oidc_sub` do ID Token aprovado; `user_name` = e-mail apenas se `email_verified=true` (senão `usuario-<sub>`); e-mail repetido com outro `sub` vira outra conta. A `role` do provedor é atualizada a cada login. | Permitido pelo §4.2.10; os `sub` do AS são UUIDs gerados no seed, então pré-cadastro manual seria impraticável. O e-mail nunca localiza usuário (§1.2). |

## Segredos
Tudo em `.env` + `secrets/` (gitignored), gerados por `scripts/gen-dev-secrets.sh`. O seed do cliente OAuth e dos usuários de demonstração é feito **no boot** a partir do `.env`, nunca em migrations.
