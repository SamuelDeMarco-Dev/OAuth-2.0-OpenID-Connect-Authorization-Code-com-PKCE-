-- Aplicação cliente: tabela de usuários (nomes de campos exigidos no PDF 4.1) e sessão local.

CREATE TABLE users (
    id         BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_name  VARCHAR(200) NOT NULL UNIQUE,
    full_name  VARCHAR(200),
    oidc_iss   VARCHAR(300) NOT NULL,                 -- vínculo é iss + sub (OIDC Core 5.7)
    oidc_sub   VARCHAR(255) NOT NULL UNIQUE,
    role       VARCHAR(30)  NOT NULL,
    created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uk_users_iss_sub UNIQUE (oidc_iss, oidc_sub)
);

CREATE TABLE local_session (
    session_id     VARCHAR(64) PRIMARY KEY,            -- aleatório >= 128 bits (não é JWT nem access token)
    user_id        BIGINT      NOT NULL REFERENCES users (id),
    created_at     TIMESTAMP   NOT NULL,
    last_access_at TIMESTAMP   NOT NULL,
    absolute_exp   TIMESTAMP   NOT NULL
);
