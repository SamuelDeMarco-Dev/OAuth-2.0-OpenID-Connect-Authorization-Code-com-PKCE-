-- Servidor de Autorização: esquema inicial.
-- Segredos (client_secret, senhas) NUNCA entram aqui: o seed é feito no boot a partir do .env.

CREATE TABLE app_user (
    id             BIGINT AUTO_INCREMENT PRIMARY KEY,
    sub            VARCHAR(64)  NOT NULL UNIQUE,      -- identificador imutável, nunca reatribuído
    username       VARCHAR(100) NOT NULL UNIQUE,
    password_hash  VARCHAR(100) NOT NULL,             -- BCrypt custo >= 12
    full_name      VARCHAR(200) NOT NULL,
    email          VARCHAR(200),
    email_verified BOOLEAN      NOT NULL DEFAULT FALSE,
    role           VARCHAR(30)  NOT NULL,
    created_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE oauth_client (
    client_id          VARCHAR(100) PRIMARY KEY,
    client_secret_hash VARCHAR(100) NOT NULL,
    redirect_uri       VARCHAR(500) NOT NULL,         -- comparação EXATA de string
    allowed_scopes     VARCHAR(200) NOT NULL,
    created_at         TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE authorization_code (
    code_hash      VARCHAR(64)  PRIMARY KEY,           -- SHA-256 do code; o valor bruto não é armazenado
    client_id      VARCHAR(100) NOT NULL REFERENCES oauth_client (client_id),
    redirect_uri   VARCHAR(500) NOT NULL,
    code_challenge VARCHAR(128) NOT NULL,
    user_sub       VARCHAR(64)  NOT NULL,
    nonce          VARCHAR(255) NOT NULL,
    scope          VARCHAR(200) NOT NULL,
    expires_at     TIMESTAMP    NOT NULL,
    used_at        TIMESTAMP
);

CREATE TABLE issued_token (
    jti        VARCHAR(64)  PRIMARY KEY,
    token_type VARCHAR(20)  NOT NULL,                  -- access | refresh | id
    code_hash  VARCHAR(64)  REFERENCES authorization_code (code_hash),
    client_id  VARCHAR(100) NOT NULL,
    user_sub   VARCHAR(64)  NOT NULL,
    expires_at TIMESTAMP    NOT NULL,
    revoked    BOOLEAN      NOT NULL DEFAULT FALSE
);

CREATE TABLE user_consent (
    user_sub   VARCHAR(64)  NOT NULL,
    client_id  VARCHAR(100) NOT NULL,
    scopes     VARCHAR(200) NOT NULL,
    granted_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_sub, client_id)
);
