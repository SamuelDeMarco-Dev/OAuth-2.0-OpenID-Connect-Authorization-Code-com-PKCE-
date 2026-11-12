-- Escopo concedido, necessário para a rotação do refresh token e para o /userinfo.
ALTER TABLE issued_token ADD COLUMN scope VARCHAR(200) NOT NULL DEFAULT '';
CREATE INDEX ix_issued_token_code_hash ON issued_token (code_hash);
