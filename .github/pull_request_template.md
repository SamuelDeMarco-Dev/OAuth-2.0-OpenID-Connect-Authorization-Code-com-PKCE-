Closes #

## O que mudou
-

## Checklist de segurança (PDF 1.2)
- [ ] Nenhum segredo, chave privada ou senha versionado
- [ ] Sem grant password / implicit; sem `alg=none`; algoritmo não vem do header `alg`
- [ ] Vínculo do usuário por `iss` + `sub` (nunca e-mail/nome)
- [ ] Testes cobrindo o caminho feliz **e** o teste negativo relacionado (PDF item 5)
- [ ] `./mvnw verify` passando
