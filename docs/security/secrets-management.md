# Segredos

`scripts/init_env.py` cria `.env` com permissão 0600 e segredos aleatórios independentes para PostgreSQL owner, runtime e Redis. Git e Docker context ignoram `.env`; `.env.example` possui somente placeholders. Bootstrap usa getpass e não publica usuário/senha fixos.

Migrate/seed/bootstrap recebem credencial de owner; API/worker usam `aegis_app` NOSUPERUSER/NOCREATEDB/NOCREATEROLE. Runtime não pode UPDATE/DELETE de evidências, resultados, versões Sigma ou auditoria. O container padrão PostgreSQL usa o usuário de inicialização privilegiado para migrações; em implantação real separar também administrador do banco e dono de schema.

Cookies de sessão HttpOnly; token persistido por SHA-256, CSRF distinto vinculado por hash. Frontend não usa localStorage para sessão. Senhas Argon2id. Expiração no backend; logout remove a sessão. Erros de validação não ecoam valores recebidos.

Wazuh recebe credenciais somente no ambiente de implantação; não aparecem em endpoints de status, auditoria, URL ou relatórios. CA própria pode ser montada somente leitura em override; nunca usar verify=False. Rotação de senhas do banco existente exige procedimento PostgreSQL, não apenas editar `.env`. `init_env.py` preserva valores existentes.

E2E usa senha aleatória via stdin de subprocessos, sem arquivo de credenciais; schema e usuário são descartados. Não compartilhar `.local` ou dumps sem inspeção.
