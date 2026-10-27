# Segredos

`scripts/init_env.py` cria `.env` com permissão 0600 e segredos aleatórios independentes para PostgreSQL owner, runtime e Redis. Git e Docker context ignoram `.env`; `.env.example` possui somente placeholders. Bootstrap usa getpass e não publica usuário/senha fixos.

Migrate/seed/bootstrap recebem credencial de owner; API/worker usam `aegis_app` NOSUPERUSER/NOCREATEDB/NOCREATEROLE. Runtime não pode UPDATE/DELETE de evidências, resultados, versões Sigma ou auditoria. O container padrão PostgreSQL usa o usuário de inicialização privilegiado para migrações; em implantação real separar também administrador do banco e dono de schema.

Cookies de sessão HttpOnly; token persistido por SHA-256, CSRF distinto vinculado por hash. Frontend não usa localStorage para sessão. Senhas Argon2id. Expiração no backend; logout remove a sessão. Erros de validação não ecoam valores recebidos.

Wazuh recebe credenciais somente no ambiente de implantação; não aparecem em endpoints de status, auditoria, URL ou relatórios. CA própria pode ser montada somente leitura em override; nunca usar verify=False. Rotação de senhas do banco existente exige procedimento PostgreSQL, não apenas editar `.env`. `init_env.py` preserva configurações válidas e recusa segredos vazios/exemplos, links, modo diferente de0600, arquivo compartilhado ou escritor concorrente. Não corrige permissões nem substitui credenciais automaticamente.

E2E usa senha aleatória via stdin de subprocessos, sem arquivo de credenciais; schema e usuário são descartados. Não compartilhar `.local` ou dumps sem inspeção.

Identidades age de backup ficam em `.local/backup-keys`,0600/0700, separadas do
ciphertext. Só o destinatário público e ID/caminho são exibidos; a chave não passa
por argumentos, API ou auditoria. `.agekey`/`.age` são ignorados pelo Git/build e
recusados pelo scanner staged. Gerar identidade nova não recripta cópias antigas,
que precisam da original. Custódia independente e destino externo permanecem
escolhas operacionais; chave e cópia locais não protegem da perda do host.
[Operação](../operations/encrypted-backups.md).

PKI do runner: `.key` é ignorado pelo Git/contexto Docker e recusado no scanner,
mesmo sem assinatura PEM. Preparação offline só lê os cinco arquivos públicos da
origem; quatro chaves novas ficam em candidato privado0700. CAs0600; folhas0444
para leitura de secrets individuais pelo UID10001, protegidas pelo diretório pai.
Não montar CAs privadas nem a pasta inteira. OpenSSL usa caminho/comandos fixos,
sem overrides de usuário; política padrão do sistema preservada. Manifesto/hash
não é assinatura, custódia externa ou autorização de ativação. Certificados têm
validade curta e exigem nova verificação no uso. [Procedimento](../operations/runner-pki.md).
