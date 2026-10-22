# ADR 0010 — Backup consistente e ensaio isolado do Demo

Data: 2026-10-22. Escopo: ferramenta operacional local, sem endpoint de restauração.

PostgreSQL é a fonte durável. Criar dump custom do schema public junto a um
inventário de contagens e SHA-256 de todas as linhas, estrutura e revisão Alembic.
Exportar snapshot numa transação REPEATABLE READ READ ONLY e mantê-la aberta até
pg_dump --snapshot terminar; conferir identidade do cluster e banco entre a
conexão local administrativa e o container db do projeto exato aegis.

Restaurar apenas em container efêmero próprio, usando o mesmo image ID local do
PostgreSQL de origem, network=none, sem portas, volumes persistentes ou aplicação.
pg_restore --single-transaction --exit-on-error --no-owner --no-privileges.
Comparar o inventário com normalização restrita pg17-literal-array-casts/1
para conversão de arrays de literais varchar→text (sem equivalência SQL genérica),
recusando sequences/views não cobertas. Conferir hashes de eventos, versões Sigma e scopes.
Workers, scheduler, Redis, agentes e SIEM nunca são conectados ao clone. Histórico
com jobs pendentes pode ser preservado no arquivo, mas não deve ser reativado.

Arquivos em .local/backups, diretórios0700/arquivos0600, nomes gerados e criação
exclusiva. Manifesto identifica formato/hash do dump; não é assinatura nem proteção
contra alteração maliciosa de ambos. Dumps contêm senhas hasheadas e sessões:
armazenamento criptografado/off-host e configurações/secrets separados continuam
responsabilidade operacional. Não importar dumps de origem não confiável: restore
executa SQL. CLI não aceita destino arbitrário ou comando de shell.

Retenção inicial: preservar tudo automaticamente. Um plano somente leitura pode
identificar backups antigos, mantendo pelo menos os sete mais recentes e todos
com menos de30 dias; nenhuma exclusão automática de evidências, backups ou volumes.
O ensaio verifica fidelidade de dados/estrutura, não failover, RPO/RTO contratado,
recuperação de roles/secrets, efeitos externos ou capacidade de iniciar a aplicação.

Fontes oficiais consultadas:
- https://www.postgresql.org/docs/17/app-pgdump.html
- https://www.postgresql.org/docs/17/app-pgrestore.html
- https://www.postgresql.org/docs/17/functions-admin.html#FUNCTIONS-SNAPSHOT-SYNCHRONIZATION
- https://www.postgresql.org/docs/17/backup-dump.html

Revisão endureceu a ferramenta: configuração Docker vazia/ambiente saneado evita
proxies com segredos herdados; intenção persistida antes de create e reconciliação
por nome+label após resposta ambígua; fsync de arquivos e diretórios. Inventário
inclui typmod/format_type/collation e flags de índices. RLS/policies, tipos
customizados e procedures são recusados nesta versão, não ignorados.

Inventário expandido é aegis-pg-inventory/2, separado do envelope
aegis-demo-backup/1 e normalização pg17-literal-array-casts/1. Legados sem essa
versão são recusados antes de Docker e preservados pelo plano de retenção.
