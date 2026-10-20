# ADR 0001 — Fundação e escopo

Status: aceito. Data de pesquisa: 2026-10-20 (versões efetivas também registradas nos lockfiles).

- Python 3.13 disponível localmente; container na mesma linha. Pydantic v2, SQLAlchemy estável 2.x, Alembic e psycopg 3. APIs síncronas simplificam transações e integração com worker.
- PostgreSQL 17: linha estável suportada, já disponível no host. Redis 8: serviço separado, opção de licença AGPLv3, não embutido no código MIT. Nenhuma dependência de serviço pago.
- Fila PostgreSQL em vez de RQ: processamento inicial de baixo volume, claim transacional com SKIP LOCKED, sem serialização pickle nem inconsistência entre commit e enqueue. Redis para limitador distribuído e heartbeat. Scheduler futuro usará o mesmo serviço de aprovação.
- React + TypeScript + Vite; TanStack Query; Tailwind; Recharts; ícones Lucide e componentes HTML acessíveis próprios. SPA servida pelo backend no container para mesma origem e implantação simples; Vite proxy no desenvolvimento.
- Sessões opacas armazenadas por hash, Argon2id, cookie HttpOnly/SameSite=Strict e CSRF associado à sessão. Sem credenciais fixas; bootstrap local interativo.
- Banco relacional para entidades e associações; JSON apenas snapshots imutáveis e payloads originais de evidências. UTC no banco. Tenant único no MVP, todos os usuários autenticados consultam o mesmo laboratório; RBAC restringe escrita.
- Atualização ATT&CK por script de desenvolvedor com versão explícita, cache local e hash; não fazer download no startup. pySigma valida sintaxe; não converte nem instala regras Wazuh.

Fontes oficiais consultadas:

- https://fastapi.tiangolo.com/release-notes/ — Pydantic v2 e compatibilidade Python.
- https://docs.pydantic.dev/latest/ — modelos e settings.
- https://docs.sqlalchemy.org/en/20/ e https://alembic.sqlalchemy.org/en/latest/ — ORM, transações e migrações.
- https://www.postgresql.org/support/versioning/ — suporte por linha.
- https://redis.io/legal/licenses/ — Redis 8 e opções de licença.
- https://python-rq.org/docs/ — alternativa avaliada, Redis/Valkey e workers.
- https://react.dev/versions e https://vite.dev/guide/ — compatibilidade verificada também no build local.
- https://tailwindcss.com/docs/installation/using-vite e https://tanstack.com/query/latest/docs/framework/react/overview.
- https://github.com/recharts/recharts — biblioteca de gráficos.
- https://github.com/mitre-attack/attack-stix-data — dataset e licença oficiais.
- https://github.com/redcanaryco/atomic-red-team — metadados, dependências e cleanup; nenhum teste implicitamente seguro.
- https://documentation.wazuh.com/current/user-manual/indexer-api/reference.html — consulta de eventos distinta da API de gestão.
- https://github.com/SigmaHQ/pySigma — parsing e licença LGPL da biblioteca; regras possuem licenças próprias.

Escolhemos versões estáveis realmente disponíveis no registry. Conteúdo de páginas e índices pode divergir; os lockfiles são a referência reprodutível. Revisão de vulnerabilidades integra o aceite, não apenas a escolha da versão mais nova.
