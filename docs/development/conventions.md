# Convenções

- Domínio puro: sem FastAPI, SQLAlchemy ou SIEM. Adaptadores convertem entradas para contratos explícitos. Serviços coordenam transações e autorizações.
- Entrada HTTP com Pydantic `extra=forbid`; nunca aceitar comando, URL de alvo, caminho de arquivo ou executor arbitrário. Banco via parâmetros/ORM; identificadores SQL administrativos via psycopg.sql.
- Funções e tipos Python em inglês; UI e documentação em pt-BR. Labels compartilhados em `apps/web/src/lib.tsx`, sem resultados hardcoded na interface. Mensagens podem ser extraídas para catálogo de i18n posteriormente.
- Alembic para toda mudança de schema, incluindo teste com dados existentes. Nenhum `create_all` no startup.
- `make format`, `make lint`, `make test`; E2E antes de concluir mudança de fluxo. Testes devem verificar regras de negócio e riscos concretos, não simplesmente reproduzir implementação.
- Seguir política de `AGENTS.md`: somente main, commits Conventional Commits granulares, staged revisado, push após cada commit. Não versionar segredos, logs, node_modules ou dist. Screenshots de documentação são capturas reais e identificadas como Demo.
