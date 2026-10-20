# Contribuindo com ÆGIS

Leia README, AGENTS.md, ADRs e docs/PROGRESS.md. Repositório privado e desenvolvimento exclusivamente em main: commits pequenos Conventional Commits, revisão de staged/segredos e push após cada commit. Não criar branches/PRs nem reescrever histórico publicado. Se houver divergência remota, preservar commits e interromper somente sincronização para orientação.

Antes de concluir: `make lint`, `make test`, `make build`; `make e2e` para alteração de fluxo. Novos adaptadores exigem testes de contrato e análise de segurança. Toda mudança de schema precisa de Alembic e teste com dados existentes. Registre limitações verificáveis, não anunciar integração não testada.

Não incluir dados empresariais, tokens, dumps ou infraestrutura externa presumida autorizada. Demonstrações devem preservar synthetic=true em API, evidências e relatórios. Nenhuma contribuição deve introduzir shell remoto, comandos arbitrários, execução automática de conteúdo importado ou desativar TLS/sandbox. Documente fontes/licenças de dados e dependências.
