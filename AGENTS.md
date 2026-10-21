# ÆGIS — instruções de engenharia

## Política obrigatória de versionamento

Use exclusivamente `main`. Não criar branches temporárias nem pull requests. Reutilizar `origin` privado; o nome autorizado do repositório GitHub é `AEGIS`, em maiúsculas, em `Buraddomoon/AEGIS`. Se o remoto estiver ausente, reutilizar esse repositório privado antes de considerar criar outro. `ÆGIS` permanece o nome do produto; GitHub aceita somente ASCII no nome do repositório. Verificar visibilidade antes do primeiro push. Nunca tornar público nem mudar visibilidade sem autorização.

Criar commits Conventional Commits pequenos, frequentes e coerentes, incluindo unidades parciais verificáveis; não aguardar uma funcionalidade completa. Antes de cada commit, revisar arquivos staged, executar o check relevante e verificar segredos/temporários. Após cada commit, tentar `git push origin main` sem nova confirmação. Se a rede falhar, preservar commits e tentar sincronizar depois. Conflito remoto: parar somente sincronização e solicitar orientação; nunca force push, rebase de histórico publicado ou exclusão de commits. Continuar o desenvolvimento entre commits.

CI com cancelamento de execuções redundantes e cache; não habilitar recursos pagos. Em cada marco, informar quantidade de commits, último hash/mensagem, sincronização, funcionalidades, testes e próximas tarefas. Essa política foi explicitamente autorizada pelo usuário nesta sessão.

Leia `docs/PROGRESS.md` e os ADRs antes de alterar o código. Monólito modular Python + React; domínio em `apps/api/aegis/domain`, integrações atrás de Protocols. PostgreSQL é a fonte de verdade e fila durável; Redis atende limites de login e heartbeat. Não implemente shell remoto, execução de comandos de API, acesso ao socket Docker ou download/execução automática de testes Atomic.

Todos os resultados Demo, eventos e relatórios devem indicar `synthetic=true`. Ausência de alerta nunca prova ausência de telemetria. Evidências devem casar execução, marcador, ativo, laboratório, tipo de comportamento e tempo. Não modificar evidências históricas ao editar regras.

Use migrações Alembic explícitas. Mantenha aprovações de uso único delimitadas pelo hash do escopo, validade e duração. Toda mutação autenticada exige RBAC e CSRF. Somente administrador aprova; Demo permite autoaprovação explicitamente; Lab real precisa revisão separada antes de habilitar. Nunca publicar credenciais. Não iniciar Wazuh nem executar operações ofensivas reais sem autorização específica.

Comandos: `make setup`, `make up`, `make test`, `make lint`, `make build`, `make e2e`, `make down`. Testes de integração usam PostgreSQL e Redis exclusivos do projeto. Nunca limpar dados de outros projetos. Não declarar checks aprovados sem executá-los. Atualize docs/PROGRESS.md com evidência e pendências. UI em pt-BR; nenhuma ação decorativa. Interfaces não operacionais devem informar indisponibilidade.

Agendamentos operam somente em Demo: planos imutáveis, até 16 ativos/64 abertos, grant exato por run/ocorrência, validade e orçamento incluindo descartes. Não reativar runs antigas ao reaprovar. Locks de controle: schedule → run → lab; worker lê plano/grant sem row lock. Dispatcher usa sessão SQL própria por thread/transação e savepoint no laboratório ocupado. Cleanup permanece obrigatório após revogação. Ver ADR 0002 e docs/operations/scheduling.md.

Runner Linux standalone: leia ADR 0003 e labs/linux/README.md. Allowlist contém somente linux-file-marker/v1. Não aceitar comandos/paths/scripts de API. Comprovante execution_receipt não é telemetria defensiva e não pode virar DETECTED. Campanhas Linux continuam desabilitadas. O usuário autorizou apenas o ensaio local descrito em 2026-10-21; isso não autoriza Wazuh, alvos externos, recorrência ou novos tipos de teste. Não iniciar Lab automaticamente com make up/test/CI. Testes: make test-runner. Watchdog deve kill/reap antes de SQLite; resultado terminal/ownership sob mesmo lock. Preservar diário, identidade e fences após restart; nunca reaplicar efeito ambíguo.
