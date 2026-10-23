# ADR0012 — Reconciliação offline do clone Demo

Data: 2026-10-23. Complementa [ADR0011](0011-recovery-quarantine.md).

Adicionar `reconcile-demo` à ferramenta host-only de backup. Restaurar primeiro
em clone novo, conferir o inventário original e gerar um plano com hash de todas
as tabelas e estrutura. Aplicar somente nesse clone, identificado por nome exato,
label de ownership e rede none, por PostgreSQL local via docker exec. Não aceitar
URL, nome de container ou SQL do operador. Não expor mutação na API recovery.

Uma única transação bloqueia as tabelas em ordem fixa, refaz o plano e recusa
drift. Encerrar somente runs pendentes comprovadamente Demo, sem dispatch real,
com testes/ativos sintéticos. Runs reais pendentes, reservas órfãs, estados
desconhecidos ou execuções inconsistentes bloqueiam toda a aplicação do plano.
Não alegar cleanup de runner ou conclusão de efeitos externos.

Apagar sessões restauradas, desativar usuários restaurados, revogar laboratórios
e grants recorrentes e encerrar agendamentos retomáveis. Aprovações e scopes
históricos permanecem íntegros; suas runs ficam terminais e os ambientes revogados.
Registrar transições e um evento de auditoria append-only, com plano/hash e
contagens, sem credenciais ou conteúdos de evidências. Repetir a mesma aplicação
deve retornar o registro anterior, sem novos efeitos.

Conferir após a aplicação que somente tabelas/colunas permitidas mudaram e que
evidências, resultados, scopes, regras e histórico anterior permanecem iguais.
Iniciar novamente apenas API em quarentena e comparar seu inventário antes/depois
da leitura. Remover API antes do DB. Só então emitir recibo distinto. Preservar
backup, fonte e intents; falha não gera sucesso. Não reativar o Demo em uso,
workers, Redis, Linux, Wazuh ou contas restauradas.

Esse marco prepara a retomada; não autoriza operação normal nem reaproveitamento
de grants. Novo administrador, credenciais, laboratório Demo, aprovação e ciclo
sintético separados ainda devem ser validados antes de uma retomada normal.

Fontes: [PostgreSQL17 LOCK](https://www.postgresql.org/docs/17/sql-lock.html) e
[bloqueios explícitos](https://www.postgresql.org/docs/17/explicit-locking.html).
NOWAIT limita espera e a ordem fixa evita inversão entre reconciliações; isolamento
do clone é condição independente desses locks.
