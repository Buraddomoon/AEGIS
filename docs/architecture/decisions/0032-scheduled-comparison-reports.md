# ADR0032 — Relatórios automáticos de ocorrências Demo

Data:2026-11-09. Estado: em implementação. Sem nova dependência, serviço, acesso
SIEM, execução Linux ou mudança dos limites/aprovações do agendamento.

Cada ocorrência Demo efetivamente emitida solicita um documento na mesma transação
de ocorrência/run/aprovação/reserva. Descartes não solicitam relatórios. Não fazer
backfill de ocorrências anteriores à implantação nem alterar planos/grants antigos.
Tabela própria `scheduled_reports` representa essa fila e seu artefato; o JSON é
o documento exportável, não substitui as relações de agendamento/run/autorização.
Esse requisito de snapshot automático difere das exportações sob demanda do ADR0015.

O par fica fixado na emissão, sob o lock do agendamento: ocorrência executada
imediatamente anterior do mesmo plano e MESMA autorização. Sem anterior, produzir
relatório individual inicial. Não atravessar uma reaprovação, escolher somente
resultados positivos ou ignorar uma run anterior falha para obter comparabilidade.
Descartes permanecem no histórico sem virar execução/resultado defensivo. Um novo
documento pode comparar com uma run anterior já existente da mesma autorização;
isso não solicita retroativamente um documento para aquela ocorrência legada.

Após a run atual atingir um estado terminal, a thread de relatórios do worker
processa a fila com sessões próprias, uma linha por transação, FOR UPDATE OF fila
SKIP LOCKED. Não bloquear run/schedule/lab nem manter sessão entre threads. Dados
do documento vêm de snapshot separado REPEATABLE READ READ ONLY, SQL15s. Usar os
builders/correlação de comparação existentes; contexto inconsistente falha fechado.
Nenhuma coleta, simulação, alteração de regra ou aprovação decorre desse trabalho.

PENDING → READY/FAILED; até três tentativas de geração com espera delimitada,
sem documento parcial. Commit atômico do artefato, hash completo e auditoria;
crash antes do commit libera a linha para cálculo sem efeitos externos. Snapshot
até2MiB, sem truncamento. Documento concluído/identidades são imutáveis por trigger
e ACL; manutenção explícita pode excluir dados Demo junto de seu histórico.

O documento preserva os formatos existentes e acrescenta proveniência automática.
Comparação é resselada após acrescentar metadados; individual conserva digest(run).
Hash próprio da linha cobre o documento inteiro. READY significa documento gerado,
não detecção ou melhora. Inconclusivos/falhas mantêm limitações e delta ausente.
Gerar JSON automaticamente; HTML/PDF são renderizações desse snapshot ao baixar,
com autenticação, rate limits e políticas de exportação já existentes.

API de consulta/exportação por agendamento para qualquer papel autenticado, sem
endpoint de geração/retry que execute simulações. UI mostra tipo, estado, par,
tentativas/erro e downloads somente quando pronto. Falha e ausência legada são
explícitas. Retirar autorização não apaga evidências/relatórios históricos.

Migração aditiva, grants restritos e testes de upgrade com dados. A nova revisão
requer código/imagem compatíveis para recovery; preservar backups/imagens antigos.
Reconciliação offline encerra PENDING como FAILED/RECOVERY_RECONCILED para evitar
processar filas restauradas; READY/FAILED já finais permanecem intactos. Nenhuma
migração ou novo ensaio em volumes Linux/Wazuh decorre dessa mudança.

Validar transação/rollback, concorrência, restart, seleção do par, reaprovação,
cancelamento/cleanup falho, integridade/imutabilidade, limites/retries, RBAC,
snapshot, reconciliação, UI e E2E Demo descartável antes de anunciar operacional.

Referências oficiais consultadas, sem atualizar o pin SQLAlchemy2.1.5:
[SQLAlchemy2.1 — transações e isolamento](https://docs.sqlalchemy.org/en/21/orm/session_transaction.html),
[PostgreSQL17 — SELECT e SKIP LOCKED](https://www.postgresql.org/docs/17/sql-select.html),
[PostgreSQL17 — triggers](https://www.postgresql.org/docs/17/trigger-definition.html).
