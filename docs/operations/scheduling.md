# Agendamentos Demo sob aprovação

O agendamento usa as mesmas campanhas, reservas, máquina de estados, worker, correlação e relatórios das execuções manuais. Toda simulação e evidência continua sintética. Não há agendamento para Lab Mode ou Wazuh externo.

## Operação na interface

1. Crie uma campanha com Demo Lab autorizado.
2. Abra **Agendamentos → Novo agendamento**. Selecione campanha, início/fim, intervalo em segundos, limite de horários e duração máxima.
3. O plano fica `PENDING_APPROVAL`. Administrador abre **Detalhes → Revisar autorização recorrente**, inspeciona limites e snapshot e confirma explicitamente execução automática.
4. O worker processa cada horário dentro da janela e registra execução ou descarte. **Ver execução** abre etapas, resultados, eventos e evidências. JSON exportado inclui plano, ocorrência e autorização de origem por identificador.
5. **Pausar plano** revoga a autorização corrente e cancela trabalhos na fila. Retomada exige nova aprovação de administrador, preservando o orçamento já consumido.
6. **Revogar autorização** encerra definitivamente o plano. É possível revogar um plano sem horários restantes para cancelar uma última execução ainda ativa.

**Relatórios automáticos**, nos detalhes do plano, mostra os snapshots solicitados
pelas novas ocorrências: inicial da autorização e comparação com a execução
anterior do mesmo grant. Worker gera após o término; JSON/HTML/PDF exportam o
documento congelado. [Semântica, limites e erros](scheduled-reports.md).

Não há botão de disparo imediato que contorne aprovação ou calendário. Uma execução manual continua exigindo sua aprovação independente.

## Limites e semântica

| Controle | Política |
|---|---|
| Ambiente | somente Demo Lab autorizado; ativo sintético e allowlist |
| Início | futuro, no máximo 30 dias após criação |
| Fim | posterior ao início, até 90 dias após criação |
| Cadência | 60 segundos a 30 dias; maior ou igual à duração máxima |
| Duração | 10–300 segundos; prazo absoluto inclui espera na fila |
| Orçamento | 1–100 horários considerados; emitidos **e** descartados consomem limite |
| Capacidade global | até 64 planos abertos (pendentes/ativos/pausados); até 16 ativos |
| Atraso | até 30 segundos; depois disso `SKIPPED_LATE`, sem execução retroativa |
| Laboratório reservado | `SKIPPED_BUSY`; sem execução parcial ou backlog |
| Concorrência | uma reserva por laboratório; cleanup falho mantém reserva |
| Horários | UTC no banco; interface aceita/exibe fuso local do navegador |

Horários são `starts_at + n × interval_seconds`, sem deriva por tempo de execução. O worker processa slots perdidos de forma limitada (20 por rodada), contabilizando descartes. Um worker parado não gera uma rajada retroativa ao voltar. Aprovar novamente não reinicia contador nem muda calendário.

Prazo de cada run: mínimo entre instante de emissão + duração máxima e fim da autorização. A validade limita toda a execução, não apenas seu início. `EXHAUSTED` encerra novas emissões, preservando runs já emitidas até seus prazos e desde que o grant original siga válido. `EXPIRED` representa validade encerrada. Planos pendentes/pausados também expiram e liberam a quota de planos abertos.

Mudanças no ambiente, allowlist, testes ou versões do inventário Sigma invalidam o snapshot e impedem novas emissões. Alterações exigem novo plano e nova revisão. Desativar criador ou aprovador, ou retirar seus papéis necessários, também invalida a autorização. Esse controle não afirma que regras Sigma estejam implantadas.

## Auditoria e consistência

- `Schedule` preserva escopo e hash do plano com todos os limites e versão da política.
- `ScheduleAuthorization` registra aprovador, hash, validade e eventual revogação. Nova aprovação cria outro registro.
- `ScheduleOccurrence` registra horário, grant exato, estado e justificativa, com unicidade `(schedule_id, scheduled_for)`; somente `QUEUED` tem run.
- A aprovação de cada run referencia o grant que realmente a originou. Pausar e reaprovar não ressuscita uma run antiga.
- Consumo do slot, criação da run/testes, aprovação derivada, reserva e enqueue são uma transação PostgreSQL. Savepoint remove efeitos parciais se o laboratório está ocupado.
- Claim e fases do worker revalidam o grant original. Revogação cancela fila e solicita cancelamento cooperativo durante execução. Uma fase já iniciada pode terminar antes de observar revogação; cleanup sempre é tentado. Não há interruptor forçado para adaptadores bloqueantes, que continuam vedados em Lab Mode.
- Locks de controle seguem `schedule → run → laboratory`. Worker bloqueia run e lê grant/plan sem row lock, evitando inversão.
- Dispatcher roda em thread leve do processo worker, com sessão SQL própria por transação. Uma simulação não bloqueia a consulta dos horários. Não há daemon extra, cron do host ou job serializado no Redis.
- No papel SQL runtime, plano só permite UPDATE de estado/contador/próximo horário/motivo; grant só permite UPDATE de revogação. Ocorrências são append-only. Nenhum desses históricos permite DELETE no runtime.

A instância continua sendo um workspace único: operadores compartilham campanhas e podem pausar planos; somente administradores aprovam/retomam/revogam. Viewer apenas consulta. Mutações exigem RBAC e CSRF no backend.

## API

- `GET/POST /api/v1/schedules` — lista paginada/criação por operador.
- `GET /api/v1/schedules/{id}` — plano, snapshot e histórico de autorizações.
- `GET /api/v1/schedules/{id}/occurrences` — histórico paginado de horários.
- `POST /api/v1/schedules/{id}/approve` — admin; `confirm_plan_hash` e `confirm_automatic_execution: true` obrigatórios.
- `POST /api/v1/schedules/{id}/pause` — operador/admin; `confirm: true`.
- `POST /api/v1/schedules/{id}/revoke` — admin; `confirm: true`.

Sem endpoint de edição dos limites nem exclusão. OpenAPI descreve campos e validações. As execuções/relatórios incluem `schedule_id`, `approval.schedule_authorization_id` e `schedule_occurrence`.

## Diagnóstico e limpeza

Sem ocorrências: confira estado ACTIVE, início/fim, worker e autorização do laboratório. Consulte motivo do plano e auditoria `schedule.*`. Falhas de transação são registradas no log do worker e não consomem parcialmente um slot.

`SKIPPED_BUSY` exige resolver a reserva do laboratório; falha de cleanup exige revisão administrativa. `SKIPPED_LATE` pede verificar disponibilidade do worker e relógio UTC. Nenhum desses estados demonstra falha de detecção, pois não executou teste.

`make clean-demo` exige revogar planos abertos e finalizar/liberar reservas; remove dados exclusivamente Demo usando credencial de manutenção e preserva auditoria/identidades. Nunca execute limpeza contra schemas de outro projeto.

Testes: `make test-integration`, `make e2e` e `make smoke`. O smoke usa API/worker do Compose com `aegis_app`, cobrindo grants restritos, emissão automática, relatório e revogação. Evidências da rodada executada ficam em [PROGRESS](../PROGRESS.md).
