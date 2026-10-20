# ADR 0002 — Agendamento Demo com autorização delimitada

Status: implementado e validado no Demo Mode. Data: 2026-10-20.

O próximo marco permite campanhas Demo recorrentes sem depender de infraestrutura externa. Não habilita Lab Mode, comandos Atomic ou Wazuh real.

Modelo: Schedule imutável (campanha, snapshot de escopo, cadência em segundos, início/fim UTC, máximo de ocorrências e duração máxima por run). Hash da autorização inclui escopo e todos os limites do plano. Criação por Operador/Admin permanece PENDING_APPROVAL; somente Administrador pode aprovar explicitamente futuras ocorrências. Pausa/revogação invalida a autorização atual; reativação exige nova aprovação. Histórico de autorizações é preservado.

Cadência mínima 60s e maior ou igual à duração máxima; até 64 planos abertos e 16 ativos; máximo 100 ocorrências; duração 10–300s; validade até 90 dias. O limite conta também ocorrências descartadas, evitando autorizações ilimitadas em ambientes ocupados. Não há execução retroativa: atraso superior a 30s gera descarte auditado. Laboratório ocupado descarta a ocorrência, sem violar reserva ou criar backlog de execuções.

Dispatcher em thread leve do worker existente, com sessões SQL independentes, usando PostgreSQL FOR UPDATE SKIP LOCKED. Ocorrência, consumo de limite, aprovação derivada e enqueue são uma única transação; unicidade por agendamento/horário e idempotência por run evitam duplicação. Serviços existentes oferecem transações controladas pelo chamador, preservando commits atuais da API. Nenhum job é serializado no Redis.

Worker revalida autorização no claim e entre etapas. Última ocorrência pode terminar após o plano atingir EXHAUSTED, dentro de seu prazo original; PAUSED/REVOKED/INVALIDATED não autorizam execução. Revogação cancela jobs ainda na fila e solicita cleanup cooperativo de runs ativos. Mudanças no laboratório, testes ou inventário de regras invalidam o plano; não se amplia um escopo já autorizado.

Evidências/relatórios usam o fluxo existente e registram a origem agendada e a autorização. UI oferece criação, revisão, aprovação, pausa, revogação e histórico reais. Validação inclui concorrência PostgreSQL, limites, expiração, indisponibilidade do worker, rollback, cancelamento e E2E de uma ocorrência Demo.

Referências oficiais revisadas: [PostgreSQL 17 SELECT/locking](https://www.postgresql.org/docs/17/sql-select.html) e [SQLAlchemy 2.1 transações](https://docs.sqlalchemy.org/en/21/orm/session_transaction.html). Não adicionamos biblioteca, serviço, cron externo ou dependência paga.

O grant exato acompanha Approval e ScheduleOccurrence; nenhuma retomada substitui o grant de uma run existente. Ao encerrar emissão, EXHAUSTED preserva runs anteriores válidas mesmo se o último slot foi descartado. Deadline é limitado ao fim da autorização. Pendentes/pausados vencidos liberam quota. Campos de plano e grant são protegidos por privilégios SQL por coluna; ocorrências append-only e históricos sem DELETE no runtime. [Operação](../../operations/scheduling.md).
