# Fluxo transacional

```mermaid
sequenceDiagram
  actor Operator
  actor Admin
  participant API
  participant PG as PostgreSQL
  participant Worker
  Operator->>API: Criar campanha e solicitar execução (idempotency key)
  API->>PG: Snapshot imutável + PENDING_APPROVAL + auditoria
  Admin->>API: Revisar hash e aprovar duração/validade
  API->>PG: Aprovação de uso único
  Operator->>API: Confirmar início
  API->>PG: Lock run/lab, revalidar, consumir aprovação, reservar lab, QUEUED
  Worker->>PG: SELECT FOR UPDATE SKIP LOCKED
  Worker->>PG: Revalidar autorização + PREPARING
  Worker->>Worker: Executar adapter Demo em memória
  Worker->>PG: COLLECTING + eventos sintéticos
  Worker->>Worker: Validar identidade, marcador, comportamento, regra e tempo
  Worker->>PG: VALIDATING + resultados + evidências com hash
  Worker->>Worker: CLEANING_UP obrigatório
  Worker->>PG: Estado terminal + liberar lab se cleanup concluído
  Operator->>API: Consultar evidências / exportar relatório
```

Não há envio paralelo PostgreSQL/Redis de jobs. Redis indisponível impede novos logins e sinalização de heartbeat, mas não perde jobs persistidos. Apenas testes de um laboratório podem estar reservados por vez. Mais de um worker pode reclamar laboratórios diferentes.

A máquina de estados e as transições permitidas estão em `domain/states.py`. Cancelamento de item em execução passa por cleanup; itens ainda não iniciados podem ser cancelados diretamente. Falha de cleanup mantém a reserva até revisão administrativa. Recuperação de worker interrompido só descarta contextos sintéticos, marca timeout e nunca repete efeitos desconhecidos.

## Emissão agendada

```mermaid
sequenceDiagram
  actor Operator
  actor Admin
  participant API
  participant PG as PostgreSQL
  participant Tick as Dispatcher no worker
  Operator->>API: Criar plano Demo e limites
  API->>PG: Snapshot + PENDING_APPROVAL
  Admin->>API: Confirmar hash e autorizar execução automática
  API->>PG: ScheduleAuthorization + ACTIVE
  Tick->>PG: Lock Schedule SKIP LOCKED + revalidar grant/escopo
  alt Slot atrasado ou laboratório ocupado
    Tick->>PG: Ocorrência descartada + consumo do limite
  else Slot válido e lab disponível
    Tick->>PG: Transação: run + aprovação derivada + reserva + QUEUED + ocorrência
    Note over PG: Worker utiliza o fluxo normal e o grant exato
  end
  Operator->>API: Pausar plano
  API->>PG: Revogar grant + cancelar fila + sinalizar runs ativas
```

Dispatcher usa sessão SQL própria em thread leve. Planos pausados só retomam mediante nova autorização; contador e calendário são preservados. Grants antigos não são substituídos em runs existentes.
