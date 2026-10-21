# Modelo de dados 0.2

Entidades implementadas nas migrações, com IDs UUID, índices, FKs e timestamps UTC:

```mermaid
erDiagram
  User ||--o{ LoginSession : autentica
  Laboratory ||--o{ Asset : identifica
  Laboratory ||--o| LinuxLabBinding : fixa
  Laboratory ||--o{ LabVerification : verifica
  TestExecution ||--o| RunnerDispatch : prepara
  TestExecution ||--o| RunnerReceipt : comprova
  TestExecution ||--o| RunnerCleanup : limpa
  Laboratory ||--o{ Campaign : delimita
  Campaign ||--o{ CampaignTest : seleciona
  TestDefinition ||--o{ CampaignTest : referencia
  AttackTechnique ||--o{ TestDefinition : classifica
  Campaign ||--o{ CampaignRun : repete
  CampaignRun ||--o| Approval : autoriza
  CampaignRun ||--o{ TestExecution : executa
  CampaignRun ||--o{ ExecutionStep : registra
  TestExecution ||--o{ TelemetryEvent : coleta
  TestExecution ||--o| ValidationResult : classifica
  ValidationResult ||--o{ DetectionEvidence : justifica
  TelemetryEvent ||--o{ DetectionEvidence : sustenta
  DetectionRule ||--o{ RuleVersion : versiona
  User ||--o{ AuditEvent : atribui
  Campaign ||--o{ Schedule : agenda
  Schedule ||--o{ ScheduleAuthorization : autoriza
  Schedule ||--o{ ScheduleOccurrence : contabiliza
  Schedule ||--o{ CampaignRun : origina
  ScheduleAuthorization ||--o{ ScheduleOccurrence : delimita
  ScheduleAuthorization o|--o{ Approval : deriva
  CampaignRun o|--o| ScheduleOccurrence : identifica
```

Papéis são enumeração com CHECK no usuário, sem tabela artificial de permissões. Relação campanha/teste e evidência/resultado é relacional. Táticas/plataformas usam arrays PostgreSQL de strings. JSONB está restrito ao snapshot de escopo, payload original e detalhes de auditoria.

Unicidade: usuário; token de sessão (hash); ID externo de ativo; STIX ID; chave de idempotência por solicitante; aprovação por run; teste por run; marcador; evento por execução/origem/ID; resultado por execução; versão por regra. `active_run_id` é uma reserva controlada por transação e bloqueio da linha do laboratório, sem exclusão automática de registros históricos.

As datas são `timestamptz`; apresentação usa o fuso do navegador. Comparações usam versões de testes, regras, ambiente e parâmetros registrados no snapshot. Mudanças posteriores de Sigma não reescrevem resultados. Hashes asseguram verificação de conteúdo, não assinatura ou garantia contra administrador do banco.

Relatórios e cobertura são projeções dos dados persistidos. Schedule, ScheduleAuthorization e ScheduleOccurrence são tabelas reais com constraints, contadores e histórico. Unicidade por plano/horário, run por ocorrência e uma autorização não revogada por plano impedem duplicação. Planos preservam scope/plan hashes; aprovações derivadas mantêm FK ao grant exato. Não existem tabelas fictícias de Report ou CoverageSnapshot; relatórios/cobertura continuam projeções. Conector é configuração de implantação, não cadastro de URLs arbitrárias via API.

Retenção inicial: não há expurgo automático. Históricos e auditoria são mantidos; limitação de disco deve ser acompanhada. `make clean-demo` remove somente campanhas/resultados sintéticos, e planos Demo encerrados, exigindo revogar planos abertos e finalizar reservas, com confirmação local, e preserva auditoria/usuários/catalogação. Sessões vencidas deixam de autenticar, mas ainda não são expurgadas automaticamente. Antes de operar Lab Mode, definir política de retenção e arquivo externo de evidências.

Linux: binding com runner único, revisão e hash da configuração pública; verificações append-only com validade e versão do ambiente. Dispatch único por execução persiste spec/hash antes da rede; somente generation pode receber UPDATE no papel runtime. Recibo e cleanup únicos por execução são append-only, com comparação de hash e conteúdo em retries. JSON contém mensagens tipadas do protocolo, não comandos arbitrários. Estes comprovantes não são TelemetryEvent nem DetectionEvidence. Migração d4465b7aca2a preserva registros Demo existentes.
