# Arquitetura inicial

ÆGIS é um monólito modular FastAPI com worker independente, PostgreSQL e Redis. React/TypeScript/Vite consome a API REST `/api/v1` na mesma origem. Nenhum serviço corporativo será acessado pela demonstração.

MVP 0.1: sessões opacas e RBAC; catálogo Enterprise ATT&CK oficial versionado; testes Demo com comportamentos explícitos; laboratório sintético; campanhas de escopo imutável; solicitações de execução, aprovação de uso único e expiração; fila durável PostgreSQL; execução sequencial por laboratório; cancelamento cooperativo e timeout; eventos, validação, evidências com SHA-256; métricas com denominadores; comparação; exportação HTML/JSON; inventário e versões Sigma com parsing pySigma; auditoria.

Fora do aceite 0.1: execução remota, instalação de Atomic, implantação de regras, agendamento de laboratório real, PDF e demonstração real Wazuh. Conector Indexer somente leitura e importador de metadados Atomic podem ser testados com fixtures, sem anunciar integração externa validada.

Contratos em `aegis/domain/contracts.py`: ExecutionAdapter prepara/executa/limpa; TelemetryProvider coleta eventos; DetectionProvider separa alertas de observações; TestCatalogProvider importa metadados sem aprovar comandos; ReportExporter exporta dados persistidos. Regras de correlação são funções puras independentes de SIEM.

Fila: solicitação aprovada muda para QUEUED na mesma transação do consumo da aprovação e aquisição do laboratório. Worker reclama com SELECT FOR UPDATE SKIP LOCKED. Não há dual-write PostgreSQL/Redis para jobs. Retomada de worker não repete efeitos: execuções abandonadas são encerradas explicitamente. Linux opt-in agora usa o mesmo fluxo, com dispatch durável antes da RPC, recibos separados e quarentena real sem replay; ver ADR 0004.

Agendamento de campanhas Demo foi entregue como extensão do MVP, sob aprovação explícita e limites persistentes. Consulte [operação](../operations/scheduling.md) e ADR 0002 para políticas, contratos e validação.

Incremento 0.2: LinuxLabBinding/LabVerification fixam identidade e revisão administrativa; aprovação segregada, marcador único e recibos/cleanup append-only. Ausência de coleta SIEM produz INCONCLUSIVE. Cobertura e detalhes ATT&CK filtram modo. O Compose padrão permanece Demo; overlay integrado é opt-in e separado. [Instalação e recuperação](../../labs/linux/README.md).
