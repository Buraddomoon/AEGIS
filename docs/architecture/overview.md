# Arquitetura inicial

ÆGIS é um monólito modular FastAPI com worker independente, PostgreSQL e Redis. React/TypeScript/Vite consome a API REST `/api/v1` na mesma origem. Nenhum serviço corporativo será acessado pela demonstração.

MVP 0.1: sessões opacas e RBAC; catálogo Enterprise ATT&CK oficial versionado; testes Demo com comportamentos explícitos; laboratório sintético; campanhas de escopo imutável; solicitações de execução, aprovação de uso único e expiração; fila durável PostgreSQL; execução sequencial por laboratório; cancelamento cooperativo e timeout; eventos, validação, evidências com SHA-256; métricas com denominadores; comparação; exportação HTML/JSON; inventário e versões Sigma com parsing pySigma; auditoria.

Fora do aceite 0.1: execução remota, instalação de Atomic, implantação de regras, agendamento recorrente, PDF e demonstração real Wazuh. Conector Indexer somente leitura e importador de metadados Atomic podem ser testados com fixtures, sem anunciar integração externa validada.

Contratos em `aegis/domain/contracts.py`: ExecutionAdapter prepara/executa/limpa; TelemetryProvider coleta eventos; DetectionProvider separa alertas de observações; TestCatalogProvider importa metadados sem aprovar comandos; ReportExporter exporta dados persistidos. Regras de correlação são funções puras independentes de SIEM.

Fila: solicitação aprovada muda para QUEUED na mesma transação do consumo da aprovação e aquisição do laboratório. Worker reclama com SELECT FOR UPDATE SKIP LOCKED. Não há dual-write PostgreSQL/Redis para jobs. Retomada de worker não repete efeitos: execuções abandonadas são encerradas explicitamente. Lab real continua desabilitado.
