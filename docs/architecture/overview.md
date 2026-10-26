# Arquitetura e evolução do código 0.2.0

ÆGIS é um monólito modular FastAPI com worker independente, PostgreSQL e Redis. React/TypeScript/Vite consome a API REST `/api/v1` na mesma origem. Nenhum serviço corporativo será acessado pela demonstração.

MVP 0.1: sessões opacas e RBAC; catálogo Enterprise ATT&CK oficial versionado; testes Demo com comportamentos explícitos; laboratório sintético; campanhas de escopo imutável; solicitações de execução, aprovação de uso único e expiração; fila durável PostgreSQL; execução sequencial por laboratório; cancelamento cooperativo e timeout; eventos, validação, evidências com SHA-256; métricas com denominadores; comparação; exportação HTML/JSON; inventário e versões Sigma com parsing pySigma; auditoria.

Fora do aceite 0.1: execução remota, instalação de Atomic, implantação de regras, agendamento de laboratório real, PDF e demonstração real Wazuh. Conector Indexer somente leitura e importador de metadados Atomic podem ser testados com fixtures, sem anunciar integração externa validada.

Esse parágrafo delimita o marco inicial. Posteriormente o pipeline Wazuh foi
validado em um único laboratório4.14.9, com marcador fixo, sem atribuição ATT&CK
ou generalização para outras regras. [Evidência e encerramento](../evidence/wazuh-2026-10-22/README.md).

Contratos em `aegis/domain/contracts.py`: ExecutionAdapter prepara/executa/limpa; TelemetryProvider coleta eventos; DetectionProvider separa alertas de observações; TestCatalogProvider importa metadados sem aprovar comandos; ReportExporter exporta dados persistidos. Regras de correlação são funções puras independentes de SIEM.

Fila: solicitação aprovada muda para QUEUED na mesma transação do consumo da aprovação e aquisição do laboratório. Worker reclama com SELECT FOR UPDATE SKIP LOCKED. Não há dual-write PostgreSQL/Redis para jobs. Retomada de worker não repete efeitos: execuções abandonadas são encerradas explicitamente. Linux opt-in agora usa o mesmo fluxo, com dispatch durável antes da RPC, recibos separados e quarentena real sem replay; ver ADR 0004.

Agendamento de campanhas Demo foi entregue como extensão do MVP, sob aprovação explícita e limites persistentes. Consulte [operação](../operations/scheduling.md) e ADR 0002 para políticas, contratos e validação.

Incremento 0.2: LinuxLabBinding/LabVerification fixam identidade e revisão administrativa; aprovação segregada, marcador único e recibos/cleanup append-only. Ausência de coleta SIEM produz INCONCLUSIVE. Cobertura e detalhes ATT&CK filtram modo. O Compose padrão permanece Demo; overlay integrado é opt-in e separado. [Instalação e recuperação](../../labs/linux/README.md).

O catálogo evoluiu para releases imutáveis e publicação CLI controlada (ADR0014);
análise de cobertura usa snapshot READ ONLY e recortes por modo/período/release
(ADR0015). Sigma preserva versões/vínculos e análise estática; compatibilidade de
conversão continua bloqueada. Ferramentas de recuperação são host-only, com
restore em clone offline, quarentena, reconciliação, novo ciclo Demo isolado e
cópia age/X25519 opcional; sem endpoint de restore/cutover/upload (ADRs0010–0016).

Entrega verificável: `scripts/check_release.py` lê somente o índice Git, confere
metadados/links/cabeçalhos PNG e reutiliza o scanner de padrões de credenciais.
É ferramenta de desenvolvimento, sem importação na API/worker ou acesso ao banco.
Não substitui testes ou revisão de segurança. [Procedimento](../operations/release.md).
