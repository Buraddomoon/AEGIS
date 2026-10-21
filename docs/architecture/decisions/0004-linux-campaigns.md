# ADR 0004 — Campanhas Linux com autorização e comprovantes distintos

Status: implementado e validado localmente em ensaio integrado especificamente autorizado. O runner do ADR 0003 passa a integrar a mesma máquina de estados/fila/API/UI do Demo, por opt-in de implantação. Sem Wazuh externo, Atomic, shell ou agendamento Linux.

Registro administrativo deriva IDs/endpoint de configuração local fixada, sem URL de API. Administrador declara revisão de isolamento, realiza preflight mTLS com validade curta e autoriza o laboratório. Escopo inclui ambiente, binding de identidade/certificados, versão do teste fixo e synthetic=false. Campanha Linux admite somente linux-file-marker/v1; nenhuma técnica ATT&CK é inventada.

Aprovação de execução Linux exige administrador diferente do solicitante e confirmação explícita de efeito real. Aprovações continuam únicas, com validade/duração/deadline e reserva. Worker revalida configuração, autorização e identidades. Scheduler permanece restrito a Demo.

Dispatch é persistido antes da primeira RPC de preparo, com spec/hash/UUID original. Geração fica vinculada ao job, inclusive quando resposta se perde. Comprovante do executor e confirmação de cleanup são registros próprios imutáveis, separados de TelemetryEvent/DetectionEvidence. Sem SIEM consultado, coleta indisponível produz INCONCLUSIVE, nunca DETECTED por receipt.

Crash real não recebe recuperação fictícia de contexto Demo: quarantine CLEANUP_FAILED, reserva mantida. Recuperação administrativa consulta/cancela/limpa somente job original com hash/geração, nunca start/replay. Confirmação verificada antecede liberação do laboratório. Dispatcher/receipts usam unicidade e INSERT ON CONFLICT para idempotência, verificando hash de conteúdo ao reencontrar registro.

Indicadores, catálogo e listas de avaliação recebem escopo demo/linux explícito; overview padrão permanece Demo e informa denominador. Detalhes/relatórios usam synthetic real do registro; UI distingue execução real, comprovante do executor e evidência defensiva. Relatório não transforma efeito em detecção.

Implantação Linux é overlay opt-in separado do Compose padrão, limitado ao runner isolado já revisado. Não iniciar laboratório/efeitos reais automaticamente. Preparar e testar código com PostgreSQL e runner de fixture em diretório pytest; ensaio integrado de containers exige aprovação de escopo concreto antes de iniciar. O único ensaio autorizado está registrado no PROGRESS.

Fontes: https://docs.sqlalchemy.org/en/21/dialects/postgresql.html#insert-on-conflict-upsert e https://docs.sqlalchemy.org/en/21/orm/session_transaction.html. Nenhuma nova dependência ou serviço pago.
