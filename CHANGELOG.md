# Changelog

## 0.1.0 — 2026-10-20

- Primeiro MVP Demo com banco e worker reais, sessões/RBAC/CSRF, campanhas de escopo imutável, aprovação de uso único e fila PostgreSQL.
- Catálogo ATT&CK Enterprise 20.0 oficial, quatro simulações sintéticas, correlação conservadora, evidências, cobertura, comparação, relatórios HTML/JSON e auditoria.
- Interface React responsiva em pt-BR; inventário Sigma com parsing e versões.
- Adapter Indexer Wazuh somente leitura e importador Atomic de metadados, testados localmente sem execução externa.
- Migrações, Compose, hardening de runtime, testes de integração e E2E em Firefox com capturas reais.
- Git privado, somente main e commits/pushes granulares. CI com cache e cancelamento de redundâncias.
- Limitações: Lab Mode, Atomic executável, Wazuh externo, scheduler e PDF ainda não habilitados; advisory DiskCache herdado registrado com análise do caminho de parsing.

## Continuidade — agendamento Demo aprovado

- Planos recorrentes sob confirmação explícita administrativa, snapshot/hash, prazo e orçamento persistentes.
- Dispatcher transacional, deduplicação por slot, descartes auditados por atraso/ocupação, pausa/revogação e grant exato por execução.
- UI e APIs reais, histórico, origem agendada no relatório, privilégios SQL por coluna e cleanup protegido.
- Testes PostgreSQL concorrentes, fluxo de navegador com ocorrência automática e smoke do Compose com SQL runtime restrito.

## Continuidade 2026-10-21 — runner Linux opt-in

- Runner separado para marcador benigno, protocolo fixo e mTLS obrigatório com CAs de cliente/servidor distintas.
- Supervisor com deadline/lease, kill/reap, PDEATHSIG, diário persistente e fencing por UUID/hash/geração.
- Workspace restrito e cleanup sem recursão, manifest Docker isolado, PKI local e controller CLI com confirmação explícita.
- Testes de TLS real, concorrência, journal bloqueado, morte do pai e inspeção de isolamento; ensaio real autorizado confirmou efeito e cleanup, sem evidência defensiva de SIEM.
- Integração de campanhas Linux na UI/PostgreSQL permanece pendente; Wazuh real não conectado.
