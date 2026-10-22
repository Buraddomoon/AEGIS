# Changelog

## Continuidade — inspeção Wazuh antes do efeito real

- Novo `make wazuh-lab-inspect`: valida metadados efetivos de isolamento do projeto
  exato via Docker somente leitura, sem iniciar serviços ou executar dentro deles.
- Recusa deriva de portas/redes/mounts/privilégios/limites e serviços extras;
  saída contém checks e booleans, sem Environment, segredos ou diagnóstico bruto.
- Testes de snapshots verificam fronteiras e falhas. Wazuh real permanece pendente
  sob o preflight/autorização existente; não inferir ingestão desses checks.

## Continuidade — ensaio Wazuh isolado preparado

- Projeto opt-in separado com Wazuh4.14.9 oficial fixado por digest linux/amd64,
  credenciais/PKI próprias, roles de leitura/ingestão distintas e mounts/rede limitados.
- Observer com log JSONL limitado, fsync/flock, deduplicação e recusa de conflitos
  após restart; tmpfs compartilhado runnerRW/observerRO e agente somente no log.
- Lifecycle e preflight somente leitura, bloqueando recursos insuficientes e
  ambiente/contexto externo; encerramento preserva volumes mesmo com pouca RAM.
- Ensaio único autorizado sob condição de recursos; início bloqueado por RAM
  disponível. Nenhuma instalação Wazuh ou detecção externa declarada.

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

## 0.2.0 — 2026-10-21 — campanhas Linux integradas

- Binding revisado e preflight mTLS, autorização de laboratório, aprovação de operação por administrador distinto e allowlist exclusiva de marcador benigno.
- API/worker persistem dispatch antes da RPC, geração, recibo e cleanup imutáveis; crash conserva quarentena e recuperação nunca inicia/reaplica o efeito.
- UI distingue real/sintético, comprovante do executor e evidência defensiva; indicadores, matriz e histórico por modo; relatórios proporcionais às evidências.
- Ensaio integrado autorizado: uma campanha, marcador de 43 bytes, cleanup confirmado, INCONCLUSIVE sem SIEM. Overlay separado, contas temporárias desativadas e serviços encerrados.
- Testes de respostas perdidas, rollback após cleanup, recuperação concorrente e revogações; capturas reais e regressão E2E Demo. Wazuh externo permanece pendente.

## Continuidade — coleta Wazuh preparada sem instalação externa

- Binding administrativo de agent.id/regra/índices/schema/janelas e fingerprint de política/destino/CA/principal; revisão explícita sem credenciais na API.
- Worker coleta por contrato, polling cancelável com orçamento/cleanup, prazo HTTP integral, mapeamento estrito de agente, limites e resumo append-only; correlação 1.1 invalidando aprovação antiga.
- UI e relatórios mostram política, tentativas, janela e evidência, distinguindo receipt do executor e conectividade/ingestão não verificadas.
- Observer passivo de marcador, configuração/XML e mounts de referência; sem instalação automática, nova simulação real ou consulta Wazuh externa. Testes de contrato, TLS loopback e Demo reais; exemplos Wazuh-logtest aguardam ambiente próprio.
