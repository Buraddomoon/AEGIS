# Changelog

## Continuidade2026-10-26 — backups cifrados verificáveis

- age/X25519 em streaming com pyrage opcional host-only, chaves privadas separadas,
  limites/arquivos privados e publicação exclusiva, sem novo endpoint.
- Decriptação autenticada completa, hash dos bytes consumidos e restore na mesma
  engine offline, sem fallback ao original ou alteração no banco em uso.
- Inventário/retenção somente leitura: snapshots distintos e verificados, chave
  disponível, cópias incompletas/não verificadas preservadas; sem exclusão/upload.
- Sem mudança de schema, frontend, senha humana ou novo ensaio Linux/Wazuh.

## Continuidade2026-10-26 — cobertura por recorte e relatórios comparativos

- Filtros por ambiente, período de solicitação e release/legado, preservando
  contexto desconhecido e denominadores explícitos em snapshot de leitura.
- Exportações agregadas/comparativas HTML/JSON com membros, evidências, hashes,
  limitações e delta apenas quando o par sustenta comparabilidade.
- Verificação de manifesto, filhos/resultados completos e integridade do scope;
  UI bloqueia comparações/exportações obsoletas ou após falha de atualização.
- Sem migração/dependência nova, mudança de veredicto histórico ou ensaio real.

## Continuidade2026-10-23 — catálogo ATT&CK controlado

- Preparação por commit oficial, cache privado, validação limitada do perfil
  Enterprise, plano de revisão READ ONLY e publicação atômica por hash/ator.
- Releases imutáveis, projeção com retirada/ausência explícitas, IDs/histórico
  preservados e escrita de catálogo negada ao papel runtime.
- Escopos novos registram contexto; worker recusa contexto desconhecido/alterado
  antes de efeitos. Cobertura atual e histórico separados, sem reclassificação.
- Proveniência, filtros e snapshots na UI/API, com proteção contra mistura de
  páginas; E2E Firefox e publicação real do bundle20.0 no Demo validados.
- Migração a0d9c7e21b45; backups anteriores exigem imagem/código compatíveis.
  Nenhuma nova simulação Linux/Wazuh ou conversão Sigma decorre desta entrega.

## Continuidade2026-10-23 — primeiro ciclo Demo recuperado

- Ensaio opt-in restaura/reconcilia/confere quarentena antes de API/worker/Redis
  normais somente no namespace offline do clone, com conta/lab/aprovação novos.
- Permissões runtime compartilhadas sem alteração e baseline privada de hashes
  para exigir todas as linhas antigas intactas e estrutura preservada.
- Uma run real do worker com4testes sintéticos, evidências, indicadores e relatórios
  HTML/JSON conferidos; fechamento da conta/sessão/lab e cleanup confirmados.
- Falha/ownership incerto retém dependências sem sucesso. Sem cutover, novos
  efeitos Linux/Wazuh ou recuperação de segredos/Redis/journals anteriores.

## Continuidade2026-10-23 — reconciliação offline Demo

- Plano com hash de dados/estrutura, transação única e bloqueio de drift,
  concorrência, tabelas extras ou efeitos reais pendentes no clone descartável.
- Invalidação de sessões/contas/labs/grants restaurados e cancelamento somente
  sintético por transições válidas, com timestamps/histórico preservados.
- Recibo idempotente e review com ID/hash exatos e fences de pais/filhos.
- Ensaio real verificou30tabelas/2.884linhas originais,1auditoria nova,
  API em quarentena e clones removidos. Sem retomada/cutover ou novo ensaio real.

## Continuidade2026-10-23 — boot recuperado em quarentena

- Modo recovery no boot: somente health e revisão agregada com token novo,
  sem login/sessões históricas, rotas operacionais, frontend ou docs interativas.
- Worker/scheduler/CLI/migrations bloqueados antes de conectar. Privilégios
  PostgreSQL conferidos, incluindo colunas e funções de large objects.
- Ensaio host-only restaura backup em clone offline, provisiona SELECT/SCRAM,
  inicia API isolada, confere bloqueios e inventário inalterado e remove clones.
- Cleanup da API incerto mantém banco para inspeção, sem recibo de sucesso.
- Sem reconciliação/reativação automática, cutover, promessa RPO/RTO ou novo
  efeito/consulta em laboratório Linux/Wazuh.

## Continuidade2026-10-22 — backup e recuperação verificável do Demo

- Dump PostgreSQL por snapshot compartilhado com inventário de30tabelas, hashes
  internos e estrutura; arquivos privados fora do Git.
- Restauração em clone efêmero sem rede/portas/workers, mesma imagem local porID,
  comparação estrita e recibo somente após cleanup. Sem alteração do banco ativo.
- Normalização restrita de casts de arrays literais que PostgreSQL reescreve no
  roundtrip; divergências restantes bloqueiam verificação.
- Plano de retenção somente leitura. Não há failover, cutover, RPO/RTO garantido
  ou recuperação de roles/secrets/journals.

## Continuidade2026-10-22 — preparação Sigma verificável

- Diagnóstico por versão/hash/perfil, campos candidatos e bloqueios de requisitos
  instalados versus metadados oficiais revisados, sem importar backends.
- Snapshot de METADATA de wheels verificados e perfil restrito ao marcador ÆGIS;
  dados _source não são apresentados como mapping físico do índice.
- Referências fieldref são identificadas e impedem mapeamento completo prematuro.
- UI com histórico, contexto conferido e estados explícitos; ações do inventário
  reorganizadas para legibilidade. Exemplo autoral sem ATT&CK artificial.
- Conversão continua indisponível: backends revisados exigem pySigma<2, core2.0.1;
  pipeline executável/mapping físico pendentes. Nenhum downgrade ou ensaio real.

## Continuidade 2026-10-22 — análise estática Sigma

- Análise autenticada por versão/hash, condições, campos declarados e cinco
  checks explicáveis AEGIS; resultado determinístico com versão do analisador.
- Interface permite consultar versões anteriores e recusa resposta de outro
  conteúdo; erros, ausência de versões e checks omitidos são explícitos.
- Preflight compartilhado limita cadeias/expansão antes do parser na importação
  e análise; profundidade YAML limitada, sem expandir payloads grandes nos testes.
- Backend/pipeline de conversão não configurado. Sem novos plugins, cache,
  implantação de regras ou execução real de laboratório.

## Continuidade 2026-10-22 — revisões Sigma e comparação de escopos

- Associações versionadas entre regras e testes, justificativa/autor, revisão
  necessária após nova versão, substituição otimista, retirada e histórico.
- FK composta, unicidade ativa, trigger monotônico, RBAC/CSRF, auditoria e
  privilégios SQL por coluna; sem alteração de expected_rule ou veredictos.
- Escopos novos guardam vínculos; comparação explica mudanças de inventário,
  testes e ambiente, distinguindo contexto legado desconhecido. Histórico intacto.
- UI em regras/matriz/cobertura, confirmação atrelada ao payload revisado e
  seletores estáveis enquanto comparação é consultada. Nenhuma implantação Sigma
  ou novo ensaio real; autorização Wazuh encerrada permanece consumida.

## Continuidade 2026-10-22 — pipeline Wazuh real validado

- Ensaio único autorizado com imagens 4.14.9 fixadas, mTLS, agenteActive, TLS,
  ACLs negativas, marcador43 bytes, um alerta/evidência original e cleanup físico.
  COMPLETED/DETECTED/CLEANED, synthetic=false, sem atribuição ATT&CK artificial.
- Corrigido grant bulk de ingestão no nível cluster; reader preservado. Security
  REST habilitada somente para administrador local do Indexer.
- Harness de uso único com intenção fsync antes de start, sem retries ambíguos,
  aprovação separada de 120s, captura de relatórios e revogação/desativação de contas.
- Alert/log/resumo registrados com hashes e testes offline. Containers/redes
  encerrados, volumes/journal preservados; autorização consumida. Nova execução
  exige novo escopo aprovado; não repetir marcador para capturas ou testes.

## Continuidade — inspeção Wazuh antes do efeito real

- Novo `make wazuh-lab-inspect`: valida metadados efetivos de isolamento do projeto
  exato via Docker somente leitura, sem iniciar serviços ou executar dentro deles.
- Recusa deriva de portas/redes/mounts/privilégios/limites e serviços extras;
  saída contém checks e booleans, sem Environment, segredos ou diagnóstico bruto.
- Testes de snapshots verificam fronteiras e falhas. Wazuh real permanece pendente
  sob o preflight/autorização existente; não inferir ingestão desses checks.
- Corrigida espera negativa no polling quando o guard de autorização demora mais
  que a fatia de sleep, evitando INCONCLUSIVE indevido sem afrouxar janela/deadline.

## Continuidade — ensaio Wazuh isolado preparado

- Projeto opt-in separado com Wazuh 4.14.9 oficial fixado por digest linux/amd64,
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
