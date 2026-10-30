# Registro de progresso — ÆGIS

Estado atual: **Demo/Linux 0.2.0, pipeline Wazuh real validado em um único ensaio encerrado e engenharia Sigma com revisões, análise estática e diagnóstico de preparação; backup/restore, reconciliação, quarentena e primeiro ciclo Demo recuperado verificados (marcos ao final)**. Demo saudável em localhost:18780. Ensaio COMPLETED/DETECTED/CLEANED, synthetic=false; laboratório revogado, contas desativadas e stack encerrado com volumes preservados. Autorização de uso único consumida. Registros anteriores abaixo são históricos.

## 2026-10-20 — Fundação e primeiro ciclo Demo

- Ambiente inspecionado; projeto novo em `/home/IVPTER/codes/aegis`, sem alterar projetos existentes. Python local 3.13.14, Node 24.18, Docker disponível. Serviços próprios PostgreSQL/Redis e portas loopback 18780–18784.
- Arquitetura e ADR 0001 registrados. Fila transacional PostgreSQL escolhida para evitar dual-write. Contratos SIEM independentes, máquina de estados e correlação conservadora implementados.
- Snapshot ATT&CK Enterprise 20.0 oficial: 706 técnicas/subtécnicas ativas, hash de origem no fixture e licença preservada.
- Backend implementado com autenticação, sessão opaca/Argon2id/CSRF, RBAC, catálogo, Demo Lab, campanhas, aprovação de uso único, worker, eventos, evidências, cobertura, comparação, HTML/JSON, parsing Sigma e auditoria.
- Primeira validação: **25 testes pytest passaram** (domínio + integração PostgreSQL real) em 9,61s. Migrações aplicadas e `alembic check` sem diferenças. `mypy` passou para domínio. Build React/TypeScript/Vite passou; aviso de bundle grande a tratar.
- UI implementada sobre API; validação de navegador e testes adicionais ainda pendentes neste ponto. Não declarar aceite completo.
- Conector Wazuh somente leitura implementado com TLS e IP fixado; **nenhuma conexão real validada**. Lab Mode, execução Atomic, scheduler, PDF e implantação de regras não habilitados.
- Revisão especializada inicial concluída; segunda revisão do código em andamento.
- Política de Git atualizada pelo usuário: repositório privado, somente main, commits granulares e push após cada commit. Aplicação da política em andamento; consultar `git log` e remoto para o estado atual.

## Próximas unidades verificáveis

1. Testes de segurança, importação e Wazuh com fixtures.
2. Fluxo E2E em Firefox já instalado, capturas reais e revisão visual.
3. Docker build/Compose completo, lockfiles, Makefile e CI.
4. Documentação operacional, limitações e aceite final do MVP Demo.

## Marco 0.1 — fluxo Demo validado

Fundação e primeiro MVP funcional implementados. Todos os cenários operacionais desta entrega são demonstrativos e explicitamente sintéticos; não houve execução ofensiva real, instalação de Wazuh ou acesso a alvos externos.

### Entregas

- API FastAPI versionada, PostgreSQL/Alembic, Redis, worker independente e SPA React/TypeScript responsiva em pt-BR.
- Sessões opacas/Argon2id, CSRF, RBAC, rate limit, erros sem echo de segredos, headers e origem restrita.
- 706 técnicas/subtécnicas oficiais ATT&CK 20.0, matriz/tabela/filtros; quatro simulações Demo em allowlist, com associação técnica somente quando justificada.
- Campanhas, scope/hash imutáveis, aprovação administrativa com validade/duração/uso único, confirmação de início, claim exclusivo e fence contra entrega duplicada.
- Cancelamento, deadline, cleanup obrigatório, erro visível/reserva retida na falha e recuperação de contextos sintéticos abandonados sem replay.
- Eventos/resultados/evidências persistidos, hashes, correlação conservadora, métricas com denominador, histórico, comparação, HTML/JSON e auditoria.
- Sigma parsing/versionamento/diff; importação Atomic somente metadados; adapter Wazuh somente leitura com TLS/IP pinning/scroll, testado por contrato e ainda desconectado de infraestrutura real.
- Docker não root/read-only/cap_drop; runtime SQL separado sem superuser e com evidências/auditoria/versões append-only.
- README com capturas reais, documentação de arquitetura/segurança/operação, licenças, Makefile e CI eficiente na main.

### Validação efetivamente executada

| Comando/check | Resultado observado |
|---|---|
| `make lint` | Ruff/format, mypy domínio e TypeScript/Prettier aprovados |
| `.venv/bin/pytest -q` | **56 passed**, 1 aviso upstream de TestClient/httpx, 16,43s na rodada final |
| `npm --prefix apps/web test` | **3 passed** |
| `make e2e` | **PASS**, Firefox do host, 2 runs / 8 testes sintéticos, zero erros JavaScript, comparação e exportação reais, viewport móvel sem overflow |
| `make build` | aprovado; bundle principal e gráfico separados, sem aviso de chunk >500kB |
| `docker compose build` + `up -d --wait` | aprovados; migrações/seed/grants e health DB/Redis reais |
| `make smoke` | aprovado no Compose final: login, campanha, aprovação, worker, 4 classificações persistidas e JSON; conta temporária desativada no fim |
| Privilégios no container | current_user=aegis_app, rolsuper=false, UPDATE em audit_events=false |
| `make audit` | npm: zero avisos; Python: um advisory transitivo DiskCache revisado, visível, com teste da premissa de caminho não utilizado |
| Markdown local | referências locais verificadas, sem destinos ausentes |

CI GitHub do código `4833eca`: **SUCCESS**, run [39478839252](https://github.com/Buraddomoon/AEGIS/actions/runs/39478839252). Instalação com locks, lint/tipos, testes PostgreSQL/React, build e auditoria remotos aprovados. O run anterior foi cancelado automaticamente por concurrency, confirmando a política de evitar jobs redundantes. Não foi habilitado plano/recurso pago. O checkpoint posterior modifica somente documentação/proveniência, sem exigir nova execução redundante de CI.

### Revisão e correções

Revisões especializadas iniciais/finais somente leitura não apontaram bloqueador restante para Demo. Corrigidos backfill de migração em banco populado, recuperação concorrente de reserva, streaming Wazuh, IPv4 mapeado, espaços significativos em senha, títulos Sigma excessivos e hash do JSON efetivamente exportado. Ver `security/review-2026-10-20.md`.

O repositório `Buraddomoon/AEGIS` foi criado com visibilidade PRIVATE, confirmada antes do primeiro push e novamente ao final. Desenvolvimento exclusivamente em main, sem PR, branches temporárias, force push ou reescrita. Commits/pushes granulares registrados em `git log`; estado exato do checkpoint de documentação é verificável com `git log -1` e `git status -sb`.

### Retomada / pendências reais

Aplicação local em `http://localhost:18780`. O administrador humano deve ser criado com `make bootstrap`; não há credencial padrão. `.env` local contém segredos aleatórios e está ignorado. Contas de smoke são aleatórias, sem senha registrada e desativadas ao final. Testes usam schemas descartáveis e não apagam dados do aplicativo.

Próxima etapa recomendada: preparar Linux Lab isolado próprio, obter autorização específica para um teste benigno, implementar isolamento/prazo efetivo dos adapters e mapear ativos internos/externos antes de ligar Wazuh. VM Windows somente quando autorizada e necessária. Lab Mode, Atomic executável, consulta Wazuh operacional, scheduler, PDF, implantação de regras e IA continuam no roadmap.

Sem claims de detecção real, proteção empresarial, zero vulnerabilidades ou maturidade enterprise-ready. Atualização do snapshot ATT&CK existe; substituição/depreciação em banco populado ainda requer migração de dados revisada. Sem tenant/MFA/SSO/recuperação de senha na UI e sem política automática de retenção.


## Renomeação do repositório GitHub

Por solicitação do usuário, o repositório foi renomeado para **AEGIS**, em maiúsculas, preservando PRIVATE e main. O GitHub [permite apenas caracteres ASCII no nome de repositórios](https://docs.github.com/en/repositories/creating-and-managing-repositories/creating-a-new-repository), portanto ÆGIS permanece a marca do produto e AEGIS é o nome remoto.

Origin de fetch/push atualizado explicitamente para `https://github.com/Buraddomoon/AEGIS.git`; README e AGENTS atualizados para evitar referências divergentes. O diretório de trabalho continua `/home/IVPTER/codes/aegis`; o exemplo de clone mantém esse nome local explicitamente. Validação desta mudança: consulta do nome/visibilidade/branch via gh, revisão de staged, fetch e push pela URL nova, comparação main/origin/main.

## Continuidade — agendamento Demo aprovado

Estado inicial: main limpa/sincronizada no commit 0e25333, remoto AEGIS confirmado PRIVATE e serviços Demo saudáveis. Próximo marco em implementação: agendamento de campanhas sintéticas sob aprovação delimitada, conforme ADR 0002. Não executar em laboratório real nem estabelecer conexão Wazuh externa. As etapas abaixo ainda precisam de validação antes de serem anunciadas como prontas: transações reutilizáveis, schema/autorizações, dispatcher, RBAC/API, UI, testes e documentação operacional.

## Marco seguinte — agendamento Demo implementado e validado

Continuidade do MVP em 2026-10-20. Agendamento agora é operacional **somente para campanhas sintéticas Demo**, sem qualquer execução ofensiva real, alteração de rede ou conexão Wazuh externa.

### Funcionalidades e decisões

- Planos imutáveis com snapshot/hash, início/fim UTC, cadência, duração e orçamento persistentes. Criação por operador/admin; aprovação administrativa exige confirmação explícita do hash e das futuras execuções automáticas.
- Limites: início até 30 dias, fim até 90 dias, cadência 60s–30 dias e maior ou igual à duração, 10–300s por run, 1–100 horários, 64 planos abertos/16 ativos globais.
- Dispatcher em thread leve do worker, sem serviço extra e com sessões SQL próprias. Cada slot é uma transação com lock SKIP LOCKED e unicidade; savepoint desfaz run/aprovação/reserva parciais quando lab ocupado.
- Atraso >30s e laboratório ocupado geram descarte auditado e consomem orçamento. Sem backlog ofensivo e sem recomeçar contador ao retomar plano.
- Grant exato por aprovação de run e ocorrência; claim/fases/cleanup final revalidam esse grant. Pausa/revogação cancela fila e sinaliza cancelamento cooperativo ativo; cleanup permanece obrigatório. Reaprovação nunca ressuscita runs antigas.
- UI real em Agendamentos: criar, revisar, aprovar, pausar, revogar, paginação, histórico de autorizações/slots e links para execução/evidências. Relatórios JSON/HTML preservam snapshot/hash do plano, autorização e ocorrência de origem.
- Campos de plano imutáveis protegidos por UPDATE por coluna; grant permite somente revogação; históricos de plano/grant sem DELETE e ocorrências append-only no papel runtime. Limpeza Demo exige revogar planos abertos e liberar reservas, preservando auditoria.

Arquivos principais: `apps/api/aegis/scheduling.py`, `models.py`, `worker.py`, `api.py`, `queries.py`, migração `cd91d47aae2f`; `apps/web/src/Scheduling.tsx`; `tests/test_scheduling.py`, `test_transactions.py`, `test_cleanup.py`; `scripts/smoke_compose.py`; ADR 0002 e `docs/operations/scheduling.md`.

### Validações executadas no código final

| Verificação | Resultado observado |
|---|---|
| `make lint` | Ruff/check/format, mypy domínio, TypeScript e Prettier aprovados |
| `make test` | **85 testes Python e 5 testes frontend passaram**, 1 aviso upstream TestClient/httpx; backend em 36,05s |
| Migração populada | downgrade/upgrade preservou run existente e `alembic check` sem diferenças, dentro da suíte |
| Testes de scheduling | 26 passaram: grant/hash/RBAC/limites, concorrência, tick versus pausa, rollback, busy/atraso, expiração, revogação ativa e cleanup |
| `make e2e` | **PASS**, Firefox real, 3 runs/12 testes sintéticos, comparação, agendamento aprovado pela UI, emissão automática, exportação com plano/grant e zero erros JavaScript; viewport móvel sem overflow |
| Capturas reais | overview/execution/attack/mobile atualizadas e schedules.png inspecionada |
| Docker build + Compose `up -d --wait` | aprovados; imagem final publicada apenas no Docker local, API/DB/Redis saudáveis e worker ativo |
| `make smoke` | **PASS** na imagem final: run manual e agendada, 8 resultados sintéticos, grant/plano, JSON, revogação e permissões restritas de aegis_app |
| `make audit` | npm zero achados; Python mantém um advisory transitivo DiskCache explicitamente revisado, sem novos achados desconhecidos |
| Referências locais Markdown | verificação sem destinos ausentes |

A revisão especializada somente leitura identificou uma expiração antecipada após último slot descartado, que poderia cancelar uma run anterior ainda válida. Corrigido para EXHAUSTED e coberto por regressão. Também corrigida quota retida por planos pendentes/pausados vencidos. Grants SQL foram conferidos pelo smoke, além dos testes que usam schema owner.

### Estado operacional e retomada

Aplicação atualizada em `http://localhost:18780`. Para criar administrador humano, `make bootstrap`; nenhuma senha padrão foi adicionada. Contas temporárias de smoke foram desativadas; E2E usa schema descartável. Planos criados pelo smoke são encerrados/revogados, sem autorização recorrente residual.

Repositório GitHub `Buraddomoon/AEGIS` confirmado **PRIVATE**, somente main. Commits granulares e push após cada commit; sem PR, force push, branches temporárias ou reescrita. Código final do marco: `0c76157`; commits posteriores atualizam documentação/capturas. Quantidade/hash/mensagem do checkpoint são verificáveis em `git log -1`, `git rev-list --count HEAD` e `git status -sb`.

CI final do código `0c76157`: **SUCCESS**, [run 39488379605](https://github.com/Buraddomoon/AEGIS/actions/runs/39488379605), job em 1m40s. Locks, lint/tipos, integração PostgreSQL/frontend, build e advisory review aprovados remotamente. Runs redundantes anteriores canceladas por concurrency. Commits posteriores modificam somente documentação/capturas e são ignorados pela CI conforme política de economia.

Este marco acrescenta **14 commits**, incluindo este checkpoint de progresso, totalizando **68 commits** no histórico. Último hash/mensagem e sincronização serão conferidos após o push final; este documento não incorpora seu próprio hash para evitar reescrita.

Próxima evolução: executor Linux isolado com timeout/interrupção efetivos, identidade verificável dos ativos e um teste benigno em laboratório próprio **após autorização específica**; depois conectar o Wazuh real. Permanecem não habilitados: Lab Mode, execução Atomic, consulta Wazuh operacional no fluxo, PDF e implantação Sigma. Retenção automática, isolamento por workspace/MFA/SSO e atualização transacional do catálogo populado continuam no roadmap. Cancelamento de Demo é cooperativo e não constitui isolamento para comandos externos.

## Continuidade 2026-10-21 — runner Linux seguro

Estado inicial: main limpa/sincronizada em e0dcb3a, remoto AEGIS PRIVATE confirmado. Implementação do ADR 0003: runner opt-in separado, um teste marcador benigno, identidade/protocolo, watchdog/cancelamento/cleanup, diário idempotente e mTLS. Lab Mode da aplicação permanece desabilitado até validação autorizada e integração completa; nenhuma conexão Wazuh será iniciada.

## Marco Linux A — runner independente implementado e ensaio autorizado

Data: 2026-10-21. Primeiro incremento da etapa Linux, sem declarar Lab Mode integrado às campanhas. O usuário respondeu **“Autorizar somente esse ensaio local”** ao escopo concreto: containers novos aegis-linux-lab, rede isolated, mTLS, um marcador de 43 bytes em tmpfs, processo limitado a 5s, verificação do diário após restart e desligamento. Não houve autorização/acesso a Wazuh, rede corporativa, outros alvos ou novos tipos de teste.

### Entregas verificáveis

- `apps/api/aegis/lab_runner/protocol.py`: modelos estritos, UUIDs, marker UUID, hash, prazo, geração e allowlist exclusiva `linux-file-marker/v1`; sem comandos/caminhos/scripts de API.
- `engine.py`, `journal.py`, `marker_program.py`, `files.py`: subprocesso Python fixo com ambiente mínimo, limites Linux, sessão/grupo próprios, kill/reap, PDEATHSIG com verificação do pai, deadline monotônico de 5s e lease de 2s sem ressurreição. Intenção persistida antes do efeito; SQLite/WAL local mantém fence e identidade após restart; sem replay ambíguo.
- `server.py` e `integrations/linux_runner.py`: HTTPS/mTLS obrigatório, CAs cliente/servidor distintas, pin de IP privado/SAN, identidade/allowlist/hash/geração/recibo verificados. Sem proxies de ambiente, redirects ou entrada de URL pela aplicação. Mesmo contrato ExecutionAdapter; ainda não ligado ao worker Demo.
- Workspace privado 0700 por UUID, nomes fixos exclusivos/NOFOLLOW, conteúdo/hash conferidos e cleanup sem recursão; arquivo desconhecido/symlink/erro mantém reserva.
- `labs/linux/compose.yml` e Dockerfile: runner UID 10001, rootfs read-only, caps ALL removidas, no-new-privileges, limites de recursos, tmpfs de 1 MiB e rede internal+gateway isolated sem portas/publicação nem endereço de host no bridge. Somente secrets individuais read-only e volume próprio do diário; sem socket Docker/diretório de dados host.
- Controller CLI opt-in: preflight, marker com confirmação explícita, inspect, cleanup e retry-check restrito a job concluído/limpo. Makefile com lab-init/config/build/up/preflight/inspect/smoke/down e test-runner. Nada é iniciado pelo make up/test/CI padrão.
- Documentação de instalação, PKI local, operação/recuperação, revisão de segurança e ADR 0003. PKI/diário/recibos reais ficam locais, ignorados e fora do Git.

### Ensaio efetivamente executado

Configuração efetiva e ausência de conflito da sub-rede 172.30.88.0/29 foram verificadas antes de aplicar somente a rede nova. Docker inspect confirmou UID/read-only/caps/no-new-privileges, limites, mounts, tmpfs e gateway isolated. Sem sondagem de outros serviços.

O controller autenticou com mTLS e confirmou runner/lab/asset/allowlist. Um job criou 43 bytes, verificou conteúdo e SHA-256 e removeu os dois artefatos. Resultado do executor **SUCCEEDED**, cleanup **CLEANED**, `synthetic=false`, kind **execution_receipt**. Validação pelo domínio retornou **INCONCLUSIVE**, pois nenhum SIEM foi consultado; não inventar telemetria nem DETECTED.

Após reiniciar o runner, retry do mesmo job devolveu o recibo original inalterado. Consulta read-only do journal confirmou **um job e um único início**, e `/work` estava vazio. Finalmente `down` removeu containers e rede próprios, preservando volume do diário e configuração local. A aplicação Demo permaneceu saudável em http://localhost:18780.

Evidência local (não publicada): `.local/linux-lab/authorized-smoke.jsonl`, `restart-retry.json`, `runtime-controls.json`; volume `aegis-linux-lab_journal`. Teste não foi registrado como campanha na plataforma; não aparece artificialmente nas métricas Demo.

### Testes e revisão

| Verificação executada | Resultado observado |
|---|---|
| `make lint` | Ruff/check/format, mypy domínio, TypeScript/Prettier aprovados |
| `make test` | **131 testes Python passaram** em 39,08s; **5 frontend passaram**; aviso upstream TestClient/httpx preservado |
| Runner | 46 cenários de protocolo, comandos/caminhos recusados, arquivos, child real de pytest, TLS real loopback, mTLS recusado, concorrência, journal/fence, lease/cancelamento/deadline, restart, morte do pai com subreaper, race de handoff e isolamento |
| Docker runner | build aprovado; ensaio opt-in autorizado e inspect de runtime aprovados; imagem final reconstruída após correção de handoff |
| Cleanup do ensaio | workspace vazio, histórico intacto, containers/rede removidos; volume preservado |
| `make audit` | npm zero achados; Python mantém um advisory transitivo DiskCache conhecido/revisado, sem novo achado desconhecido |
| Links Markdown | 31 documentos verificados, sem destinos locais ausentes |

A revisão especializada somente leitura identificou race entre publicar SUCCEEDED e liberar active, que poderia recusar cleanup indevidamente. Corrigida por publicação/liberação no mesmo lock após reap e regressão com barreira determinística. Motivo de interrupção/cancelamento agora é preservado. Outro problema encontrado no primeiro up: opções tmpfs separadas pelo YAML; corrigido antes de executar o ensaio e coberto por teste/inspect. O ensaio real ocorreu antes da correção de handoff; essa correção foi validada em testes de software e a imagem final foi reconstruída, sem novo efeito real.

### Estado de publicação e próximo incremento

CI final de `a4f185a`: **SUCCESS**, [run 39602912793](https://github.com/Buraddomoon/AEGIS/actions/runs/39602912793), job em 1m53s. Lint/tipos, testes PostgreSQL/frontend, build e advisory review passaram. A rodada anterior de 11accac também passou; a última inclui a proteção de fixture para não sinalizar PID já recolhido. Commits posteriores são somente documentação e não disparam CI redundante. GitHub permanece AEGIS privado e somente main, com commits pequenos e push após cada commit. Consultar git log -1, git rev-list --count HEAD e git status -sb para hash/quantidade/sincronização do checkpoint.

Pendências reais: registrar Linux Lab/Asset/autorização/isolamento na API; ligar adapter ao worker com aprovações delimitadas e identidade mTLS, receipts imutáveis no PostgreSQL, recuperação real pós-falha e synthetic=false correto; UI e métricas separadas por modo; depois Wazuh com configuração autorizada, tradução Asset/agent e coleta defensiva real. O worker atual continua exclusivamente Demo. PKI é de desenvolvimento (folhas de 2 dias/CA de 7 dias), sem rotação automática. Journal tem quota de 10.000, sem expurgo que elimine fences. Containers não substituem VM; nenhum suporte a Atomic executável, Windows, comandos genéricos ou códigos arbitrários foi habilitado.

Este marco acrescentou **12 commits**, incluindo este checkpoint, totalizando **80 commits**. Hash/mensagem finais e main/origin/main serão conferidos após o push. Nada foi tornado público, nenhum PR/branch temporário/force push foi usado. O ensaio autorizado foi encerrado e não concede autorização para SIEM externo ou outros testes.

## Continuidade — campanhas Linux integradas

Início em main limpa/sincronizada b34c555 (80 commits). Implementação do ADR 0004: binding/admin preflight/autorização, campanha e aprovação separada, dispatch/comprovantes/cleanup persistidos, worker com quarentena real, UI/relatórios/métricas por modo. O ensaio anterior foi encerrado; não reutilizar sua autorização para Wazuh, alvos externos ou novos efeitos sem escopo específico.

## Marco Linux B — campanha integrada, comprovantes e recuperação

Data: 2026-10-21. Continuidade a partir de b34c555 (80 commits). O usuário autorizou separadamente **“Autorizar somente esse ensaio integrado”**: projeto próprio aegis-linux-lab, API loopback 18785, banco/Redis/migração/API/worker/runner próprios, acesso mTLS apenas à rede isolada do runner, um marcador de 43 bytes em tmpfs, filho limitado a 5s, aprovação separada, comprovantes/indicadores/relatórios e encerramento. A autorização não inclui Wazuh, outros alvos, novos testes ou recorrência.

### Funcionalidades entregues

- `linux_labs.py`, `services.py`, `api.py`: registro administrativo derivado exclusivamente da configuração de implantação; revisão de isolamento, binding de IDs/certificados, preflight mTLS com validade de 5 min, autorização do laboratório, allowlist exclusiva e aprovação de operação por administrador ativo diferente do solicitante ativo. Sem URL, comando ou caminho recebido da API.
- Migração `d4465b7aca2a`: LinuxLabBinding, LabVerification, RunnerDispatch, RunnerReceipt, RunnerCleanup e execution_kind. Upgrade de banco populado preserva o histórico Demo. Comprovantes/verificações são append-only; runtime só altera generation no dispatch.
- `worker.py`: mesma fila/máquina de estados e contratos; intenção confirmada no PostgreSQL antes de prepare RPC e geração antes de start. Identidade/versão/usuários/allowlist revalidados. Crash real mantém CLEANUP_FAILED/reserva; recuperar consulta/cancela/limpa o job original, sem novo prepare/start. 404 ambíguo não libera laboratório.
- `queries.py`/`reporting.py`: recibo e cleanup separados de eventos/evidência defensiva; synthetic=false preservado; relatórios HTML/JSON limitam conclusões. Sem SIEM consultado, INCONCLUSIVE. Cobertura, matriz e detalhes/histórico ATT&CK respeitam modo; overview é explicitamente Demo. Marcador não recebe técnica ATT&CK artificial.
- UI pt-BR: cadastro/revisão/preflight/autorização Linux, histórico de verificações, campanhas com testes compatíveis, confirmação de efeito real, autoaprovação bloqueada, recibos inspecionáveis, seleção de modo e relatórios corretamente identificados. Scheduler continua somente Demo.
- `labs/linux/platform.yml` e Makefile: stack integrado opt-in separado; API 18785, volume PostgreSQL próprio e diário/identidade Linux preservados. Somente API/worker recebem certificado cliente; runner sem portas/gateway host e sem Docker socket. Wazuh explicitamente vazio. Nenhum Lab é iniciado por make up/test/CI padrão.
- Versão de produto/API/pacotes alinhada em 0.2.0. README, AGENTS, arquitetura/segurança/operação/aceite atualizados e captura real Linux adicionada.

### Ensaio real efetivamente observado

O Compose foi renderizado e revisado sem expor segredos, sem conflito da sub-rede 172.30.88.0/29. Inspect confirmou UID 10001, read-only, caps removidas, no-new-privileges, tmpfs/limites, mounts individuais e gateway isolated.

Campanha única **40033401-d62d-46b9-98d3-377dbda00a00**: solicitação pelo operador e aprovação por administrador distinto; fila PostgreSQL e worker sob papel SQL restrito; mTLS real; marcador **43 bytes**; execução **COMPLETED**, recibo **execution_receipt**, cleanup **CLEANED**, synthetic=false. Classificação **INCONCLUSIVE**, com **zero eventos e zero evidências defensivas inventadas**. Relatórios HTML/JSON e separação de cobertura real/Demo verificados. Workspace do runner vazio; banco confirmou exatamente uma campanha Linux.

O comando com captura opcional inicialmente terminou com erro porque o script tentou preencher login antes do formulário aparecer. Corrigida espera por seletor; apenas o histórico foi consultado depois, com visualizador temporário, em Firefox real. Não houve repetição do marcador. A captura e assertions de UI passaram sem erros JavaScript. Não declarar que o comando original inteiro retornou exit 0: fluxo de negócio e consulta visual tiveram verificações separadas.

Admin, operador e visualizador temporários foram desativados. Laboratório revogado e sem reserva. `linux-platform-down` encerrou todos os containers/redes próprios, preservando volumes `aegis-linux-lab_journal` e `aegis-linux-lab_postgres-data`. Evidências completas locais ignoradas: `.local/linux-lab/platform-assay.json`, `platform-execution.png`. Captura revisada e sem credenciais em `docs/images/linux-execution.png`.

### Verificações finais executadas

| Verificação | Resultado observado |
|---|---|
| `make test` | **149 testes Python passaram**, 68,93s; **10 frontend passaram**; aviso upstream TestClient/httpx preservado |
| `make lint` | Ruff/check/format, mypy domínio, TypeScript e Prettier aprovados |
| Cenários Linux | aprovação segregada, confirmação, preflight expirado, usuários/binding/allowlist revogados, scheduler recusado, recibos/relatórios/métricas, crash e geração, 404 sem liberar, respostas perdidas em prepare/start/cleanup, rollback após cleanup remoto e recuperação concorrente (um sucesso/um conflito) |
| Migrações | upgrade/downgrade de schema de teste populado e alembic check aprovados |
| `make e2e` final | **PASS**, Firefox, 3 runs / 12 testes sintéticos, repetição/comparação/agendamento/grant/relatórios, cinco capturas e zero erros JS |
| Docker build | imagens API/SPA e runner construídas; imagem final Demo reconstruída e aplicada |
| `make smoke` final | **PASS**: API + SQL runtime + worker, execução manual e agendada, grant/revogação e 8 resultados sintéticos |
| Runtime Demo | http://localhost:18780 saudável, banco/Redis true; OpenAPI 0.2.0, endpoints opt-in e assets novos confirmados |
| Cleanup do ensaio | nenhum container/rede aegis-linux-lab restante; volumes preservados |
| `make audit` | npm zero; Python mantém um advisory transitivo DiskCache PYSEC-2026-2447 explicitamente revisado, sem alegar zero achados |
| Documentação | 33 Markdown verificados sem destinos locais ausentes; git diff --check aprovado |

A primeira tentativa do smoke Demo após recriar API encontrou conexão resetada durante startup. Adicionada espera limitada de health GET antes das mutações; smoke repetido apenas no Demo passou. Essa correção não executou outro teste Linux. Revisão especializada somente leitura confirmou fronteiras de autorização, dispatch antes da rede, geração, quarentena e grants; sugestões de respostas ambíguas/rollback/concorrência foram cobertas por regressões.

### Pendências e continuidade

Próxima etapa: ligar coleta defensiva Wazuh ao fluxo Linux por configuração/autorização próprias, mapeamento Asset/agent, instrumentação que preserve o marcador, consulta com janela de ingestão e fixtures adicionais; somente depois validar um ciclo defensivo real. Nenhum Wazuh externo foi acessado nesta entrega. PKI é de desenvolvimento e expira em poucos dias; rotação/binding original após quarentena requer procedimento manual, não bypass. Sem Windows real, Atomic executável, scheduler Linux, PDF, implantação Sigma, MFA/SSO, multi-tenant ou expurgo automático de fences. Não ampliar allowlist nem repetir ensaio sem autorização específica.

Este marco acrescenta **21 commits granulares**, incluindo este checkpoint, totalizando **101**. GitHub AEGIS confirmado **PRIVATE**, somente main, sem PR/branch temporário/force push; push após cada commit. Consultar git log -1 e git status -sb para hash/mensagem/sincronização após o checkpoint. O último commit de código é 8d7a38b; commits seguintes são documentação/capturas.

CI remota do último código **8d7a38b: SUCCESS**, [run 39615555686](https://github.com/Buraddomoon/AEGIS/actions/runs/39615555686). Lint/tipos, PostgreSQL/frontend/build e revisão de advisories passaram. Commits posteriores contêm somente documentação/capturas e não iniciam execução redundante. Repositório confirmado privado; sincronização e hash do checkpoint conferidos após push.

## Continuidade — preparação da coleta Wazuh

Início em main limpa/sincronizada b8c9b0e (101 commits). Usuário confirmou: **“Ainda não tenho Wazuh; preparar integração sem instalar”**. Implementar ADR 0005, binding explícito de agente/regra/configuração, consulta limitada com polling, resumo de coleta imutável e UI/relatórios proporcionais. Sem instalar/iniciar Wazuh ou repetir ensaios Linux; testes locais e fixtures não serão apresentados como evidência externa.

## Marco Wazuh A — coleta preparada e validada localmente, sem instalação

Data: 2026-10-21. Continuidade de b8c9b0e (101 commits). O usuário confirmou **“Ainda não tenho Wazuh; preparar integração sem instalar”** e pediu continuidade. Nenhum Wazuh foi instalado/iniciado/consultado; nenhum novo ensaio Docker Linux foi realizado. Testes usaram somente fixtures descartáveis, PostgreSQL/Redis existentes e HTTPS próprio em loopback. O Demo padrão foi atualizado sem acessar alvos externos.

### Entregas e decisões

- ADR 0005 e `integrations/wazuh_config.py`: política opt-in tipada, sem credenciais, fixa laboratório/ativo, agent.id externo, regra, índices, schema/prefixo, janela e limites. Configuração de destino/credenciais/CA permanece na implantação; API não recebe URL/query/comando/segredo.
- Migração **4b72c7bb8548**: WazuhBinding relaciona namespaces explícitos, com identidade única e revisão administrativa; TelemetryCollection é resumo append-only por execução. Grants runtime recusam UPDATE/DELETE no resumo.
- `telemetry.py`, API, services e worker: binding exige administrador, confirmação, Linux Lab revogado/sem reserva; versão de ambiente e scope/hash incluem configuração pública aprovada. Mudança de mapping/regra/destino/CA/principal/janelas invalida aprovação. Identidade duplicada retorna 409 com rollback, sem alterar versão. Remover vínculo preserva escopos/auditoria históricos.
- `integrations/wazuh.py`: Indexer Search/Scroll somente leitura, IP fixado, TLS/SNI/CA validados, sem proxy/redirect. Mapping exige agent.id externo exato, inclusive recusando agente cujo valor coincida com UUID interno. Campos ausentes/errados não são inventados. IDs/índice/payload originais preservados.
- `wazuh_polling.py`: espera de ingestão cobrindo janela temporal, até 64 rodadas, páginas/documentos/bytes limitados, deduplicação e rejeição de conflito por source/id, guards de cancelamento e reserva de tempo para cleanup. AsyncClient/asyncio.Runner privados e asyncio.timeout limitam request inteiro (conexão/TLS/headers/corpo); sem threads abandonadas. Compressão recusada; clear de cursor conhecido é tentativa limitada, com expiração como fallback.
- Correlação **1.1**: alerta da regra esperada só confirma DETECTED com execução e identidade/marcador/comportamento/tempo correlacionados. Alerta de outra regra correlacionado é observação, sem afirmar regra esperada; sem regra definida, conclusão é inconclusiva. Worker recusa lógica diferente da aprovada, sem executar silenciosamente versão nova. Negativos exigem consulta final completa/janela cumprida; falha/403/índice ausente/shards zero/timeout/truncamento/orçamento insuficiente não viram falha defensiva confirmada.
- UI mostra política pública, revisão, agent/regra/hash, estado não verificado e resumo da coleta. Relatórios distinguem SIEM não consultado de consulta tentada, janela, disponibilidade e evidências; recibos/cleanup continuam separados de alertas. Não há badge falso de integração Wazuh externa validada.
- `marker_observer.py`: observação passiva de arquivo físico, sem criar/apagar/executar teste. Verifica arquivo regular/nlink/43 bytes/UUID/hash, recusa links/FIFO/conteúdo inválido, opera em workspace privado e emite UUID canônico a partir do nome físico UUID.hex. Não inicia automaticamente.
- `labs/wazuh/`: política com IDs fictícios, XML localfile/regra de pipeline e guia de preparação. `infra/compose.wazuh.example.yml` apenas exemplifica mounts na aplicação; não instala nem inicia SIEM. Arquivos estruturais foram validados, mas **não houve wazuh-logtest nem execução do rules engine real**. Compartilhamento read-only do workspace/log/agente ainda é trabalho de implantação futura autorizada.

### Testes efetivamente executados

| Check | Resultado observado |
|---|---|
| `make test` final | **208 Python passaram**, 95,13s; **14 frontend passaram**; aviso upstream TestClient/httpx preservado |
| `make lint` | Ruff/check/format, mypy do domínio, TypeScript e Prettier aprovados |
| Contrato Indexer | 36 cenários de política/schema/identidades/shards/índices/falhas/polling/cancelamento/deadlines, sem Wazuh externo |
| Campanhas com fixture HTTP | 10 cenários de worker/PostgreSQL/runner de teste, classificações, binding/revogação/confirmação/RBAC, lógica antiga recusada e conflito de agente com rollback |
| TLS real loopback | Transporte HTTPX padrão aceita CA/SNI corretos e recusa CA/hostname incorretos; não usa verify=false |
| Observer | 10 cenários com Workspace real, sem subprocesso do observer, links/hardlinks/FIFO/paths/conteúdo inválidos recusados |
| `make e2e` | **PASS**, Firefox, 3 runs / 12 testes sintéticos, repetição/comparação/agendamento/grant/relatórios, 6 capturas e zero erros JavaScript |
| Docker Demo | build final aplicado; API/SPA atualizadas e health ready DB/Redis confirmado em http://localhost:18780 |
| `make smoke` | **PASS**, papel SQL runtime restrito (incluindo novos resumos imutáveis), worker, manual/agendado, grant/revogação e 8 resultados sintéticos |
| Estado do runtime | sem WAZUH_URL/política/vínculo/coleta externa; zero registros Wazuh no banco operacional; nenhum container Linux Lab iniciado |
| Exemplos | JSON Pydantic, XML estrutural e render do overlay app-only aprovados, sem up do overlay Wazuh |
| `make audit` | npm zero; Python mantém DiskCache PYSEC-2026-2447 transitivo revisado, sem novo achado desconhecido e sem alegar zero vulnerabilidades |

Os DETECTED nos testes Wazuh são resultados do contrato em schemas descartáveis com documentos fictícios, não evidências defensivas de ambiente real. A captura `docs/images/wazuh-preparation.png` vem do aplicativo em Firefox e mostra **Desconectado**, sem Wazuh. O histórico Linux da etapa anterior permanece intacto; não se fabricou um novo ciclo real para esta preparação.

### Problemas encontrados e corrigidos

Revisão especializada somente leitura apontou fallback de agent.id para UUID interno (falso positivo), buffering/timeout por fase (slow response prolongaria prazo) e incompatibilidade UUID com hífens versus UUID.hex do runner. Corrigidos e cobertos por regressões: namespace estrito, timeout async integral/streaming limitado e fixture usando Workspace real. O teste TLS real também revelou SNI bytes incompatível com AnyIO; corrigido para string conforme API oficial, sem enfraquecer certificados. Escopos usam LOGIC_VERSION e rejeitam aprovação antiga. Tipagem do estado vazio da UI e import de fixture foram ajustados antes da rodada final; checks não foram declarados aprovados enquanto falhavam.

### Pendências reais e próxima etapa

A preparação de software está concluída neste escopo. Para fechar validação externa: Wazuh próprio/isolado, versão/schema/CA/conta read-only e agent.id reais; acesso passivo ao workspace físico e logfile/rotação revisados; instalar regras manualmente só após checar ID/validar com wazuh-logtest; confirmar ingestão/archives/relógios e executar um ciclo específico autorizado. O usuário ainda não possui essa infraestrutura e **não autorizou instalação**. Não buscar alvos presumidos nem repetir laboratório/efeito para contornar isso. A regra de exemplo só verifica pipeline de marcador benigno, sem cobertura ATT&CK artificial ou proteção empresarial.

Persistem limitações anteriores de PKI de desenvolvimento, rotação/recuperação de binding, retenção/fences, Windows, Atomic executável, scheduler Linux, Sigma deployment, PDF e isolamento multi-tenant. Nenhuma nova dependência, serviço pago, PR, branch temporário, force push ou reescrita de histórico.

Este marco acrescenta **18 commits granulares**, incluindo este checkpoint, totalizando **119 commits**. Último código/configuração: **8eb1103**; commits posteriores são documentação/capturas. GitHub AEGIS permanece privado e exclusivamente main; commit/push foram feitos por unidade verificável. Conferir git log -1 e git status -sb após o checkpoint para hash/mensagem/sincronização finais.

CI remota do último código/configuração **8eb1103: SUCCESS**, [run 39645394721](https://github.com/Buraddomoon/AEGIS/actions/runs/39645394721). Instalação dos locks, lint/tipos, PostgreSQL/frontend/build e revisão de advisories passaram. Os commits seguintes são documentação/capturas e não disparam testes remotos redundantes. Foram verificados 36 Markdown sem destinos locais ausentes. Hash/sincronização final serão conferidos após push deste checkpoint.

## Marco Wazuh B — ensaio isolado preparado; início condicionado à RAM

Data: 2026-10-21. Continuidade de **c1c3ce1**, 119 commits, main limpa/sincronizada.
O usuário pediu priorizar a pendência real de Wazuh. A preparação desta etapa não
instalou nem iniciou SIEM, não repetiu o Linux Lab e não executou outro marcador
real. Testes locais usam fixtures/schemas/arquivos descartáveis; seus resultados
não são evidência defensiva Wazuh.

### Autorização específica e bloqueio atual

Após apresentar os artefatos concretos em `labs/wazuh/ASSAY.md`, o usuário respondeu
**“Autorizar somente esse ensaio quando o preflight passar”**. Autoriza somente o
projeto próprio aegis-wazuh-lab, imagens oficiais Wazuh4.14.9 fixadas por digest,
builds próprios, API localhost18786, TLS/regra/agente, um marcador43bytes/filho5s/
campanha120s, aprovação segregada, evidências/cleanup e encerramento preservando
volumes. **Não pedir a mesma autorização novamente**; não ampliar alvos, repetir
efeitos ou parar outros projetos. Isso sucede o pedido anterior sem instalar
somente dentro desse escopo delimitado.

Preflight final observado: **16 CPUs**, **5.285.867.520 bytes MemAvailable
(4,92 GiB)**, **440.968.421.376 bytes livres no filesystem Docker**,
**vm.max_map_count=1048576**. O gate exige 4 CPUs/8 GiB disponíveis/50 GiB livres/
map_count262144. **RAM insuficiente, exit1 esperado; início/download bloqueados.**
Swap não conta como RAM disponível. Não alterar sysctl/swap/cache nem parar
serviços de outros projetos para contornar esse limite. A autorização não elimina
o gate. Não houve recusa de aprovação automática: o bloqueio é o recurso medido.

### Implementado e verificável

- ADR0006, `labs/wazuh/compose.yml`, `config/*`, `images.json`: projeto separado,
  imagens manager/Indexer/agente4.14.9 oficiais linux/amd64 fixadas por digest.
  Consultados documentos oficiais e manifests do registro, **sem baixar camadas**.
  Runner/observer usam imagem própria separada; API/worker/migração também. Sem
  novos pacotes/dependências ou serviço pago. GPLv2 manager/agente e Apache2.0
  Indexer documentados separadamente da licença MIT do código AEGIS.
- Redes runner172.30.89.0/29 e telemetria172.30.90.0/29 internas/isolated; runner
  não integra rede SIEM, observer sem rede, agente só lê logfileRO. Somente API
  loopback18786; nenhum endpoint SIEM publicado. Sem host network/socketDocker ou
  diretórios do host. Backend/ingress seguem a plataforma, sem afirmar isolamento
  físico total do host. Teto agregado de containers7.03GiB, incluindo migração.
- Workspace tmpfs1MiB UID10001/0700/noexec/nosuid/nodev compartilhado runnerRW/
  observerRO. Imagem prepara `/observation-log`10001/0700 para copy-up do volume.
  Permissões/opções efetivas **ainda precisam de inspeção no runtime**.
- `marker_log.py`: JSONL dedicado1MiB, arquivo0600, flock de único escritor, fsync
  do arquivo/diretório, retomada/dedupe; conflito de marcador/hash da mesma execução,
  linha parcial, outro escopo, links/FIFO/permissões inseguras recusados. Sem
  rotação/truncamento destrutivos. ObserverCLI aceita sink opt-in, continua sem
  executar/criar/remover marcador nem atribuir rule.id/detecção.
- `prepare_wazuh_lab.py`: identidades novas, PKI própria com SANs novos, senhas
  aleatórias, agent001 pré-provisionado somente nesse manager, política60s/poll2s/
  request3s. Recusa sobrescrever identidades; dados locais em `.local/wazuh-lab`
  ignorados e0700, senhas/env0600. Essa preparação não chama Docker nem instala
  serviços. Agente precisa ser confirmado Active antes de aprovar o efeito.
- Roles reader/ingest/admin separados; aplicação recebe somente leitura dos
  índices de alertas, sem chave de ingestão/admin. Manager recebe conta própria.
  TLS verificado; gestão API configurada no loopback interno, módulos desnecessários
  desativados, sem archives no primeiro ensaio. Bootstrap/permissões reais ainda
  pendentes de teste na imagem, incluindo rotação/desativação de defaults internos.
- `wazuh_host_preflight.py` e `wazuh_lab.py`: verificações somente leitura,
  daemon Unix local explícito, sanitização de contexto/plataforma/variáveis para
  shell não sobrescrever lab.env. Lifecycle pull/hash/build/up opt-in sob gate;
  hash por ferramenta oficial isolada, segredo somente stdin; check-rule futuro
  usa sandbox sintético, não evidência; status/config/down não dependem de RAM,
  down preserva volumes. Colisão de rede/porta/certificado expirado bloqueia início.
  Scripts de lifecycle **não executam marcador**.
- Makefile, AGENTS, README, changelog, roadmap, integração e testes documentam
  escopo/autorização/limites atuais. `make up/test/CI` não inicia Wazuh ou Lab.

### Verificações efetivamente executadas

| Check | Resultado observado |
|---|---|
| `make test` | **244 Python passaram**,90.93s; **14 frontend passaram**; aviso upstream TestClient/httpx preservado |
| `make lint` | Ruff/check/format81arquivos, mypy domínio, TypeScript e Prettier passaram |
| `make test-wazuh-preparation` | **46 passaram**; host gate, PKI/DN/SAN, config privada, render Compose, lifecycle simulado e log/observer reais em filesystem descartável |
| `make wazuh-lab-config` | Compose real renderizado/validado, sem up e sem imprimir credenciais |
| PKI | OpenSSL verify real para novos IPs, teste de DN RFC2253; CA/key não publicados |
| Limites do log | restart/dedupe, conflito append/restart, escritor concorrente, links/hardlinks/FIFO, partial line, capacidade e preservação verificados |
| Guardas lifecycle | falta confirmação/recursos não chega ao Docker mutável; shutdown sem gate/-v/prune; segredo não aparece em argv; contexto externo não substitui destino |
| Estado Docker | nenhum container/rede aegis-wazuh-lab; nenhum container aegis-linux-lab; nenhuma imagem wazuh/* baixada |
| Demo existente | http://localhost:18780 pronto, database=true e redis=true; histórico e serviços de outros projetos preservados |
| Documentos | 42 Markdown verificados sem destinos locais ausentes; git diff --check aprovado |

Teste de hash usa resultado simulado e **não valida a ferramenta Java/BCrypt da
imagem oficial**. Render/config não valida os entrypoints ou engine Wazuh. Sem
rebuild da aplicação Demo, alteração de UI ou nova rodada E2E: o código alterado
é de implantação/CLI/observação; os resultados E2E anteriores permanecem históricos.
Não repetir checks sem mudança/falha que justifique. Não houve nova dependência;
advisory transitivo DiskCache previamente revisado continua documentado.

### Revisão e correções

Revisão especializada somente leitura encontrou DN de certificado em ordem
incompatível com nodes_dn e dedupe silencioso de marcadores conflitantes. Ambos
corrigidos com regressões executadas, além de fsync do diretório e sanitização
compartilhada do daemon/DOCKER_DEFAULT_PLATFORM. Revisão final confirmou correções
e não apontou outro bloqueador concreto estático. Isso não substitui runtime.
A primeira coleta do teste de preflight teve import de scripts fora do pacote;
corrigida carga do arquivo de ferramenta, sem alterar sys.path da aplicação.

### Próxima ação, sem repetir trabalho

Quando houver **8GiB MemAvailable** e demais condições, executar o ensaio **já
autorizado** de ASSAY.md: pull/hash/build/up, inspeção efetiva, wazuh-logtest,
agenteActive/ingestão/TLS/leitura e negativa de escrita, cadastro/binding/preflight,
uma campanha com um marcador e aprovação separada, documento original/evidências,
relatórios/cleanup, revogação e encerramento. Não recriar identidade/journal para
apagar ambiguidade nem repetir efeito por falha de screenshot. Se faltarem recursos,
preservar esta preparação e informar o bloqueio sem afirmar Wazuh validado.

Persistem as limitações anteriores de Windows, Atomic executável, scheduler Linux,
retenção/fences, rotação operacional de PKI, Sigma deployment, PDF e multi-tenant.

Este marco acrescenta **11 commits granulares**, incluindo este checkpoint,
totalizando **130 commits**. Somente main, GitHub AEGIS privado, push após cada
commit, sem branch/PR/force ou reescrita. Último código **6e6464b**; CI
[run39658915452](https://github.com/Buraddomoon/AEGIS/actions/runs/39658915452)
**SUCCESS**, efetivamente consultada após conclusão: lint/tipos, testes PostgreSQL/
frontend/build e revisão de advisories passaram. Commits seguintes contêm somente
documentação e não iniciam validação redundante. Conferir git log -1 e git status
-sb após o checkpoint para hash/mensagem/sincronização finais.


## 2026-10-22 — Continuidade Wazuh: inspeção de isolamento antes do ensaio

O usuário pediu seguir para o próximo passo. A autorização de ASSAY.md persiste
sem nova pergunta, condicionada ao preflight. Às **12:40 UTC**, a medição somente
leitura encontrou **16 CPUs, 7.678.832.640 bytes (7,15 GiB) MemAvailable,
440.305.610.752 bytes livres no filesystem Docker e vm.max_map_count=1048576**.
O piso de 8 GiB disponíveis ainda falha; não baixar/construir/iniciar o stack nem
parar outros serviços, alterar swap/sysctl/cache para contornar essa condição.
Após a suíte completa, nova medição encontrou **7.288.549.376 bytes (6,79 GiB)**
disponíveis; gate continuou recusando início. MemAvailable varia durante a sessão.
Nenhuma imagem wazuh/* ou container do projeto foi encontrado. Não houve novo
marcador, consulta SIEM, evidência defensiva ou alteração dos ensaios anteriores.

### Unidade entregue e decisões

- `scripts/inspect_wazuh_lab.py` e `make wazuh-lab-inspect`: somente ps/ls/inspect
  no daemon Unix local, filtrando o projeto aegis-wazuh-lab; não executa dentro de
  containers nem recebe destino/comando livre. Ausência/divergência retorna exit1.
- Compara com allowlist explícita independente do Compose: todos os serviços e
  somente eles, migração concluída, saúde disponível, memórias/CPU/PIDs, namespaces,
  usuários/read-only/capabilities/no-new-privileges, portas solicitadas/efetivas,
  redes/IPs/membros, volumes do projeto e mounts/source/RO/RW, workspace tmpfs com
  opções revisadas e referências Wazuh fixadas por digest. Recusa dispositivos
  adicionais, namespaces host, sockets/mounts extras e volumes remotos.
- Saída só contém nomes conhecidos de checks e booleans. Template não solicita
  Config.Env; falhas não imprimem comando, daemon response, paths ou valores
  privados. Coleta não depende de memória disponível, para poder diagnosticar o
  projeto após seu início autorizado ou quando estiver com poucos recursos.
- Integração no Makefile, ADR0006, AGENTS, changelog, runbook e documentação de
  testes. Cabeçalho deste progresso corrigido para refletir a autorização atual.
- Esse check cobre **metadados Docker**, não a configuração/conteúdo dentro dos
  containers, opções efetivas do kernel, mTLS, ACL, rule engine ou ingestão.
  Completar esses passos do checklist continua obrigatório antes do único efeito.
  Não criar novos guardas como substituto indefinido do ensaio pendente.

### Verificações efetivamente executadas

| Check | Resultado observado |
|---|---|
| `make test-wazuh-preparation` | **97 passaram**, 0,70s, sem novos serviços; inclui 51 testes do novo verificador |
| Projeções Docker reais | Quatro regressões somente leitura em objetos Demo já existentes: worker sem Health, db sem Tmpfs, rede e volume; todas passaram, sem restart/exec |
| `make lint` | Ruff/check/format83arquivos, mypy domínio, TypeScript e Prettier passaram |
| Regressão do polling | Falhou antes com sleep=-0,1s; 47 testes de coleta/campanhas passaram após correção, 20,70s |
| `make test` após correção | **296 Python passaram**,92,66s; **14 frontend passaram**,sem falha |
| CI c61000b | **SUCCESS**,run39780994246; lint/tipos, PostgreSQL/frontend/build e revisão de dependências passaram |
| `make wazuh-lab-config` | Compose renderizado/validado sem iniciar e sem imprimir segredos |
| `make wazuh-lab-inspect` | Recusa esperada: projeto não iniciado, inspection_completed=false/isolation_verified=false; nenhum efeito |
| `make wazuh-lab-preflight` | Recusa esperada por RAM disponível; outros pisos aprovados |
| Demo existente | localhost:18780/api/v1/health/ready: ready, database=true, redis=true |
| Git | Scanner staged, inspeção dos arquivos e diff --check aprovados antes de cada commit; nenhum dado .local/.env/PKI incluído |

Os snapshots de testes são fictícios, não resultados Wazuh. Quatro testes de
projeção somente leitura usam objetos próprios Demo existentes e pulam quando
estes estiverem ausentes na CI; não criam infraestrutura. O aviso upstream
Starlette TestClient/httpx permanece. Sem nova dependência, rebuild do Demo ou
rodada E2E. A suíte completa local foi repetida após a mudança no backend e passou.

### Revisão especializada e correções

Revisão somente leitura reproduziu dois problemas: dot lookup em campos opcionais
Docker falhava quando Health/Tmpfs estavam ausentes e DeviceCgroupRules não era
inspecionado. Corrigidos com index/with e recusa de grants adicionais de
dispositivos. Regressões executadas, inclusive templates no Docker29 real.
Revisor confirmou ambos resolvidos no commit7727862, sem outro bloqueador concreto.
Isso não equivale à validação do runtime Wazuh.

A CI do código c39708f encontrou uma falha no teste de contrato NO_TELEMETRY:
retornava INCONCLUSIVE. Investigação reproduziu deterministicamente a causa na
espera de polling: guard de autorização/ownership PostgreSQL podia consumir uma
fatia de espera e o cálculo posterior passar um valor negativo a sleep. ValueError
era capturado como falha de configuração/coleta. `wazuh_polling.py` agora recalcula
o restante após guard e dorme somente se positivo. O teste novo falhou antes e
passou após a mudança; coleção/campanhas completas passaram. Revisão especializada
confirmou preservados janela, deadline, reserva de cleanup, cancelamento, fechamento
do provider e critérios de classificação. Sem alterar LOGIC_VERSION1.1 ou evidências
históricas: corrige espera operacional, sem mudar regras aprovadas/correlação.

### Continuidade e versionamento

Próximo passo continua sendo o único ensaio real **já autorizado**, quando houver
8 GiB MemAvailable e os demais pisos passarem: imagens/hash/build/up, inspeção de
runtime e interna, readiness/TLS/ACL/agente/regra, uma campanha/execução/marcador,
evidências originais e cleanup/revogação/encerramento preservando volumes.
Não repetir autorização ou efeito ambíguo. Certificados atuais expiram em
**2026-10-23 18:57:22 UTC**: verificar validade antes de iniciar; não recriar
identidades/journals ou apagar evidências para contornar estados ambíguos.

Este marco tem **6 commits**, incluindo este checkpoint, totalizando **136**.
Somente main e repositório AEGIS privado, push após cada commit. Último commit de
código: **c61000b**. A CI posterior à correção
[run39780994246](https://github.com/Buraddomoon/AEGIS/actions/runs/39780994246)
concluiu **SUCCESS**, consultada após finalizar: lint/tipos, testes PostgreSQL/
frontend/build e revisão de dependências passaram. Não confundir com
run39780201407 que falhou antes da correção. Este checkpoint muda só documentação
e não dispara validação redundante. Os runs intermediários são cancelados pela
concurrency existente. Consultar git log -1/status -sb para hash e sync finais.


## 2026-10-22 — Ensaio Wazuh autorizado em preparação de runtime

O usuário encerrou o Firefox e pediu prosseguir. Às 13:13 UTC, o preflight real
passou: 16 CPUs, 9.426.079.744 bytes (8,78 GiB) MemAvailable, 440.363.372.544 bytes
livres no filesystem Docker e vm.max_map_count1048576. Redes revistas/porta18786
livres, certificados válidos até 2026-10-23 18:57:22 UTC, main limpa/remoto privado.
A condição da autorização foi satisfeita sem parar outros projetos ou alterar
swap/sysctl/cache. Iniciado somente o download das três imagens oficiais4.14.9
fixadas por digest de images.json; Indexer amd64 já conferido. Nenhum marcador
ou campanha Wazuh iniciado neste checkpoint. Bootstrap/readiness e ensaio seguem
pendentes; os próximos registros devem trazer somente resultados observados.

Revisão especializada somente leitura contra entrypoints oficiais v4.14.9 confirmou
caminhos de cópia dos arquivos manager/agente, parametrização Filebeat fullTLS e
bootstrap que altera wazuh e randomiza wazuh-wui. Não usar certificados admin demo
embutidos. Isso é inspeção de fonte, não validação de credenciais, regra ou ingestão.


## 2026-10-22 — Marco Wazuh B: pipeline real validado e encerrado

### Resultado e escopo efetivamente executado

Após o usuário encerrar o Firefox e pedir prosseguir, o preflight passou às
13:13 UTC com 16 CPUs, 8,78 GiB disponíveis, 410 GiB livres e vm.max_map_count=1048576. Foi usado
somente o projeto aegis-wazuh-lab autorizado, imagens oficiais 4.14.9 linux/amd64
fixadas por digest, builds próprios, novos banco/identidades/PKI, API loopback:18786,
SIEM sem portas publicadas, runner em rede isolada e observador sem rede.
Não foi parado outro projeto ou alterado sysctl/swap/cache. O Demo permaneceu pronto.

**Campanha única:** `987bd48f-fafc-4a34-bf2a-2d310e7ca794`.
**Execução:** `a54831d6-5517-4a15-b0c8-adc9faee97d8`.
Resultado observado **COMPLETED / DETECTED / CLEANED**, `synthetic=false`.
Intenção de start persistida às 13:29:53UTC, resultado capturado às 13:30:05UTC.
Um único teste linux-file-marker-v1; um marcador de 43 bytes, filho limitado a 5s,
operador solicitante e administrador distinto, aprovação consumida de 120s.
Não houve replay do efeito, agendamento, ATT&CK artificial, credenciais coletadas
ou alvos empresariais/externos.

Fluxo real: arquivo → observador passivo → logfile 0600 → agente 001/aegis-marker →
manager/regra 100200 → Filebeat TLS → Indexer → worker/correlação → evento/evidência
no PostgreSQL → relatório HTML/JSON. Alerta original preservado:
`wazuh-alerts-4.x-2026.10.22 / H5fNY6EB3Gh75NYK5xtJ`.

### Verificações reais e encerramento

- 163 checks Docker passaram. Conferidos dentro dos containers: tmpfs 1MiB
  noexec/nosuid/nodev, UID10001/0700, runnerRW/observerRO, log 0600 inicialmente
  vazio, agente root/logcollector somente no logfile RO; nenhum socketDocker.
- Regra100200 validada no wazuh-logtest com JSON sintético somente no sandbox,
  sem inseri-lo no Indexer. Agente001 Active conferido. ManagerAPI somente em
  127.0.0.1 interno; SQLiteRO/hashverify confirmou defaults wazuh/wazuh-wui
  rejeitados e senha configurada de wazuh correspondente, sem expor hashes/senhas.
- Reader autenticou com CA/SNI/IP fixado, Filebeat testoutput verificou TLS 1.3,
  Search/Scroll/Clear passaram. Reader recebeu 403 para create-index e para acesso
  ao índice de segurança. Ingest bulk fora dos índices de alertas recebeu HTTP200
  com item403: status do item conferido, não somente HTTP. Probe usou índice vazio
  e delete de ID inexistente; nenhum documento de teste inserido, índice removido.
- Um evento e uma evidência persistidos, correlacionados à execução/laboratório/
  ativo/marcador/comportamento/tempo/regra 100200. Hash do evento, recibo e cleanup
  conferidos. Única linha do observador preservada e comparada ao full_log e hash
  dos 43 bytes, independentemente do receipt. Não foi convertido recibo em alerta.
- Coleta: seis tentativas, completa/alerts_available=true, archives não configurado
  (telemetry_available=false), window_satisfied=false. Alerta positivo exato
  permite conclusão antes do horizonte; não tirar conclusão negativa dessa janela.
- Conferidos estado CLEANED e workspace fisicamente vazio, uma campanha/execução/
  evento/evidência no banco, aprovação segregada usada por 120s, coleção append-only,
  laboratório revogado/sem reserva e duas contas temporárias inativas.
- Containers e quatro redes do projeto encerrados; nove volumes, diário/fences e
  evidências preservados. Senhas temporárias das duas contas removidas após
  confirmação, sem remover segredos de implantação necessários aos volumes.
  Nenhuma imagem/volume foi apagada por prune/down-v. Às 13:41UTC, 9,23 GiB de RAM
  estavam disponíveis; Demo localhost:18780 pronto com DB/Redis true.

**A autorização de um único ensaio foi consumida.** Não iniciar novamente o stack,
repetir marcador ou apagar intent/journal para contornar replay. Nova execução
real exige novo escopo específico. Leitura dos arquivos/testes offline não
reexecutam o efeito nem consultam serviços externos.

### Código, problemas encontrados e evidências

- `smoke_wazuh_platform.py`: harness opt-in, intent O_EXCL append/fsync antes de
  mutações e START_INTENT antes do único POSTstart. Recusa histórico prévio, sem
  retry de resposta ambígua; contas aleatórias no container owner/migrate via
  stdin, API/worker sem credencial owner/admin Indexer. Captura antes de avaliar,
  revoga lab/desativa contas/remove senhas temporárias ao confirmar encerramento.
  CLEANUP_FAILED/ambiguidade preservam acesso para recuperação original.
- Runtime encontrou 403 por falta de bulk no nível cluster do perfil ingest.
  Corrigido em roles.yml mantendo index_patterns dos alertas e reader inalterado;
  RESTSecurity habilitada só para aegis_admin. Perfil aplicado viaREST local Indexer
  com senha somente stdin. Não usar certificados admin demo da imagem. ACLs
  negativas reais confirmaram separação; templates/pipelines globais de bootstrap
  do ingest continuam explicitamente documentados, sem alegação de isolamento
  administrativo total por índice.
- Consultas de diagnóstico iniciais usaram scroll size0 e HEAD com curl inadequados;
  corrigidas para size1/GET antes do efeito, sem afrouxar TLS/permissões. Config
  mínima do manager gerou avisos por listas CDB omitidas: não foi avaliada cobertura
  do ruleset padrão, só a regra de instrumentação100200.
- [Alerta, observação, resumo e hashes](evidence/wazuh-2026-10-22/README.md) publicados
  após revisão contra senhas de implantação/client.keys e chave privada. IDs/IPs
  são somente desse lab próprio. Resumo curado sem credenciais ou chave de
  idempotência; originais HTML/JSON completos permanecem em `.local/wazuh-lab`.
  Hashes conferem integridade, não assinatura/autenticidade do operador.
- README, AGENTS, ADR0006, guias de laboratório/integração/testes, roadmap, aceite e
  changelog atualizados. A captura Wazuh anterior continua identificada como Demo
  sem conector; não inventar screenshot ou inserir o ensaio no banco Demo.

### Verificações automatizadas executadas

| Check | Resultado observado |
|---|---|
| `make test` | **311 Python passaram**,84,33s; **14 frontend passaram** |
| `make lint` | Ruff/check/format de 86 arquivos, mypy domínio, TypeScript e Prettier passaram |
| `make test-wazuh-preparation` | **106 passaram**,0,93s; fixtures/arquivos/projeçõesreadonly, sem novo marcador |
| Harness de uso único | **8 passaram**, incluindo start durável, resposta ambígua sem retry/acesso retido, recusa de histórico e remoção de credencial após desativação |
| Artefatos gravados | **6 passaram**, hashes byte/canônico, normalização do schema real e recusa de agente/regra alterados; offline, não nova validação externa |
| Preparação corrigida | **8 passaram**, incluindo separação reader/ingest/admin e render Compose |
| Documentos | 11 Markdown/42 links locais verificados, sem destinos ausentes; scanner staged/diff-check por commit |
| CI | **SUCCESS**, código 42d3d1d, [run39788294808](https://github.com/Buraddomoon/AEGIS/actions/runs/39788294808), consultada após concluir; lint/tipos/PostgreSQL/frontend/build/advisories aprovados |

Aviso upstream TestClient/httpx e advisory transitivo DiskCache previamente
revisado permanecem; sem dependências novas ou recurso pago. Não houve nova rodada
E2E de navegador, screenshot Wazuh ou rebuild do Demo. Revisões especializadas
somente leitura confirmaram configuração oficial, escopo bulk, método seguro de
verificar defaults e ausência de bloqueador no harness. Nenhum agente executou
marcador ou serviços em paralelo.

### Limitações e próximo passo

O resultado confirma **somente o pipeline da regra própria de marcador** em
Wazuh 4.14.9/schema aegis-json/1/Linux. Um teste válido e zero técnicas ATT&CK
avaliadas; não demonstra eficácia de EDR, detecção padrão Wazuh ou proteção
empresarial. Windows, archives, outras versões, regras operacionais, retenção e
restore/rotação de PKI continuam pendentes. Os volumes guardam histórico, não uma
implantação SIEM mantida em execução. Não anunciar integração universal pronta.

Próxima etapa de software recomendada: associação operacional entre regras e
testes e análise comparativa de cobertura baseada nas evidências existentes,
sem novos efeitos reais. Mantêm-se limites anteriores de Sigma deployment, PDF,
workspace único e scheduler somente Demo.

Este marco acrescenta **7 commits granulares**, incluindo este checkpoint,
totalizando **143**. Somente main, AEGIS privado, push após cada commit, sem
branch/PR/force. Último código/testes 42d3d1d; CI verde acima. Commits seguintes são
só documentação e não disparam validação redundante. Conferir log/status após
este checkpoint para hash/mensagem/sincronização finais.

## 2026-10-22 — Revisões Sigma/teste e comparação histórica de escopos

### Entrega e decisões

Associações entre regras e testes agora são metadados reais, persistentes e
revisados na API/UI. Não são regras implantadas e não participam da correlação,
do expected_rule, das classificações ou dos denominadores de cobertura.

- [ADR0007](architecture/decisions/0007-rule-test-review.md): RuleTestLink fixa
  RuleVersion/hash, versão do teste, justificativa e autor. Um vínculo ativo por
  par, FK composta versão/regra, substituição otimista e lock compartilhado com
  importação Sigma. Migrações explícitas ec3020ae8711/977fd0c42ae8.
- Retirada preserva histórico; trigger PostgreSQL impede reescrita, reativação e
  exclusão. Papel runtime tem somente INSERT/SELECT e UPDATE das duas colunas de
  retirada. Administrador do banco continua privilegiado; hash não é assinatura.
- GET paginado /rule-test-links e POST/DELETE /rules/{id}/test-links, com
  RBAC/CSRF e auditoria. Viewer consulta; operador/admin registra revisão.
  Hash/versão/replaces_id obsoletos retornam conflito, sem sobrescrever revisão.
- UI permite examinar YAML, confirmar payload exato, associar, revisar, retirar
  e consultar histórico. Nova versão sinaliza revisão necessária. Matriz separa
  vínculos planejados de regras operacionais e cobertura observada.
- Solicitações e planos novos capturam vínculos relevantes no scope/hash.
  Mudança relevante invalida aprovação anterior ao início e plano recorrente.
  Scopes antigos não recebem campo ou hash retroativo: solicitar/aprovar um
  novo escopo. Runs iniciadas e relatórios mantêm seu contexto original.
- Comparação usa exclusivamente snapshots históricos, inclui testes retirados
  e mostra diferenças de regras, vínculos, testes e ambiente/coleta. Ausência do
  campo no legado significa contexto desconhecido. Inventário global Sigma
  continua conservador: nova versão de qualquer regra pode invalidar aprovação.
  Diferença de configuração/resultado não demonstra causalidade.

Arquivos centrais: apps/api/aegis/rule_links.py, models.py, services.py, queries.py,
api.py, cli.py, migrações; apps/web/src/RuleTestLinks.tsx e
ScopeChanges.tsx, páginas de catálogo/regras/cobertura, testes API/UI/E2E.
[Guia operacional e contrato](operations/rule-test-reviews.md),
[revisão de segurança](security/review-rule-links-2026-10-22.md).

### Problemas encontrados e corrigidos

Revisão especializada somente leitura identificou retirada reversível por SQL,
título atual confundível com versão histórica, confirmação sobrevivendo a uma
atualização de cache e resposta de comparação sob filtros alterados. Corrigidos
com trigger monotônico, current_rule_title explícito, confirmação do payload
serializado e bloqueio dos seletores durante consulta. Testes exercitam as quatro
situações; a verificação final foi realizada pelo agente principal.

O E2E inicialmente encontrou entrada multilinha incompatível com locator.fill
no Firefox/BiDi e clique em confirmação antes de o formulário estar pronto ou
visível. Automação corrigida com digitação, espera da resposta/estado habilitado
e posicionamento visível; confirmação e validações da aplicação mantidas.
Última rodada completa passou. Captura do modal corrigida para começar no topo.

### Verificações executadas

| Check | Resultado observado |
|---|---|
| `make test` | **329 Python passaram**,100,00s; **22 frontend passaram** |
| `make lint` | Ruff/check/format de 91 arquivos, mypy domínio, TypeScript e Prettier passaram |
| PostgreSQL/API direcionados | **19 passaram**,14,58s: vínculos, comparação e migração populada |
| `make e2e` | Firefox, API/worker/PG/Redis reais: **4 runs/16 testes sintéticos**, **8 capturas**, **0 erros JavaScript** |
| Preservação histórica no E2E | Importação, revisão, versão seguinte, substituição e retirada; relatório anterior permaneceu idêntico e comparação conservou snapshots |
| Build/implantação Demo | Compose com migrations/seed/grants e build frontend passou; API/DB/Redis/worker saudáveis, ready database/redis=true |
| `make smoke` | API/worker/runtime SQL, campanha e ocorrência agendada, revogação e relatório; conferiu privilégios por coluna e trigger |
| Documentos | 13 Markdown/37 links locais verificados antes deste checkpoint; scanner staged/diff-check por commit |
| CI final do código | **SUCCESS**, código 4ef1408, [run39799833294](https://github.com/Buraddomoon/AEGIS/actions/runs/39799833294); execuções anteriores redundantes canceladas |

Nenhuma dependência ou recurso pago adicionado. Aviso upstream TestClient/httpx
e advisory transitivo DiskCache previamente revisado permanecem. CI incluiu
advisories; não foi feita nova auditoria local além das verificações registradas.
O Demo atualizado está em http://localhost:18780. Nenhum container Wazuh está
presente; volumes/evidências do ensaio anterior preservados. Sua autorização
continua consumida: esta etapa só executou fluxos Demo e testes locais.

### Pendências e continuidade

Próxima etapa recomendada: análise semântica determinística das regras e avaliação
de compatibilidade de backend/pipeline Sigma oficial, com limites explícitos.
Ainda não há conversão ou implantação Sigma validada no Wazuh. Associação humana
não prova que a regra detecta o comportamento. Permanecem pendentes comparação
entre ambientes, atualização controlada ATT&CK, retenção/restore/rotação de PKI,
Windows, archives e PDF. Scheduler segue restrito a Demo e workspace único.

Este marco acrescenta **14 commits granulares**, incluindo este checkpoint,
totalizando **157**. Somente main, AEGIS privado, push após cada commit, sem
branch/PR/force. Último código 4ef1408 com CI verde acima; commits seguintes são
capturas/documentação. Consultar log/status após o checkpoint para hash/mensagem
e sincronização finais; não incorporar seu próprio hash neste arquivo.


## 2026-10-22 — Análise estática Sigma por versão e proteção pré-parser

### Funcionalidades e decisões

Entregue análise real sobre o conteúdo persistido de cada RuleVersion. O serviço
é puro, determinístico e identificado por sigma-static/1, pySigma2.0.1 e SHA-256.
Nenhuma tabela/cache, migração, dependência ou serviço pago foi acrescentado.
[ADR0008](architecture/decisions/0008-sigma-static-analysis.md) e
[contrato/limites](integrations/sigma.md#análise-estática-de-versões).

- Cinco checks AEGIS sobre o parser/modelo oficiais: resolução de condições,
  seleções não referenciadas, all sem contains, curingas consecutivos e
  caracteres de controle. Resultados ordenados, campos/seleções de contexto e
  prioridade de revisão; não representam risco de negócio ou eficácia.
- Fatos incluem logsource, condições, seleções e campos declarados. Ausência de
  achados é limitada aos checks listados. Condição não resolvida impede o check
  de seleção não referenciada, explicitamente marcado como não executado.
- GET /rules/{rule_id}/versions/{version_id}/analysis exige sessão, permite
  viewer, verifica associação da versão à regra e hash, limita60/min por usuário.
  409 por integridade divergente,422 por conteúdo não analisável e429 por limite.
  Não grava vínculos, evidências, aprovações, scopes ou veredictos.
- Regras → Análise estática seleciona versões atuais/históricas, exibe achados,
  limites e identificação/hash do conteúdo. Recusa identidade/hash divergentes,
  não mistura resposta pendente de outra versão, trata erro/ausência de versões.
- Compatibilidade not_configured, backend/pipeline null, conversão/implantação
  false. Documentação oficial lista backend OpenSearch e pipelines de mapeamento;
  isso não demonstra compatibilidade com schema Wazuh ou regra XML no manager.

Arquivos principais: apps/api/aegis/integrations/sigma_analysis.py,
yaml_import.py e api.py; apps/web/src/RuleAnalysis.tsx, Management.tsx e types.ts;
tests/test_sigma_analysis.py e UI sigma-analysis.test.tsx; harnesses E2E/smoke e
scripts/audit_dependencies.py. [Revisão](security/review-sigma-analysis-2026-10-22.md).

### Problemas encontrados e correções verificadas

Importar um validador de sigma.validators.core executa descoberta/importação de
outros módulos, inclusive loaders MITRE/DiskCache. Inspeção e teste revelaram o
caminho antes da entrega. Usar checks locais explícitos sobre parser/modelo e
manter regressão/auditoria de DiskCache ausente; nenhum validador upstream copiado.

Revisão especializada somente leitura identificou expansão de modificadores
antes dos budgets de análise e bypass via dispatch de documento filter. Corrigidos
na entrada compartilhada de importação/análise ANTES de SigmaCollection:

- YAML até32 níveis antes de safe_load,64KiB/5000eventos e aliases proibidos.
- Somente regra individual: rejeitar filter/correlation/action e detection não
  objeto antes do dispatch. Até6 modificadores por campo, sem repetição.
- Estimativa conservadora de transformação:256KiB/valor,1MiB total,4096variantes,
  considerando encodings/base64offset/windash da versão pySigma fixada. Não mede
  RAM total do interpretador e pode recusar regras legítimas complexas. Revisar
  política ao atualizar a biblioteca; conteúdo legado fora da política não é
  apagado, mas sua análise retorna422.

Testes substituem o parser por função proibida para provar recusa antecipada,
sem executar expansões perigosas. Encoding normal também foi aceito. Processo
novo com audit hook verifica ausência de importação DiskCache, rede e gravações.
Revisão estática final não identificou bloqueador concreto restante nesses deltas.
O teste UI de falha foi ajustado à tentativa adicional de consulta, preservando o
retry da aplicação e o estado de erro real.

### Verificações executadas

| Check | Resultado observado |
|---|---|
| `make test`, rodada final | **362 Python passaram**,143,20s; **27 frontend passaram**,4,61s |
| `make lint` | Ruff/check/format de93 arquivos, mypy domínio, TypeScript e Prettier passaram |
| PostgreSQL/API/análise direcionados | **52 passaram**,6,39s, incluindo expansão/dispatch antes do parser; sem payload perigoso |
| `make e2e`, após hardening | **PASS** Firefox/API/worker/PG/Redis:4 runs/16 testes sintéticos,9 capturas,0 erros JavaScript |
| Histórico no navegador | Consulta versão atual com achado e anterior sem achados; revisões/retirada, relatório anterior idêntico e comparação histórica |
| Docker Compose | Build de produção/migrate/seed/grants e API/worker saudáveis; ready database/redis=true |
| `make smoke`, imagem corrigida | **PASS**, papel SQL runtime, importação/análise Sigma, campanha+ocorrência,8 resultados sintéticos, grant/revogação e relatórios; conta temporária desativada |
| `make audit` | **PASS**:1 advisory transitivo DiskCache revisado visível; parsing/análise não importam seu cache; npm0 vulnerabilidades |
| Documentos |10 Markdown/40 links locais verificados antes deste checkpoint; scanner staged/diff-check antes de cada commit |
| CI do código final | **SUCCESS**,8fcd0d6, [run39829087308](https://github.com/Buraddomoon/AEGIS/actions/runs/39829087308): lint/tipos/PG/UI/build/advisories |

Rodadas anteriores344 e349 Python/27frontend passaram antes dos complementos de
segurança; tabela acima registra a rodada final. Aviso upstream TestClient/httpx
permanece. Captura real da análise em docs/images/sigma-analysis.png, inspecionada;
imagens Demo atualizadas pelo fluxo de navegador, sem inserir dados do ensaio real.

### Estado operacional e próxima etapa

Demo atualizado em http://localhost:18780. Wazuh permanece encerrado com9volumes
preservados, sem novo marcador/consulta SIEM; autorização do ensaio anterior
continua consumida. Nenhum serviço de outro projeto foi parado ou reconfigurado.

Próximo passo recomendado: avaliar backend/pipeline oficial e mapeamento de campos
para um destino definido, com testes offline de conversão e limites explícitos.
Não há conversão ou implantação Sigma validada; semântica completa, correspondência
à telemetria e eficácia permanecem pendentes. Mantêm-se roadmap de retenção/restore,
PKI, atualização ATT&CK, Windows, archives e scheduler restrito a Demo.

Este marco acrescenta **12 commits granulares**, incluindo este checkpoint,
totalizando **169**. Main exclusiva, AEGIS privado e push após cada commit, sem
branch/PR/force. Último código8fcd0d6; mudanças seguintes só documentação/capturas.
Consultar git log/status após o checkpoint para último hash/mensagem e sync;
não incorporar seu próprio hash neste documento.


## 2026-10-22 — Diagnóstico Sigma de compatibilidade e mapeamento candidato

### Entrega e decisão de escopo

Implementados serviço, APIs e UI reais de **preparação de conversão**, calculados
sobre RuleVersion persistida e perfil/hash. Não há conversão executada nem query
fabricada. [ADR0009](architecture/decisions/0009-sigma-conversion-readiness.md),
[contrato/limites](integrations/sigma.md#preparação-de-conversão-e-campos-candidatos).

A pesquisa encontrou um impedimento real: wheels oficiais OpenSearch2.0.3 e
Elasticsearch2.1.1 exigem pySigma<2.0.0, mas o núcleo usa2.0.1. Os artefatos foram
baixados somente para conferir SHA-256 e extrair METADATA, sem instalar/executar
código. Requisitos do wheel OpenSearch diferem do pyproject atual do repositório;
a fonte operacional do diagnóstico é o wheel publicado, registrado em snapshot.
Não forçar instalação com --no-deps, copiar backend nem reduzir o parser.
Conversão/implantação permanecem indisponíveis, com motivos consultáveis.

- Serviço sigma_readiness.py compara requisitos oficiais capturados às versões
  realmente instaladas, sem importar backends ou acessar rede durante consulta.
  Identifica readiness_version, versão/hash da regra e perfil/hash, snapshot/data/
  fonte/hash, requisitos ausentes/conflitantes e licença declarada LGPL-3.0-only.
- Perfil fixo wazuh-aegis-marker/1 mapeia apenas logsource próprio e campos
  presentes no alerta aegis-json/1 registrado. Não inventar Image/CommandLine→
  full_log. _source demonstra presença do valor, não tipos/analisadores/keyword
  no índice. artifact_bytes apareceu como string, não garantia de campo numérico.
- Campos/logsource ausentes, seleções keyword, achados estáticos e referências
  fieldref geram pendências explícitas. Mesmo com nomes mapeados, can_convert/
  conversion_performed/deployment_performed=false: perfil candidato não é
  ProcessingPipeline e mapping físico continua não verificado.
- GET /sigma/conversion-profiles permite viewer autenticado,60/min por usuário.
  GET /rules/{id}/versions/{version_id}/conversion-readiness?profile_id=... fixa
  versão e perfil,30/min. Sem destinos, plugins, índices ou pipelines arbitrários.
  Helper compartilhado confere associação da versão/hash; metadados indisponíveis
  falham503. Diagnósticos não modificam scopes, aprovações, relatórios ou veredictos.
- UI Regras → Preparação de conversão seleciona histórico, lista bloqueios e
  campos candidatos, confere identidade/hash/perfil e trata erro/ausência de
  perfis. Resposta atrasada de outra versão não aparece sob a seleção atual.
  Ações da tabela reorganizadas em lista legível, sem botão Converter decorativo.

Arquivos centrais: apps/api/aegis/integrations/sigma_readiness.py e api.py;
fixtures/sigma/backend-metadata.json e aegis-marker-candidate.yml;
apps/web/src/RuleReadiness.tsx/types.ts/Management.tsx; testes sigma_readiness,
sigma-readiness.test.tsx, guard de análise, harnesses E2E/smoke e auditoria.
packaging26.3 passa de dependência transitiva a direta; versão/locks mantidos,
nenhum pacote adicional instalado ou serviço pago ativado. Sem migração.

### Revisão e problemas corrigidos

Revisão especializada somente leitura confirmou limites de execução, hash/contexto,
separação entre _source e mapping e ausência de importação de backend/cache.
Apontou imprecisão de fieldref: o nome referenciado não constava de declared_fields.
Corrigido com coleta dessas referências no documento pré-validado, bloqueio
field_reference_mapping_unspecified e field_mapping_complete=false, inclusive
quando o nome tem caminho candidato. UI explicita referências pendentes. Dois
casos backend e um UI validam o comportamento; revisão estática final não apontou
bloqueador concreto restante nesse delta.

Testes iniciais de UI ajustados para verificar método GET no objeto de opções
real do cliente HTTP, mantendo os headers/sessão. Nenhum bypass de confirmação,
controle ou efeito real foi introduzido. O diagnóstico é atual sob dependências/
metadados/perfil identificados, não uma evidência histórica imutável de detecção.
[Revisão registrada](security/review-sigma-readiness-2026-10-22.md).

### Validações executadas

| Check | Resultado observado |
|---|---|
| `make test`, rodada final | **378 Python passaram**,162,41s; **35 frontend passaram**,4,63s |
| `make lint` | Ruff/check/format de95 arquivos, mypy domínio, TypeScript e Prettier passaram |
| Diagnóstico direcionado | **16 passaram**,4,54s, incluindo conflitos de requisitos, perfis, paths gravados, história, sessão/hash/rate limit, metadados inválidos e fieldref |
| `make e2e`, após correção | **PASS**,Firefox/API/worker/PG/Redis:4 runs/16 testes sintéticos,10 capturas,0 erros JavaScript |
| Cenários no navegador | Regra genérica sem mapeamento; exemplo de marcador com campos mapeados e conversão bloqueada; relatório anterior permaneceu idêntico |
| Compose | Build de produção/migrate/seed/grants e API/worker saudáveis; ready database/redis=true |
| `make smoke`, imagem corrigida | **PASS**,papel SQL runtime, APIs de análise/preparação, campanha+agendamento,8 resultados sintéticos, grant/revogação e relatórios; conta temporária desativada |
| `make audit` | **PASS**,advisory transitivo DiskCache revisado visível; parsing/análise/assess sem cache/rede/escritas no guard; npm0 vulnerabilidades |
| Compatibilidade de instalação | `pip check`: **No broken requirements found**; nenhum backend forçado/instalado |
| Documentos |11 Markdown/45 links locais verificados antes deste checkpoint; scanner staged e diff-check em cada commit |
| CI final | **SUCCESS**,3479f01, [run39841661856](https://github.com/Buraddomoon/AEGIS/actions/runs/39841661856): lint/tipos/PG/UI/build/advisories |

A rodada anterior376 Python/34frontend passou antes da correção fieldref; tabela
acima registra a final. Aviso upstream TestClient/httpx e advisory DiskCache
permanecem. Captura real docs/images/sigma-readiness.png inspecionada; dados Demo
e exemplo autoral estão identificados, sem técnica ATT&CK artificial.

### Estado e continuidade

Demo atualizado em http://localhost:18780. Nenhum serviço Wazuh iniciado ou novo
marcador real executado;9volumes/evidências do ensaio anterior preservados, nenhum
container desse projeto presente. Autorização real anterior continua consumida.

Conversão requer backend oficialmente compatível com o core, pipeline executável
revisado, mapping físico e validação de saída; consulta/implantação em SIEM exigem
seu próprio escopo autorizado. Este marco não remove esses bloqueios. Próxima
etapa sem essa dependência externa: backup/restore verificável do Demo em banco
isolado e política de retenção. Mantêm-se pendências de PKI, atualização ATT&CK,
Windows, archives, multi-workspace, PDF e scheduler restrito a Demo.

Este marco acrescenta **11 commits granulares**, incluindo este checkpoint,
totalizando **180**. Main exclusiva, AEGIS privado e push após cada commit,
sem branch/PR/force. Último código3479f01; seguintes só capturas/documentação.
Consultar git log/status após o checkpoint para último hash/mensagem e sync;
não incorporar seu próprio hash neste arquivo.


## 2026-10-22 — Backup consistente e recuperação verificável do Demo

### Entrega

Implementada ferramenta operacional host-only, sem endpoint administrativo novo:
`make backup-demo`, `make verify-backup BACKUP_ID=...`,
`make backup-retention-plan` e `make test-recovery`.
[ADR0010](architecture/decisions/0010-demo-backup-rehearsal.md),
[procedimento/limites](operations/backup-recovery.md),
[revisão](security/review-recovery-2026-10-22.md).

- Fonte restrita ao projeto aegis/db, PostgreSQL17/public e conexão administrativa
  local18782. Identidade do cluster/banco conferida, snapshot REPEATABLE READ READ
  ONLY compartilhado entre inventário e pg_dump; nenhuma pausa ou escrita no
  banco em uso. Inventário inclui todas as linhas/tabelas, migração, colunas,
  tipos/typmods/collations, constraints, índices/flags, triggers e funções cobertas.
- SHA-256 do dump e recálculo dos hashes internos de eventos, versões Sigma e
  scopes. Dados e contas do dump são privados; manifesto não é assinatura.
  Arquivos0600, diretórios0700, fsync de arquivos/diretórios, criação exclusiva,
  symlinks recusados e dumps adicionados ao ignore/scanner staged.
- Restore somente em clone próprio aegis-recovery-UUID, mesma imagem local porID,
  sem pull, rede, portas, mounts do host, volumes duráveis, API, worker ou scheduler.
  Tmpfs limitado,1CPU/768MiB/128PIDs, read-only/no-new-privileges. Restore em transação
  única, sem ACL/owner; nenhuma troca de destino de aplicação.
- Intenção privada persistida antes de create e reconciliação por nome exato/label
  mesmo após resposta ambígua. Sem receipt verificado quando restore/comparação/
  cleanup falham. Docker CLI com config temporário vazio e ambiente saneado:
  não herdar proxies com credenciais nem contexto remoto do usuário.
- Inventário aegis-pg-inventory/2, envelope aegis-demo-backup/1 e normalização
  pg17-literal-array-casts/1 explícitos. Formato antigo é recusado antes de Docker;
  histórico não é regravado e plano de retenção preserva os legados.
- Retenção é somente plano: mantém sete mais recentes/todos até30dias e legados;
  review_only exige revisão humana específica, sem exclusão automática. Nada
  removeu backups, evidências, auditoria, volumes ou journals de laboratórios.

Arquivos centrais: apps/api/aegis/operations/backup.py,
scripts/demo_backup.py, tests/test_backup_inventory.py/test_backup_cli.py,
Makefile, scanner staged, docs operacionais e recibo público sem dados de linhas.
Nenhuma dependência nova, migração ou mudança de API/frontend.

### Problemas encontrados e corrigidos

Primeiro restore recusou schema public já existente no initdb; agora remove
somente o schema vazio do clone sem CASCADE antes de restaurar. Quatro constraints
foram reescritas pelo PostgreSQL de cast de array varchar→text para casts em cada
literal. Normalização restrita cobre apenas esse caso, preservando valores/aspas;
NULLs/funções/outros casts não são equivalência genérica. Diferenças restantes
continuam bloqueadas. O primeiro backup experimental foi preservado, não editado.

Revisão especializada somente leitura apontou: create ambíguo sem reconciliação,
falta de fsync de diretórios, typmod de arrays ausente e configuração Docker global
podendo injetar proxies. Quatro correções implementadas com regressões. Recusar
RLS/policies, tipos customizados, procedures, sequences/views e outros recursos
não inventariados evita declarar recuperação não coberta. Revisão estática final
não encontrou novo bloqueador; observação menor de versionamento também tratada.
Revisor não executou testes, Docker ou efeitos reais.

Uma rodada ampla teve420pass/1fail em rate limiting porque executei pytest
concorrente com outra suíte que limpa Redis DB15. Essa rodada não foi aprovada.
A documentação exige executar essas suítes serialmente; controle de produção
permaneceu inalterado. Rodada exclusiva final passou integralmente.

### Evidência e validação

- `make test` final, sozinho: **423 Python passaram**,156,13s; **35 frontend**,
  4,59s. `make lint` passou: Ruff/check/format100arquivos, mypy domínio, TS/Prettier.
- `make test-recovery`: **45 passaram**; PG real para inventário, snapshot com
  commit posterior excluído, constraints e typmods. Mocks de Docker somente para
  falhas de create/start/restore/comparação/ownership/cleanup e configuração CLI.
- `make backup-demo`/`make verify-backup` reais finais: **30tabelas/2.884linhas**,
  hashes/estrutura conferidos, **clone removido**. ID final
  20261022T210359Z-e689b5a47fa44a69b969a726982324de. Recibo9,488s é uma medição
  desse restore, não benchmark/RTO. [Evidência](evidence/recovery-2026-10-22/README.md).
- `make backup-retention-plan` passou: quatro arquivos preservados, legados
  sinalizados, nenhuma exclusão. Permissões0700/0600 conferidas no host.
- Recibo público foi comparado ao original privado;9Markdown/42links locais
  verificados no commit de operação e scanner/diff-check em cada commit.
- E2E de navegador/smoke/deploy não foram repetidos: API/UI/worker não mudaram.
  Demo segue ready database/redis=true. Nenhum clone remanescente nem container
  Wazuh presente;9volumes do ensaio anterior preservados, nenhum ensaio real
  Linux/Wazuh repetido.
- CI final: **SUCCESS**,fba4494, [run39854484061](https://github.com/Buraddomoon/AEGIS/actions/runs/39854484061),validate3m12s: lint/tipos/PG/frontend/build/advisories. Advisory transitivo DiskCache revisado continua visível; não foi declarado zero vulnerabilidades Python.

### Limites e próximo passo

Backup cobre schema public do Demo confiável; não roles/ACLs, secrets/.env/PKI,
Redis, journals do runner ou artefatos externos. Hash não é assinatura e0700/0600
não é criptografia. Cópia criptografada fora do host e guarda de imagens/configuração
são pendências operacionais. Queda abrupta/daemon indisponível pode exigir revisão
de intenções/clones; observed_absent não comprova término futuro de create ambíguo.

Não foi testado boot da API/worker recuperados, failover, cutover ou retomada de
jobs; não há RPO/RTO garantido. Próxima etapa recomendada: recuperação operacional
em Demo separado, com execução automática bloqueada e reconciliação explícita de
sessões/jobs/agendamentos antes de qualquer worker. Mantêm-se pendências Sigma
backend/pipeline/mapping, atualização ATT&CK, PKI, Windows/archives, PDF e
multi-workspace. A autorização real Wazuh continua consumida.

Este marco acrescenta **11 commits granulares**, incluindo este checkpoint,
totalizando **191**. Main exclusiva, AEGIS privado e push após cada commit; último
código b55d22a, recibo público fba4494 e documentação9f6ed3d. Consultar git log/status
para hash/mensagem finais e sincronização; não incorporar seu próprio hash aqui.


## 2026-10-23 — API recuperada em quarentena

### Entrega e decisões

[ADR0011](architecture/decisions/0011-recovery-quarantine.md) acrescenta ensaio de
boot restrito ao backup verificado no ADR0010. `make recovery-app-build` constrói
imagem própria separada; `make verify-recovered-app BACKUP_ID=...` restaura em
clone temporário e inicia somente API em recovery, sem modificar o Demo em uso.
[Procedimento](operations/backup-recovery.md), [revisão](security/review-recovery-2026-10-23.md)
e [recibo real](evidence/recovery-2026-10-23/README.md).

- Seleção de rotas no boot: somente health e review agregada; token efêmero
  independente, sem sessão histórica/login, frontend, docs ou mutações. Não há
  endpoint para sair de recovery. Nenhuma nova integração ou dependência.
- Worker, claim/processamento/recuperação, scheduler, CLI seed/grants/bootstrap
  e migrações recusam antes de conexão/thread. Fluxo normal preservado e testado.
- Role SELECT provisionado apenas no clone, sem ownership/membership, poderes
  administrativos, DB/schema CREATE/TEMP, grants DML/coluna ou EXECUTE em funções
  public/large objects. Readiness exige ACLs, transação read-only e revisão Alembic
  da imagem. SQL timeouts e falhas genéricas sem dados/segredos.
- Trust TCP do initdb substituído por SCRAM do role efêmero/IP/banco fixos e
  reject restante; socket administrativo não é montado na API. Probe confirma
  que nem um override READ WRITE dá permissão para DML/DDL/TEMP/large objects.
- API uid10001/read-only/cap-drop ALL/no-new-privileges,384MiB/1CPU/64PIDs/tmpfs64MiB,
  no namespace do PostgreSQL network=none, sem portas/mounts/Redis/runner/SIEM.
  Imagens locais por ID, sem pull no ensaio. Dockerconfig vazio/env saneado.
- Intenções duráveis próprias, segredos em env temporário0600 somente durante
  create, não argv/intent/recibo. Cleanup API antes de DB; falha/incerteza retém
  DB como retained_api_cleanup_unconfirmed e não gera sucesso. Retenção de backup
  continua sem exclusão. SIGKILL/daemon indisponível ainda exige revisão manual.
- Review aegis-recovery-review/1 conta sessões/filas/reservas/grants/agendamentos/
  dispatches; não aplica reconciliação e mantém normal_operation_permitted=false.
  Histórico e dados restaurados são comparados novamente depois da leitura.

Arquivos centrais: apps/api/aegis/operations/recovery.py, main.py/config.py/db.py,
worker.py/scheduling.py/cli.py, migrations/env.py, scripts/demo_backup.py e
recovery_probe.py, tests/test_recovery_api.py/test_recovery_guards.py/
test_recovery_probe.py e expansão de test_backup_cli.py. Nenhuma migration nova
ou mudança de frontend; o default Demo não foi reconstruído/reiniciado.

### Achados corrigidos e validação

Uma primeira execução de review nos testes expôs a interface SQLAlchemy2.1:
dict(CursorResult) não é subscriptable. Ajustado para consumir linhas com all(),
sem depender do tuples() depreciado. Sem falso sucesso da API.

Revisão especializada somente leitura encontrou EXECUTE residual em pg_catalog
large objects e ordem de cleanup DB após erro API. Ambos corrigidos e reinspecionados,
sem novo bloqueador identificado. Não houve testes/Docker pelo revisor. Nova
regressão verifica grant drift e tentativa lo_create/42501; outra impede remoção
DB antes de cleanup API confirmado. Probe também recusa ambiente/URL/token fora
do destino fixo antes de I/O.

- `make test` após correções: **461 Python passaram**,111,10s; **35 frontend**,
  3,04s. Os8 testes novos de escopo da probe passaram separadamente; **469 casos
  Python únicos validados localmente**. Suítes com Redis DB15 rodadas serialmente.
- `make test-recovery` final: **91 passaram**,16,32s. ACLs reais em banco/papel
  aleatórios próprios, removidos após o teste; nenhuma revogação PUBLIC na fonte.
  Sessões válidas/expiradas, fila, reserva e aprovação pendentes permanecem intactas.
- `make lint` final passou: Ruff/check/format105arquivos, mypy domínio4arquivos,
  TypeScript/Prettier. Sem ocultar aviso upstream TestClient/httpx.
- Build da imagem separada passou. `make verify-recovered-app` real final:
  backup20261022T210359Z-e689b5a47fa44a69b969a726982324de,
  **30tabelas/2.884linhas**, inventário igual antes/depois, **API e DB removidos**;
  9 rotas/4 tentativas SQL/5 entrypoints e TCP administrativo bloqueados.
  Recibo16,321s é só medição desse ensaio, não RTO/benchmark. Imagem
  sha256:dd16c33d779c6f698803e3143701dffd8d43c196b7d76d308dd81fcba5057160.
- `make e2e` passou: build e Firefox, **4 runs/16 testes sintéticos**,10capturas,
  zero erros JavaScript, fluxo completo com agendamento e Sigma. Capturas novas
  preservadas privadamente em .local/e2e/recovery-milestone-screenshots; imagens
  públicas anteriores não foram alteradas desnecessariamente.
- Recibo público comparado ao original privado, permissões0700/0600 verificadas;
  49 links locais da documentação alterada conferidos antes dos commits.
  Scanner staged/diff-check em cada commit. Nenhum dump/manifesto/secret publicado.
- Demo18780 continua ready(database/redis=true), nenhum clone remanescente,
  nenhum container Wazuh,9volumes anteriores preservados. Nenhum novo ensaio
  Linux/Wazuh, alteração de rede/sysctl/serviço alheio ou consulta SIEM.
- CI final: **SUCCESS**,06017fe, [run39956649898](https://github.com/Buraddomoon/AEGIS/actions/runs/39956649898),
  validate3m33s: **465 Python passaram/4 skip**,35frontend, lint/tipos/build e
  revisão de advisories. Os4 skip são projeções opcionais de objetos Docker Demo
  já existentes (test_wazuh_runtime_inspection.py:410); CI não os cria. Localmente
  os469casos passaram. Advisory DiskCache transitivo revisado continua visível;
  não declarar zero vulnerabilidades Python. Docs finais só Markdown não disparam
  outra CI. Checkpoint anterior ainda registrou aguardando porque a conferência
  esperava469pass no log; corrigido após ler os4skip, sem reescrever commits.

### Limites e continuidade

O backup utilizado tem20runsCOMPLETED, nenhuma sessão/fila/agendamento ativo e
1Demoautorizado. Esse conteúdo não representa todos os snapshots possíveis;
fixtures cobrem pendências sem ativá-las. Boot em quarentena não é recuperação
normal, failover, reconciliação aplicada, retomada de jobs ou RPO/RTO garantido.
Roles/ACLs originais, secrets/PKI, Redis e journals externos não são recuperados.
Imagem/configuração e dump precisam ser confiáveis, hash não é assinatura e
permissão privada não é criptografia. Nenhuma autorização real foi renovada.

Próxima etapa: reconciliação explícita em destino Demo isolado (sessões, grants,
filas/reservas e agendamentos), somente então novo ciclo sintético com aprovação
nova antes de avaliar reativação. Seguem pendentes cópia criptografada externa,
guarda de imagens/configuração, RPO/RTO, PKI, Sigma backend/pipeline/mapping,
atualização ATT&CK, Windows/archives, PDF e multi-workspace.

Este marco acrescenta **11 commits granulares**, incluindo checkpoint e correção
do registro CI, totalizando **202**. Main exclusiva, AEGIS privado, push após cada commit. Código
ff366e5, recibo/revisão06017fe, documentação4e0b937; consultar git log/status para
hash/mensagem finais e sincronização, sem incorporar o próprio hash aqui.


## 2026-10-23 — Reconciliação offline do clone Demo

### Entrega e decisões

[ADR0012](architecture/decisions/0012-demo-recovery-reconciliation.md) acrescenta
`make reconcile-demo-backup BACKUP_ID=...`: novo clone offline, inventário original
verificado, plano fixo/hash, aplicação transacional e API novamente em recovery.
[Ferramenta e limites](operations/backup-recovery.md),
[recibo real](evidence/reconciliation-2026-10-23/README.md) e
[revisão](security/review-reconciliation-2026-10-23.md).

- Host-only, sem endpoint de mutação ou destino/SQL arbitrário. Nome exato,
  label, network=none e ausência de mounts/binds/portas conferidos antes do SQL.
  PostgreSQL17/schema exatos, tabelas extras recusadas, hash de dados/estrutura,
  locks em ordem fixa/NOWAIT e nova comparação sob lock antes de aplicar.
- Apaga sessões, desativa usuários, revoga labs/grants e agendamentos retomáveis;
  cancela apenas runs/filhos comprovadamente Demo por transições válidas e steps
  próprios. Preserva ended_at existente, scopes/aprovações, evidências/resultados,
  regras e histórico anterior. Não alega execução/cleanup/validação defensiva nova.
- Pendências reais, dispatch em run pendente, misturas de ativos/testes, reservas
  órfãs e estados/filhos inconsistentes bloqueiam toda a transação. Falha final
  ou trigger que altera campos protegidos/reativa conta também faz rollback.
- Auditoria append-only e idempotência por ID/hash. Plano privado e registro de
  aplicação não substituem recibo final. Fonte/dump/manifesto intactos e nenhum
  worker, Redis, runner ou Wazuh iniciado pela recuperação.
- API SELECT/SCRAM continua em recovery; ID/hash esperados no boot precisam casar
  com registro único e fences atuais de sessões/contas/pais/filhos/labs/grants/
  agendamentos. Auditoria histórica sozinha é só contagem e não comprova aplicação
  atual. Sempre normal_operation_permitted=false, sem endpoint de reativação.
- Comparação protegida depois da aplicação, inventário igual antes/depois da
  leitura da API, probes existentes e cleanup API→DB antes de sucesso. Cleanup
  incerto mantém DB, sem recibo. Repetir o CLI cria outro clone; nunca retoma
  automaticamente um clone anterior ou muda o ambiente em uso.

Arquivos centrais: apps/api/aegis/operations/reconciliation.py e recovery.py,
config.py/main.py, scripts/demo_backup.py, Makefile, tests/test_recovery_reconciliation.py,
test_recovery_api.py e test_backup_cli.py. Sem dependências, migrations ou UI novas.
README/AGENTS/CHANGELOG e documentação operacional atualizados.

### Achados corrigidos e validação

Revisão especializada somente leitura encontrou: flag indevida por auditoria
histórica; salto de estado dos filhos sem steps; sobrescrita de ended_at factual;
tabelas extras fora do plano; e ausência de fence para filho pendente depois da
reconciliação. Corrigidos com binding exato, transições por simulação, COALESCE,
schema exato e revisão de pais/filhos. Regressões exercitadas em PostgreSQL real;
revisor não executou testes/containers. Reinspeção confirmou os quatro primeiros;
último fence foi corrigido e passou no teste de drift do filho.

Durante desenvolvimento, um helper de teste inicialmente tratou JSON text do
psycopg como dict e uma fixture removeu teste ainda referenciado por step; corrigidos
parsing/FKs da fixture, sem afrouxar constraints. Outra fixture de CLI tinha
estrutura diferente do manifesto e foi corrigida; testes não foram considerados
aprovados enquanto falhavam.

- `make test` final: **538 Python passaram**,160,78s; **35 frontend**,2,99s.
  Inclui **34 novos casos de reconciliação SQL**; nenhuma suite Redis DB15 em
  paralelo. Bancos/papéis aleatórios próprios removidos:0/0 remanescentes.
- `make lint` passou: Ruff/check/format107arquivos, mypy domínio4arquivos,
  TypeScript/Prettier. Aviso upstream Starlette TestClient/httpx permanece visível.
- Build da imagem separada passou; frontend da imagem veio do cache sem mudança.
  Imagem local fixada no ensaio por
  sha256:d2c3915dfb69859f95804af27a06efd786b8926b9da88acb1975649dd89c71ca.
- Ensaio real `make reconcile-demo-backup`: backup
  20261022T210359Z-e689b5a47fa44a69b969a726982324de,30tabelas/2.884linhas originais;
  2.885linhas após1auditoria, estrutura/histórico protegidos preservados,
  autorização do Demo restaurado revogada e environment_version incrementada.
  API confirmou ID83563951337c44ab81329019421e355d/hash do plano e fences vazios,
  mantendo quarentena.9rotas/4tentativas SQL/5entrypoints/TCP administrativo
  bloqueados; API e DB removidos.20,578s é só medição, não RTO/benchmark.
- Snapshot utilizado tem20runsCOMPLETED,nenhuma conta ativa/sessão/fila/grant,
  1Demoantes autorizado. Casos não vazios são cobertos pelos testes, não inventados
  no recibo desse backup. Dump/manifesto/intents privados preservados; recibo
  público igual ao privado, diretórios0700/arquivos0600 conferidos.
- Demo18780 segue ready database/redis=true, imagem/API/worker em uso não foram
  reconstruídos/reiniciados. Nenhum clone ou container Wazuh remanescente;9volumes
  do ensaio real anterior preservados. Nenhuma nova simulação Linux/Wazuh,
  consulta SIEM, renovação de PKI ou alteração de serviços/rede/sysctl do host.
- 50links locais alterados conferidos; scanner staged/diff-check em cada commit.
  E2E de navegador não repetido: UI/fluxo normal não mudaram; suíte completa cobre
  regressões normais da API e testes frontend. Último E2E Firefox validado permanece
  o do marco anterior, sem atribuí-lo a uma nova execução.
- CI final: **SUCCESS**,02f94b4,
  [run39965210762](https://github.com/Buraddomoon/AEGIS/actions/runs/39965210762),
  validate3m06s: **534 Python passaram/4 skip**,35frontend, lint/tipos/build e
  revisão de advisories. Os4skip são projeções opcionais de objetos Docker Demo
  já existentes; CI não os cria. Localmente538passaram. Advisory transitivo
  DiskCache revisado permanece visível; não declarar zero achados Python. Commits
  seguintes só Markdown não alteram o código validado nem disparam nova CI.

### Limites e continuidade

Não houve boot normal, criação de nova conta operacional, novo ciclo sintético,
cutover, failover ou recuperação de efeitos reais. Próximo passo: destino Demo
separado com credenciais/conta novas, autorização Demo nova e aprovação nova para
um ciclo completo; worker só depois dos fences/reconciliação. Não reaproveitar
usuários, grants, jobs ou autorização real do snapshot.

Mantêm-se pendências de cópia criptografada externa, guarda de imagens/configuração,
RPO/RTO, roles/secrets/Redis/PKI/journals externos, Sigma backend/pipeline/mapping,
atualização ATT&CK, Windows/archives, PDF e multi-workspace. Autorização real
Linux/Wazuh continua consumida; nenhum novo ensaio decorre da recuperação Demo.

Este marco acrescenta **10 commits granulares**, incluindo este checkpoint,
totalizando **212**. Main exclusiva, AEGIS privado, push após cada commit. Código
finalfae9039, recibo/revisão02f94b4 e operação657187f; consultar git log/status para
hash/mensagem finais e sincronização, sem incorporar o próprio hash aqui.


## 2026-10-23 — Primeiro ciclo Demo após recuperação

### Entrega e decisões

[ADR0013](architecture/decisions/0013-recovered-demo-cycle.md) acrescenta
`make verify-recovered-cycle BACKUP_ID=...`: novo restore e inventário,
reconciliação, boot/probes em quarentena e, somente depois, API/worker/Redis
normais limitados ao clone offline. Comandos anteriores permanecem sem workers.
[Procedimento](operations/backup-recovery.md),
[recibo real](evidence/recovered-demo-2026-10-23/README.md) e
[revisão](security/review-recovered-demo-2026-10-23.md).

- RUNTIME_PERMISSIONS extraído sem mudar as 10 instruções/grants anteriores,
  compartilhado pela implantação normal e bootstrap recuperado. Nova role app
  sem administração/ownership e com restrições de auditoria/evidências preservadas.
- Bootstrap transacional com recibo exato/fences vazios, schema/PG17/catálogo Demo
  revisados. Nova conta administrativa/senha, lab inicialmente revogado e ativo
  sintético; sem seed que reautorize dados antigos. Baseline privada de hashes
  de todas as linhas reconciliadas, sem USAGE para runtime.
- API/worker normais e Redis novo só no namespace network=none do DB, sem portas/
  mounts persistentes/socket Docker/runner/SIEM. Imagens locais fixadas por ID,
  sem pull no ensaio; senhas SQL/Redis/conta via env temporário0600 ou stdin,
  não argv/intents/recibo. Redis loopback/autenticado sem save/AOF.
- Probe fixa destino interno e recusa configuração externa antes de I/O. Login
  novo, autorização lab nova, campanha/run nova, recusa sem aprovação e aprovação
  nova pelo hash. Worker processa os quatro testes Demo; confere eventos/evidências/hashes,
  classificações, indicadores e HTML/JSON. Nenhum agendamento criado.
- Lab revogado e sessão encerrada pela API; worker removido antes dos locks de
  fechamento. Conta nova desativada e verificados 1 run/4 testes/resultados sintéticos,
  aprovação própria consumida, nenhum dispatch, pendência/autoridade ou sessão.
  EXCEPT ALL de hashes exige todas as linhas antigas idênticas; estrutura public
  também comparada. Não reescrever scopes/resultados históricos.
- Intenções duráveis antes de cada create, ownership exato mesmo em resposta
  ambígua; cleanup worker→API→Redis→DB. Falha retém dependências/DB como
  retained_cycle_cleanup_unconfirmed, sem recibo final. Fonte/dump/manifesto,
  volumes e journals antigos não são alterados. Não há cutover.

Arquivos centrais: operations/runtime_grants.py/recovered_demo.py/
recovery_cycle_probe.py, cli.py, scripts/demo_backup.py/recovery_cycle_runtime.py,
Makefile e tests/test_recovered_demo_cycle.py/test_recovery_cycle_runtime.py.
Sem dependência, migração ou frontend novos. README/AGENTS/CHANGELOG, roadmap e
procedimentos atualizados para separar quarentena, reconciliação e ciclo novo.

### Validação e achados

Revisão especializada somente leitura não identificou bloqueador concreto de
SQL, destino, credenciais, baseline/histórico ou cleanup. Não executou testes,
Docker ou acesso a .local. Durante implementação, a extração inicialmente
esperava12grants, mas AST conferiu10 e nenhum arquivo foi alterado antes dessa
asserção; extração corrigida e comparada ao original. Uma fixture inicialmente
não importou o fixture de DB transitivo e o cliente usou base_url sem /api/v1;
ambos corrigidos, sem afrouxar autenticação, constraints ou permissões.

- Testes direcionados:14 casos API/worker/PG com role runtime temporário, acesso
  negado à baseline e DELETE protegido, ciclo real das funções do worker,
  fechamento, drift de histórico/autoridade e validação sintética;88 casos de
  lifecycle/CLI anteriores+novos incluindo create-before/after/start/probe/closure/
  ownership/cleanup e transporte dos segredos. Mocks só para Docker nessas falhas.
- `make test` final: **578 Python passaram**,154,62s; **35 frontend**,3,42s.
  Redis DB15 usado serialmente e limpas só chaves próprias. Bancos/papéis de
  recuperação/ciclo temporários remanescentes:0/0. Não foram lançadas duas suítes
  compartilhando DB15 em paralelo.
- `make lint` passou: Ruff/check/format 113 arquivos, mypy domínio 4 arquivos,
  TypeScript/Prettier. Aviso upstream Starlette TestClient/httpx permanece visível.
- Build separado passou; frontend da imagem veio do cache sem alteração. Imagem
  própria sha256:a2a0ace33b901bb89bb5ee044c12f20452f37a0d80363e09c1e0f679c6a41daf;
  Redis local sha256:3811787313eba226a2ef38658c6ccb91cd5e110edc89c37767de373120a0e5a0.
- Ensaio Docker real verify-recovered-cycle passou, 29,147 s (medição, não RTO):
  backup 20261022T210359Z-e689b5a47fa44a69b969a726982324de,30 tabelas/2.884 linhas
  originais; 2.885 após reconciliação; 3.000 ao final, todas as 2.885 anteriores idênticas
  e estrutura public preservada. Quarentena anterior com 9 rotas/4 escritas SQL/
  5 entrypoints/TCP administrativo bloqueados, API removida antes da fase normal.
- Nova run 2bb3840f-baeb-4148-b791-93674937a9fa COMPLETED/synthetic=true, 4 testes e uma
  classificação de cada DETECTED/OBSERVED_NOT_ALERTED/NO_TELEMETRY/INCONCLUSIVE.
  Evidências, report SHA256/HTML/JSON e delta 1 run/4 testes/3 válidos conferidos.
  Lab/conta/sessão novos encerrados; zero pendências. Worker, API, Redis e DB
  removidos; 3 recibos de cleanup dos filhos/0600 conferidos. Recibo público igual
  ao privado; dump/manifesto/segredos não publicados.
- Demo 18780 segue ready database/redis=true, sem rebuild/restart da imagem/API/
  worker em uso. Nenhum clone ou container Wazuh remanescente; 9 volumes/journals
  anteriores preservados. Sem nova execução Linux/Wazuh, consulta SIEM, renovação
  PKI ou alteração de serviços/redes/sysctl do host.
- 52 links locais da documentação alterada conferidos; scanner staged/diff-check
  em cada commit. E2E de browser não repetido porque UI não mudou; ensaio atual
  verifica API/worker/relatórios reais em Docker, sem atribuir novas capturas ou
  uma execução Firefox que não ocorreu.
- CI final: **SUCCESS**, head251b163,
  [run39997058403](https://github.com/Buraddomoon/AEGIS/actions/runs/39997058403),
  validate3m27s: **574 Python passaram/4 skip**, 35 frontend, lint/tipos/build e
  revisão de advisories. Os quatro skip são projeções opcionais de objetos Docker
  Demo já existentes; CI não os cria. Localmente578passaram. Advisory transitivo
  DiskCache revisado permanece visível, sem alegar zero achados Python. Commits
  seguintes só Markdown não mudam o código validado nem disparam nova CI.

### Limites e continuidade

Esse resultado demonstra um novo ciclo sintético em clone descartável, com
credenciais/autorizações novas. Não recupera roles/secrets/Redis antigos, PKI,
journals ou efeitos externos; não é recuperação entre hosts, failover, cutover,
RPO/RTO garantido ou ferramenta enterprise-ready. Autorização real Linux/Wazuh
continua consumida e nenhum novo ensaio decorre dessa entrega.

Backups criptografados/off-host, guarda de imagens/configuração e política de
retenção por ambiente seguem pendentes. Próxima evolução independente de
infraestrutura externa: atualização controlada/versionada do catálogo ATT&CK.
Mantêm-se Sigma backend/pipeline/mapping, PKI, Windows/archives, PDF e
multi-workspace no roadmap, sem anúncio de disponibilidade.

Este marco acrescenta **8 commits granulares**, incluindo este checkpoint,
totalizando **220**. Main exclusiva, AEGIS privado e push após cada commit. Código
final 2d10d92, recibo/revisão 251b163 e operação 0886768; consultar git log/status para
hash/mensagem finais e sincronização, sem incorporar o próprio hash aqui.

## 2026-10-23 — catálogo ATT&CK controlado e versionado

Escopo seguinte autorizado por “pode prosseguir”: remover a pendência de atualização
de catálogo de um banco populado, preservando evidências e decisões anteriores.
Nenhum novo ensaio Linux/Wazuh, consulta SIEM, instalação pesada, alvo externo ou
autorização ofensiva foi consumido. Política main/privado/commits granulares e push
direto mantida. ADR0014 define preparar→revisar→publicar, sem sincronização automática.

### Implementação

- Migration a0d9c7e21b45, após977fd0c42ae8:32tabelas, releases imutáveis com
  documento/hash canônico e origem/commit/hashes, singleton vigente e projeção
  AttackTechnique com flags oficiais/ausência/source_modified. IDs referenciados
  e metadados ausentes preservados; seed só adota legado conhecido e não
  sobrescreve release inicializada. Não inventa commit para snapshot antigo.
- CLI host-only prepare/plan/apply. HTTPS oficial numerado fixado por commit40hex,
  TLS validado, sem proxies/redirects/compressão, limites e prazo absoluto75s
  cobrindo headers/corpo. Cache0700/0600 exclusivo, rehash/renormalização no load.
  Normalização cobre perfil Enterprise, não validação STIX completa ou assinatura.
- Plano READ ONLY vincula destino/schema, base/projeção/candidato e impactos nos
  testes. Aplicação por hash exato e administrador ativo, locks NOWAIT e transação
  única incluindo auditoria. Bloqueia licença não revisada, downgrade, reescrita
  de versão oficial, identidades conflitantes, drift, ator/plano inválidos,
  concorrência e runs/reservas/agendamentos retomáveis. Repetição sem novos efeitos.
- API/worker não escrevem em catálogo nem precisam de UPDATE para locks de leitura.
  Scopes novos registram release e técnicas; retiradas/ausentes são recusadas.
  Worker rejeita contexto desconhecido/alterado antes de preparar/emitir efeitos,
  preservando cleanup. Nenhuma reescrita de allowlist, regras, scopes, aprovações,
  resultados, evidências ou relatórios JSON históricos.
- Cobertura atual exige mesma release/mode; histórico, tendência e percentual
  continuam históricos com denominadores explícitos. Contexto antigo desconhecido
  permanece desconhecido. Comparação explica mudança de catálogo sem causalidade.
- API autenticada somente leitura para proveniência, releases e snapshots.
  Matriz/tabela têm filtros de ciclo de vida, origem/hashes, histórico pesquisável
  e recarga; paginação/detalhe recusam troca de release. Sem botão decorativo
  de publicação. Catálogo não inicializado retorna status explícito/conflito409.

Arquivos centrais: aegis/catalog/{document,artifacts,store,api}.py,
scripts/update_attack.py, models/migration/seed/runtime_grants, services/worker/
queries/reporting/backup, AttackCatalog.tsx/Catalog.tsx e testes test_attack_*.
README/AGENTS/CHANGELOG/modelagem/API/roadmap/operação/testes atualizados.

### Fonte real e implantação

Fonte oficial consultada: Enterprise20.0 permanece atual; commit
c2494b29dd268c46a5d0ea0990553e4327cd2253,55.271.014bytes,
SHA25681113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352,
igual à origem do snapshot anterior. Licença idêntica à revisada. CLI prepare
real produziu candidato798dc8da9a8e2f7996894d11b5ec00211c2532a26da391a50d2c170b2b849844,
867referências:706ativas/149revogadas/12descontinuadas. Não é nova versão20→21
nem dado sintético; somente as execuções de validação são sintéticas.

Ensaio em schema PostgreSQL17 próprio: dois ciclos reais das funções do worker,
oito testes sintéticos, CLI plan/apply, relatório anterior idêntico pelo hash,
seed sem sobrescrita, reaplicação already_applied e duas releases preservadas.
Cobertura atual0 após publicação e3 após novo ciclo aprovado; histórico seis
válidos/dois detectados,33,3% nesse escopo. Comparação não equivalente; schema
removido e chaves próprias Redis13 limpas. Esse ensaio usa TestClient/funções;
processos separados são comprovados pelo E2E, sem atribuição falsa de transporte.

Demo em uso: antes977fd0c42ae8,20runs/zero pendências/reservas/planos retomáveis.
Backup20261023T185409Z-1ee667a8a3b6449299cfe4dfa8cbda2b criado e restaurado
em clone offline,30tabelas/2.884linhas idênticas/clone removido,5,264s medidos.
Imagens antigas preservadas em aegis-catalog-previous:demo-977fd0c42ae8 e
recovery-977fd0c42ae8. Somente API/worker próprios parados/recriados, sem parar
db/redis ou alterar serviços/rede/sysctl do host. Migration/seed/grants passaram.

Plano local revisado:161inclusões retiradas e apenas source_modified nas706ativas,
sem testes afetados ou bloqueadores. Publicado pela CLI com conta administrativa
temporária própria; API18780 autenticada confirmou nova release e leitura pelo
papel SQL restrito. Conta desativada, sessão encerrada, zero sessão temporária.
Vinte runs preservadas,26tabelas históricas idênticas ao backup, excluindo
mudanças esperadas de usuário/auditoria/schema/catálogo. Cobertura atual0;
histórico legado continua disponível sem versão de scope inventada. Nenhuma
campanha adicional foi executada no Demo em uso. Health database/redis=true.

Backup posterior20261023T185803Z-e24dc58921054fef8aa4fdab4b4a2caf verificado:
32tabelas/3.055linhas, clone sem rede removido,5,132s medidos. Dumps/manifestos,
backups antigos e nove volumes/journals Wazuh preservados; nenhum clone ou
container Wazuh remanescente. Isso não repete boot/reconciliação/ciclo completo
da imagem nova nem enfraquece exigência de schema compatível para backups antigos.
Imagem final Demo/recovery:
sha256:a160bed6dc12c3bd8c69df3ed6c86d7e4c061ee1e280d30524af06bb665471a4.
[Recibos curados e limites](evidence/attack-catalog-2026-10-23/README.md).

### Verificações e achados

Revisão especializada somente leitura encontrou dois achados médios: prazo HTTP
não abrangia headers e lock não incluía TestDefinition referenciada no plano.
Ambos corrigidos/testados; revisão final de3dc11a3 não identificou bloqueadores
na UI/escopos/erros. Não executou testes/Docker/rede nem acessou arquivos privados.
[Revisão](security/review-attack-catalog-2026-10-23.md).

Erros de implementação/ensaio tratados sem afrouxar controles: inferência de
tipos na paginação TypeScript, mock de resposta sem metadados e dialog sem
polyfill em jsdom; harness local recusou Redis com credencial por validação
textual e login sem X-Aegis-Request, corrigidos sem imprimir segredo. Uma CI
anterior recebeu conflito NOWAIT antes da exceção de integridade esperada,
compatível com manutenção de fundo. Fixture agora desabilita autovacuum somente
das tabelas de seus bancos descartáveis, antes do seed;71casos passaram e locks
de produção/conflitos explícitos continuam. Ajuste final de catálogo ausente
coberto por30casos de API/recuperação. Nenhum sucesso atribuído às rodadas falhas.

Primeira rodada completa:654Python/43frontend passaram. E2E Firefox passou:
API/worker separados,4runs/16testes sintéticos, consulta de proveniência e pesquisa
de snapshot histórico,11capturas reais/zero erros JavaScript/sem overflow móvel.
Snapshots das capturas são os distribuídos iniciais, não uma publicação oficial
fingida. Lint Ruff/format124arquivos, mypy domínio, TypeScript/Prettier e build
passaram. Aviso upstream TestClient/httpx e advisory transitivo DiskCache revisado
permanecem visíveis, sem alegação de zero vulnerabilidades.

Rodada final de3dc11a3: `make lint` passou; `make test` **655Python passaram**
em220,84s e **43frontend passaram** em3,27s. Total incremental77casos Python e8
frontend sobre o marco anterior, sem contar repetições como casos novos.
89links locais da documentação conferidos. Não houve duas suítes compartilhando
Redis15 ao mesmo tempo. E2E14/ensaio13 usaram destinos independentes; segredos/
artefatos privados não foram adicionados ao Git. Scanner staged/diff-check por
commit.

CI final **SUCCESS**, código3dc11a3,
[run40008263252](https://github.com/Buraddomoon/AEGIS/actions/runs/40008263252),
validate5m07s: **651Python passaram/4skip**,43frontend, lint/tipos/build e revisão
de advisories. Os quatro skip são projeções opcionais de objetos Docker Demo já
existentes; CI não os cria. Localmente655passaram. DiskCache5.6.3/PYSEC-2026-2447
permanece finding transitivo explicitamente revisado, sem alegação de zero
vulnerabilidades Python; npm reportou zero. Commit seguinte só Markdown não
altera o código validado nem dispara outra CI.

### Continuidade

Atualização administrativa local entregue; permanecem fora do escopo sincronização
automática, revisão web de publicação, outras matrizes e rollback de release.
Não é cobertura de segurança empresarial ou validação de toda versão futura de
STIX. Não houve nova autorização real Linux/Wazuh. Backups exigem guarda própria
de imagem/configuração e schema compatíveis; criptografia/off-host/RPO/RTO e
retenção por ambiente continuam pendentes. Sigma ainda precisa de backend/pipeline/
mapping oficialmente compatíveis; Windows/archives, PDF e multi-workspace seguem
no roadmap.

Próxima evolução independente de infraestrutura externa: filtros de cobertura
por período/release e relatórios comparativos com escopo/denominadores fixados.
Não remover o histórico de versão desconhecida nem inferir causalidade de mudança
de catálogo. Consultar git log/status para hash, mensagem, total e sincronização
finais do checkpoint, sem incorporar seu próprio hash neste arquivo.

Este marco acrescenta **17commits granulares**, incluindo este checkpoint,
totalizando **237**. AEGIS privado, main exclusiva, push após cada commit;
código final3dc11a3, recibos7e47e24 e documentação9cfad98. Sem branches/PRs,
force push ou reescrita de histórico. Árvore limpa/sincronização devem ser
conferidas após o commit final, sem supor sucesso antes do push.

## 2026-10-26 — cobertura por período/release e relatórios comparativos

Próxima etapa autorizada por “continua pra proxima etapa”. Entrega ADR0015:
somente leitura analítica/exportação, sem migração/dependência nova ou mudança
da engine/allowlist/aprovações. Schema a0d9c7e21b45/32tabelas preservado. Nenhum
ensaio Linux/Wazuh, nova autorização real, alvo externo ou coleta SIEM.

### Funcionalidades e contratos

- analytics.Selection: modo, all/current/legacy/release exata e período RFC3339
  com fuso, normalizado UTC, [from,before) pela data da solicitação. Limites
  abertos aceitos, intervalo vazio/invertido/sem fuso e release inválida recusados.
- Sessão própria REPEATABLE READ READ ONLY, SQL15s e limite5000runs sem truncar
  métricas. Referência atual resolvida no snapshot; histórica usa documento
  imutável. Legado tem catálogo/avaliação null, preservando IDs/resultados sem
  inventar versão. Contagens de estados/execuções separadas do denominador válido.
- Total/estados incluem todo recorte; taxa usa somente pais/filhos COMPLETED,
  DETECTED+OBSERVED_NOT_ALERTED+NO_TELEMETRY. Sem válidos: null, sem falso0%.
  Join reutiliza run já carregada, sem retransmitir scope inteiro por resultado.
- Rotas autenticadas /coverage, /coverage/runs, /coverage/report,
  /coverage/compare e /coverage/compare/report; /reports compartilha seleção,
  padrão Demo. Exportação30/min/usuário e auditoria por tipo/formato/hash.
  Comparação exige mesma campanha/IDs distintos, manifesto correspondente,
  filhos/resultados completos, scope íntegro/igual e contexto conhecido. Delta
  só quando comparável e ambos denominadores válidos, arredondando as frações.
- HTML/JSON agregados e comparativos autocontidos: membros/hashes, evidências,
  diferenças técnicas, resumo/denominadores/limitações e hash do documento
  entregue. HTML escapado, sem scripts/recursos externos; hash não é assinatura.
  Formato/integridade dos relatórios individuais preservados. Sem tabela fictícia.
- UI com aplicação explícita de filtros, conversão do horário local, seletores
  paginados completos, bloqueio de exportação por hash de escopo e comparação
  restrita à campanha. Erro/dirty/mismatch não habilita ações sobre cache antigo.
  Alteração de resultado não comprova causalidade, risco ou proteção empresarial.

Arquivos principais: analytics.py/analytics_api.py, queries.py/reporting.py/api.py,
CoverageFilters.tsx/CoveragePage.tsx, Operations.tsx/lib.tsx/types.ts, test_analytics_*
e test_analysis_export, UI coverage-filters/comparison e e2e.mjs. Documentação em
[coverage-reports](operations/coverage-reports.md), ADR0015, README/AGENTS/CHANGELOG,
API/roadmap/aceite/testes. Sem alteração de lockfiles ou controles de execução real.

### Revisão, erros e validação executada

Revisão especializada somente leitura encontrou três bordas: filhos falhos ou
sem resultado podiam sustentar comparação; filho individual ausente do manifesto
não era detectado; erro de refetch podia conservar ações sobre comparação antiga.
Corrigidos e conferidos novamente por inspeção, sem bloqueador restante. Regressões
de banco/UI passaram, sem alterar dados do ambiente real. Revisão não executou
testes, Docker/rede ou arquivos privados. [Detalhes](security/review-coverage-reports-2026-10-26.md).

Rodadas anteriores não foram consideradas sucesso. Fixture inicial omitiu
alerts_available e foi corrigida mantendo NOT NULL. Dois testes de invariância
precisavam excluir somente snapshot_at volátil, continuando a comparar todos os
fatos/métricas e a integridade de relatórios. Uma rodada posterior recebeu
NOWAIT em campaign_runs antes do bloqueador esperado, compatível com manutenção
das tabelas do schema de teste. Fixture agora desabilita autovacuum somente das
tabelas explicitamente qualificadas do seu schema descartável, antes do seed;
configuração/locks de produção e escritores concorrentes explícitos intactos.
E2E corrigiu espera pelas opções do seletor e o texto atualizado de não equivalência.

- Testes direcionados de seleção/fronteiras/offset, release histórica/legado,
  snapshot concorrente, escrita SQL negada, cap sem truncamento, export/hash/
  escape/misto/denominador vazio, RBAC e negativos de árvore/manifesto passaram.
- Rodada final: `make lint` aprovado, Ruff/format130arquivos, mypy domínio4,
  TypeScript/Prettier. `PYTEST_ADDOPTS=--maxfail=1 make test`: **688Python passaram**
  em299,10s e **53frontend passaram** em3,96s. A opção só interromperia em falha;
  todos os casos executaram. Incremento33Python/10frontend, sem somar repetições.
- Build passou; `make e2e` Firefox real aprovado: API/worker separados/schema
  descartável,4runs/16testes sintéticos,12capturas/zero erros JavaScript e390px sem
  overflow. Exportou recorte/par, validou membros/evidências/denominadores e
  aplicou legado/período vazio, além do fluxo anterior de agendamento/Sigma.
  Não houve duas suítes compartilhando Redis15 ao mesmo tempo; E2E usa14.
- CI **SUCCESS**, código1e62a3f,
  [run40351257873](https://github.com/Buraddomoon/AEGIS/actions/runs/40351257873),
  validate5m52s: **684Python passaram/4skip**,53frontend, lint/tipos/build/auditoria.
  Skip são projeções opcionais de objetos Docker Demo preexistentes, não criados
  na CI; localmente688passaram. Aviso upstream TestClient/httpx e DiskCache5.6.3/
  PYSEC-2026-2447 revisado permanecem, sem alegação de zero vulnerabilidades Python.
  Commits posteriores somente Markdown não alteram código nem disparam CI.

### Implantação e dados preservados

Antes de atualizar o Demo18780:21runs, zero pendências/reservas/agendamentos
retomáveis, administrador humano ativo. Backup privado
20261026T153138Z-da45ceb4b6d748e0b66a5c0a0d8514a1 restaurado/verificado:
32tabelas/3.160linhas, clone offline removido,6,792s medidos, sem promessa de RTO.
Imagem anterior a160bed6... preservada em aegis-coverage-previous:demo-20261026.
Somente API/worker próprios recriados; db/redis e volumes mantidos. Migration/seed/
grants passaram sem mudar revisão/schema. Imagem Demo/recovery:
sha256:ef97abfdf122df5bd513f7a6e2a44c7ec84a3b89757e1698d04da0f0f8871a02.

Smoke real autenticado com viewer temporário: exports HTML/JSON recalculados por
hash, erro409 para referência incorreta e403 na auditoria administrativa; papel
SQL runtime operacional.21runs/84resultados mantidos:20legadas,1release atual,
63válidos/21detectados,33,3% exclusivamente sintético. Legado preserva versão
desconhecida e comparação antiga não sustenta delta.30tabelas históricas iguais
ao manifesto anterior, exceto mudanças esperadas em users/audit_events; registro
completo do admin humano, incluindo hash da senha, idêntico antes/depois. Logout,
desativação do viewer e zero sessões temporárias conferidos. Não foi criada nova
campanha/run no Demo em uso, nem usado/resetado o login humano no smoke.
Health database/redis=true. [Recibo curado](evidence/coverage-reports-2026-10-26/README.md).

### Pendências e continuidade

Este marco não entrega PDF, geração agendada de relatórios, snapshots analíticos
exportáveis persistidos, outros workspaces ou escala acima do limite. Nenhum
novo controle ofensivo/defensivo foi implantado. Sigma backend/pipeline/mapping,
Windows/archives e rotação PKI seguem pendentes; não inferir cobertura empresarial.
Próximo bloco: backups criptografados, retenção e recuperação, mantendo destino
externo/configuração/custos sujeitos às informações e autorização próprias.

Este marco acrescenta **14commits granulares**, incluindo o checkpoint,
totalizando **251**. Privado/main exclusiva e push por commit, sem branches/PRs,
force push ou histórico reescrito. Consultar git log/status para hash/mensagem
final, árvore limpa e sincronização efetivamente concluída após o push.

## 2026-10-26 — em desenvolvimento: backups criptografados

Próxima etapa autorizada por “prossiga”. ADR0016 fixa age/X25519 com dependência
opcional host-only, chave separada, artefatos privados e verificação pela mesma
restauração offline existente. Retenção só plano; sem upload, exclusões, mudanças
no Demo ativo ou novo ensaio Linux/Wazuh. Implementação e testes ainda pendentes;
não declarar cópias cifradas/recuperação validadas antes de executar os checks.

### Concluído — cópia cifrada local e recuperação verificada

ADR0016 implementado. Chave de backup separada, age v1/X25519 em streaming com
pyrage 1.4.0 fixado por hash; extra backup/dev host-only, fora do lock/imagem da
aplicação e sem import na API/worker. Framing fixo sem tar/path importado,
manifesto até 4 MiB/conteúdo até 1 GiB, diretórios 0700/arquivos 0600 e publicação
exclusiva após fsync. Nenhuma migração, frontend ou mudança da engine ofensiva.

CLI acrescenta keygen, seal, verify-sealed e vault-plan; Makefile oferece
backup-tools, backup-keygen, seal-backup, verify-sealed-backup e backup-vault-plan.
verify-sealed exige hash esperado independente e identidade por ID, autentica
stream inteiro e verifica SHA/count dos bytes consumidos antes de materializar
manifesto/dump. Reutiliza a mesma validação/inventário/restore offline existente,
sem acessar banco/dump fonte ou permitir destino/SQL/container arbitrário.
Sucesso durável somente após remover clone e staging privado.

Inventário cifrado somente leitura: integridade, recibos vinculados ao mesmo
ciphertext e presença de chave local válida. Mínimo de sete snapshots distintos
verificados/com chave e trinta dias; cópias não verificadas/incompletas ou sem
chave preservadas. Re-selagem não verificada não altera a ordem/idade dos bons.
Não existe exclusão ou transferência. Recibos são registros locais editáveis,
não assinatura, prova de posse independente ou nova restauração.

Arquivos principais: apps/api/aegis/operations/vault.py, scripts/demo_backup.py,
test_backup_vault.py/test_backup_cli.py, requirements-backup.lock, Makefile e
scanner staged. Documentação operacional em
[encrypted-backups](operations/encrypted-backups.md); README, AGENTS, changelog,
licenças, segurança, testes, aceite e roadmap atualizados. Git/build ignoram
.agekey/.age e scanner recusa identidades age; nenhum artefato privado entrou no Git.

### Revisão, correções e checks

Revisão especializada somente leitura encontrou dois achados, corrigidos e
conferidos novamente por inspeção: hash prévio no mesmo FD não evitava troca
in-place por outro ciphertext válido; e a data de re-selagem não verificada podia
influenciar a retenção de snapshot com outra cópia boa. CipherReader e seleção
apenas de datas verificadas/com chave resolvem esses casos; regressões reproduzem
ambos. Nenhum outro bloqueador concreto relatado. O revisor não executou testes,
Docker, rede ou acesso a .local/.env. [Revisão](security/review-encrypted-backups-2026-10-26.md).

Um teste novo de retenção falhou corretamente ao mostrar que dez cópias não
verificadas podiam deslocar o único backup bom; implementação corrigida para
contar apenas snapshots elegíveis. Falha não anunciada como sucesso. Depois,
regressão adicional cobriu re-selagem do mesmo ID entre mais de sete backups bons.

- 21 casos vault usam age real: roundtrip, segredo não exibido, chave/hash
  errados, corrupção/header/final/truncamento/extra, limites, symlink/hardlink/
  FIFO/permissões, exclusividade, corrida de leitura e retenção read-only.
- Cinco casos novos de CLI verificam staging autenticado, nenhum fallback,
  recusa de backup alterado e ausência de falso recibo após erro de restore/
  cleanup. Guardas Docker anteriores mantidas; mocks não comprovam runtime.
- Primeira suíte completa passou com 712 Python/53 frontend. Rodada final após
  os dois casos adicionais: **714 Python passaram em 243,53 s e 53 frontend
  passaram em 3,29 s** (`PYTEST_ADDOPTS=--maxfail=1 make test`). Incremento de 26
  casos Python sobre o marco anterior; não somar repetições como casos novos.
- `make lint` passou: Ruff/format 132 arquivos, mypy domínio, TypeScript/Prettier.
  `make build` passou. Auditoria runtime+extra passou com o advisory transitivo
  DiskCache/PYSEC-2026-2447 explicitamente revisado, sem alegação de zero findings;
  extra pyrage não apresentou advisory Python conhecido nessa consulta.
- CI **SUCCESS**, código 59c02f9,
  [run40361995268](https://github.com/Buraddomoon/AEGIS/actions/runs/40361995268),
  16:45:35–16:51:29 UTC, 5 min 54 s: **710 Python passaram/4 skip opcionais**,
  53 frontend, lint/tipos/build e auditoria. Skip são projeções somente leitura
  de objetos Docker Demo ausentes na CI; localmente os 714 passaram.
  Commits seguintes somente Markdown não alteram código nem repetem a CI.
- 164 links locais conferidos; 303 arquivos tracked revisados por caminhos e
  padrões de credenciais, zero ocorrência. Scanner staged/diff-check por commit.
  Aviso upstream TestClient/httpx permanece. Nenhuma suíte Redis15 em paralelo.
  E2E navegador não repetido: nenhuma mudança de UI/API/worker; evidências do
  marco anterior permanecem, sem capturas inventadas.

### Prova local e preservação

Novo backup privado: 20261026T164137Z-9c0d7d0bebc54d8cb25a5898d96acafc,
dump SHA256 30e1e84387b0b1da4ce2becc756ed3b1d3ed6bd2345bcea195bf05a951500af5.
Cópia age de 1.318.864 bytes, SHA256
fe8a7491de6d5d2aefb746f5663ec529f59f5d6f06b1d98b34b5bf04c3259f52.
Verificação real: **32 tabelas/3.169 linhas**, estrutura/hashes iguais,
PostgreSQL17 por image ID local, network=none/tmpfs/sem portas/volumes/API/worker.
Restore/inventário/cleanup em 4,682 s, clone removido; não é medição de RTO.

Harness privado proibiu loader do dump original e consulta da fonte durante a
recuperação cifrada. Inventário completo do banco em uso, incluindo usuários e
hashes de senha, idêntico antes/depois; nenhuma credencial humana usada/resetada.
Zero staging após saída; recibo durável só depois desse cleanup. Chave privada
nova nunca exibida/argv/Git; continua separada em diretório privado no host.
[Recibo curado e limites](evidence/encrypted-backups-2026-10-26/README.md).

API/worker não reiniciados; imagem Demo/recovery permanece
sha256:ef97abfdf122df5bd513f7a6e2a44c7ec84a3b89757e1698d04da0f0f8871a02.
Schema a0d9c7e21b45/32 tabelas, 21 runs preservadas, zero pendências/reservas/
agendamentos retomáveis. Administrador humano ativo e senha inalterada; site18780
saudável. Zero clones de recuperação, schemas pytest/E2E e bancos temporários
remanescentes; autovacuum do public intacto. Backups antigos, imagens e nove
volumes/journals Wazuh preservados. Nenhuma nova simulação Linux/Wazuh ou SIEM.

### Continuidade e versionamento

O usuário escolheu **“Vou decidir depois; concluir a proteção local”** para o
destino externo. Entrega local concluída; não fazer upload, compra de serviço ou
exportação de chave sem definição própria. Chave/ciphertext no mesmo computador
não protegem contra perda/comprometimento do host. Originais permanecem em claro;
scratch privado pode deixar resíduo após SIGKILL e unlink não é secure erase.

Guarda independente, recuperação entre hosts, roles/secrets/configuração/imagens,
retenção operacional por ambiente, cutover e RPO/RTO continuam pendentes. Não
reescrever ou apagar backups/journals antigos. Rotação PKI Linux/Wazuh precisa
escopo/revisão próprios; autorizações anteriores continuam consumidas. Sigma
backend/pipeline/mapping compatíveis, Windows, PDF e multi-workspace permanecem
roadmap. Próximo bloco local: revisão final de release/portfólio, consolidando
instalação, critérios realmente aceitos e limitações, sem iniciar novo lab real.

Este marco acrescenta **13 commits granulares**, incluindo este checkpoint,
totalizando **264**. Repositório privado confirmado, main exclusiva, push após
cada commit, sem PR/branch/force push ou histórico reescrito. Código final59c02f9,
recibo/revisão fea228d. Consultar git log/status para hash/mensagem finais e
confirmar árvore limpa/sincronização depois do commit de checkpoint.

## 2026-10-26 — consolidação de entrega concluída

Continuidade autorizada por “prossiga”, após o usuário adiar custódia externa e
concluir a proteção local. Repositório privado/main conferido em 28a5443, árvore
limpa no início. Este marco mantém o código 0.2.0 e não cria tag/GitHub Release.

### Entregas verificáveis

- Corrigida a configuração inicial: o gerador não recusava arquivos existentes
  inseguros e preservava segredos vazios/exemplos. Agora abre por FD sem seguir
  links/bloquear em FIFO, verifica owner/tipo/nlink/modo0600/64KiB e lock, recusa
  entrada incompleta/duplicada sem echo de valores. Configuração válida preservada;
  histórico sem APP_DB_PASSWORD recebe somente esse segredo, com newline correto.
- Scanner staged ganhou --all para todo o índice Git e nomes NUL-delimitados;
  não lê conteúdo ignorado/não rastreado e nunca imprime valores de possíveis segredos.
- `make release-check`: versões Python/React/lock, dependências declaradas na raiz
  do lock npm, destinos relativos inline Markdown e cabeçalhos/dimensões PNG.
  Usa índice Git e informa divergência de HEAD/worktree; não valida links externos/
  âncoras/procedência de pixels nem comprova ausência de segredos ou instalação.
- Workflow documental sem dependências/bancos, permissões read, timeout 2 min e
  cancelamento de redundantes. CI principal completa permanece ativa para código.
- README reorganizado ao redor do fluxo reproduzível e tabela de capacidades/limites;
  galeria documenta 12 capturas Demo e uma histórica Linux, sem fabricar imagem Wazuh.
  Corrigidos textos operacionais antigos que ainda descreviam o SIEM como bloqueado
  e o adapter como exclusivamente Demo. Revisões históricas/evidências preservadas.

Não há nova abstração runtime/dependência/migração: ferramentas host-only seguem
as fronteiras já definidas. API/worker/runner e contratos de detecção inalterados.
[Procedimento de entrega](operations/release.md),
[evidência e limites desta rodada](evidence/source-delivery-2026-10-26/README.md) e
[revisão local de segurança](security/review-delivery-2026-10-26.md).

### Verificações realmente executadas

| Check | Resultado |
|---|---|
| Novos grupos pytest | 15 init_env + 6 repository_checks + 9 release_check passaram; 30 casos incluídos na suíte final |
| `make test` |**744 Python passaram** em 256,64 s e **53 React passaram** em 3,52 s |
| `make lint` | Ruff/check/format, mypy domínio, TypeScript e Prettier aprovados |
| `make build` | SPA aprovada, sem aviso de chunk>500kB |
| `make audit` | npm: zero; Python: um advisory DiskCache/PYSEC-2026-2447 revisado e visível |
| `pip check` | Sem requisitos quebrados |
| Configuração nova temporária | 0600/idempotente; Compose renderizado com cinco serviços, API 127.0.0.1:18780, DB/Redis não publicados, papéis SQL distintos e nenhum runner/coletor habilitado; nenhum serviço iniciado |
| Índice Git final | 312 arquivos, 77 Markdown, 204 links locais e 13 cabeçalhos PNG aprovados; padrões de credenciais/paths sem ocorrências |
| Ambiente em uso | API live/ready: 200; schema a0d9c7e21b45, 32 tabelas incluindo Alembic, 21 runs existentes, zero pendências/reservas/agendamentos retomáveis |

CI principal do código 88e8c10: **SUCCESS**,
[run40392713839](https://github.com/Buraddomoon/AEGIS/actions/runs/40392713839),
740 passed / 4 skipped opcionais Docker, 53 React, lint/tipos/build/auditoria.
Localmente os quatro testes opcionais passaram. CI documental 5ef9ad3: **SUCCESS**,
[run40394072412](https://github.com/Buraddomoon/AEGIS/actions/runs/40394072412).
Commits posteriores só documentam evidência/progresso. Aviso upstream
Starlette/TestClient/httpx preservado; não alegar zero vulnerabilidades.

Não repetido E2E: UI/fluxo inalterados; último Firefox real continua sendo o marco
de cobertura de 2026-10-26. Overview/coverage existentes foram inspecionados, sem
modificar PNGs. Não reconstruída/reimplantada imagem runtime: segue
sha256:ef97abfdf122df5bd513f7a6e2a44c7ec84a3b89757e1698d04da0f0f8871a02.
Site http://localhost:18780 saudável, sem reiniciar API/worker ou mudar credenciais
humanas. Zero schemas pytest/E2E restantes; autovacuum public intacto. Linux/Wazuh
com zero containers; volumes/journals e backups/chaves anteriores preservados.

### Continuidade

Custódia externa continua adiada pelo usuário; não enviar cópia/chave, comprar
serviço ou interpretar conclusão local como proteção contra perda do host.
Recuperação entre hosts/configuração/secrets/imagens/cutover/RPO/RTO, retenção de
laboratórios, rotação PKI/binding, Windows e PDF continuam pendentes.

Próximo incremento funcional sugerido: pesquisar novamente constraints oficiais
Sigma/backend/pipeline e validar uma opção compatível num ambiente de testes,
sem conversão anunciada antes da prova e sem implantação/ensaio Linux/Wazuh.
As autorizações anteriores de laboratório continuam consumidas. O MVP e seus
incrementos comprovados não equivalem ao cumprimento de todo o master prompt.

Este marco acrescenta **8 commits granulares**, incluindo este checkpoint,
totalizando **272**. Somente main, repositório AEGIS privado, push após cada commit;
sem PR/branch/force push ou reescrita. Código 88e8c10, evidência 5ef9ad3. Conferir
hash/mensagem finais, árvore limpa e sincronização após o push deste documento.

## 2026-10-26 — prévia Sigma entregue no Demo

Continuidade após pergunta sobre o que falta para fechar o produto e autorização
para seguir. Base e0e44ba, main limpa/sincronizada, repositório privado confirmado.
Pesquisa oficial atual confirmou o bloqueio real: OpenSearch 2.0.3 / Elasticsearch 2.1.1
continuam exigindo pySigma<2, enquanto o core da aplicação permanece 2.0.1. SHA dos
wheels e METADATA conferidos iguais ao snapshot anterior; nenhum backend instalado,
constraint ignorada ou parser reduzido. Conversão SIEM continua pendente.

### Incremento funcional

- [ADR0017](architecture/decisions/0017-sigma-mapping-preview.md): prévia independente
  com ProcessingPipeline/FieldMappingTransformation oficiais, um rename fixo por
  perfil, modelo novo apenas em memória e invariância de valores/estrutura/condição.
- Política plana de strings literais, condição única e limites antes do parser;
  modificadores/fieldref/keywords/nesting/unknown fields e custom/pipeline/vars não
  entram no subconjunto. YAML/preflight seguros anteriores continuam obrigatórios.
- GET de versão/hash/perfil com viewer, rate 30/min, erros estáticos e documento
  inteiro por SHA; unsupported sem before/after. Não modifica versão, scope,
  relatório, cobertura ou veredicto; nenhum flag de conversão/consulta/implantação
  ou mapping físico é habilitado. Perfil candidato/hash anteriores inalterados.
- UI em Regras → Preparação de conversão → Gerar prévia de campos. Antes/depois
  reais; recusa de contexto/contrato/flags divergentes, resposta atrasada e cache
  após erro. Conversão bloqueada continua explícita.
- Smoke Compose verifica a prévia positiva no papel SQL runtime e só seleciona
  laboratório autorizado de kind=demo/synthetic=true. Nada inicia um lab real.

Arquivos: sigma_mapping.py, endpoint em api.py, MappingPreview.tsx/RuleReadiness.tsx,
types.ts, testes Python/UI e harness e2e/smoke. Sem dependência, migração ou mudança
na engine/worker/contratos de execução. Versão do código continua 0.2.0.
[Evidência detalhada](evidence/sigma-mapping-2026-10-26/README.md) e
[revisão de segurança](security/review-sigma-mapping-2026-10-26.md).

### Verificação

| Check | Resultado |
|---|---|
| Novos testes | 35 domínio/pipeline + 7 API + 13 UI; incluídos na suíte final |
| `make test` |**786 Python passaram** em 306,72 s e **66 React passaram** em 3,63 s |
| Lint/build/audit/pip check | Aprovados; npm: zero; um advisory DiskCache conhecido/revisado e visível; aviso TestClient/httpx preservado |
| Guard novo em processo | Core/pipeline reais sem cache/backend/rede/subprocessos/gravações; loaders de pipeline proibidos |
| Firefox E2E | 4 runs / 16 testes sintéticos, 13 capturas e zero erros JS, relatório histórico idêntico e modal em 390 px sem overflow |
| Docker | Build próprio e troca só de API/worker, sem recriar DB/Redis/migrate; health ready: 200 |
| Smoke da imagem final | Prévia/hash/histórico, SQL restrito, análise/preparação, manual+agendado, grant/revoke, 8 resultados sintéticos e relatórios aprovados |
| Backup pré-deploy | 32 tabelas / 3.169 linhas restauradas em clone offline; hash/estrutura iguais e cleanup confirmado |
| Fonte/Git | 321 arquivos, 80 Markdown, 218 links locais e 14 cabeçalhos PNG; sem achados nos padrões/paths rastreados |

CI final executável d5982a9: **SUCCESS**,
[run40398531188](https://github.com/Buraddomoon/AEGIS/actions/runs/40398531188),
782 passed / 4 skipped opcionais Docker e 66 React, lint/tipos/build/auditoria. Os quatro
opcionais passaram localmente. Commits posteriores só atualizam docs/capturas.
A execução remota redundante 70b5499 foi cancelada pela política de concurrency.

Revisão especializada adicional somente leitura do código 283c544 não encontrou
bloqueador concreto: rename/invariância, flags desabilitados, ownership/SHA e
contexto da UI conferidos. O revisor não executou testes, serviços, rede ou SIEM
e não leu segredos; não é pentest independente nem garantia de ausência de falhas.

Corrigidos dois problemas de fixtures: import normaliza whitespace, portanto a
invariância usa conteúdo efetivamente salvo; /api/v1 não pode casar a versão v1
do teste de resposta atrasada. Falhas iniciais não foram contadas como pass.
E2E repetido após ajuste de enquadramento da captura e teste do modal 390 px; ambas
as rodadas passaram, sem efeitos fora dos schemas descartáveis. Galeria agora
com 13 imagens Demo e uma Linux histórica; PNGs inspecionados e sem dados empresariais.

### Implantação local e continuidade

Imagem API/worker atual:
sha256:ec57c8c9177fa8a4a8a5141bb958ed86e6bcf245f003dcb2f7972ea34a5d0314.
Anterior ef97abf preservada em aegis-before-sigma-mapping:20261026 e na tag
recovery; não apagar imagens necessárias aos dumps anteriores. Guard pré-deploy
confirmou zero jobs/reservas/agendamentos retomáveis. Nenhuma senha/configuração
humana alterada; administrador ativo e mesmas credenciais em http://localhost:18780.

Banco mantém a0d9c7e21b45 / 32 tabelas e 23 runs: 21 anteriores mais duas do smoke, todas
as novas sintéticas. Conta temporária desativada/plano revogado, zero pendências,
reservas ou planos retomáveis; schemas pytest/E2E removidos, autovacuum public
intacto. Linux/Wazuh com zero containers; nove volumes/journals anteriores preservados.
Nenhum alvo externo/SIEM consultado e nenhuma nova simulação real.

Backup 20261026T204444Z-b85ee5892de445f08a99c18a3e28e5b2, dump SHA256
2253cab121564ccd2d2e9e36ab0fca44bbd9be0a095a6d00c69e8e9e65ce02f4:
verified, 32 tabelas / 3.169 linhas, network=none, application_started=false,
clone_removed=true em 4,752 s. É backup privado em claro; não equivale a criptografia
ou recuperação operacional do destino. Cópia/chave cifradas anteriores preservadas;
custódia externa continua adiada, sem upload/compra/novo destino.

Pendências reais para fechar a operação: backend/pipeline completo compatíveis e
mapping físico/consulta validados sob escopo; rotação PKI/binding/recuperação dos
laboratórios; recuperação entre hosts/configuração/secrets/imagens/cutover/RPO/RTO
e custódia independente. Windows/PDF/outros provedores/multi-workspace continuam
expansões. Próximo incremento local sugerido: rotação/verificação de certificados
como operação offline revisável, sem reiniciar labs ou reaproveitar autorizações.

Este marco acrescenta **10 commits granulares**, incluindo este checkpoint,
totalizando **282**. main exclusiva, GitHub AEGIS privado, push após cada commit;
sem PR/branch/force push ou reescrita. Código/harness d5982a9, evidência 283c544.
Conferir hash/mensagem finais, árvore limpa e sincronização após o push final.


## 2026-10-27 — preparação offline da rotação mTLS do runner

Continuidade do incremento iniciado em2026-10-26, base e234b61, main exclusiva,
GitHub Buraddomoon/AEGIS privado confirmado. Escopo cumprido sem ativação de
certificados, start de laboratório, consulta SIEM ou novas autorizações reais.

### Funcionalidades e decisões

- ADR0018 e scripts/runner_pki.py: inspect/prepare/verify host-only, contratos por
  SHA canônico revisado e candidato privado separado. Geração aditiva em
  init_linux_lab.py preserva três UUIDs, endpoint e nomes de secrets.
- Somente cinco arquivos públicos lidos da origem; nenhuma chave antiga,
  ids.env ou diário. Duas CAs/quatro pares novos/distintos, cadeias/purpose/EKU/
  SAN/IP/CN/P-256/pares e validade real verificados. Origem expirada pode ser
  inventariada explicitamente; candidato exige agora e >=24h restantes nas folhas.
- OpenSSL fixo com ambiente mínimo e política padrão do sistema preservada;
  sem biblioteca nova, proxy, shell, dependência de banco/Docker/rede ou apply.
- Arquivos limitados/owner/permissões, sem symlinks/hardlinks/FIFO; fsync dos
  artefatos e diretórios/ancestrais privados inclusive retry. Erro não emite recibo
  de sucesso; resíduos privados podem permanecer, inclusive manifesto final.
- .key ignorado por Git/Docker e recusado no scanner; comandos Make e runbook
  documentados. Sem migração, UI/API novas, mudança de versão ou imagem runtime.

[Operação](operations/runner-pki.md),
[evidência](evidence/runner-pki-2026-10-27/README.md) e
[revisão](security/review-runner-pki-2026-10-27.md).

### Verificação e problemas resolvidos

| Check | Resultado |
|---|---|
| `make test` final | **839 Python passaram** em271,12s e **66 React passaram** em3,58s; quatro opcionais Docker incluídos |
| Novos casos | 52 PKI, incluindo três TLS echo loopback, mais um scanner .key; todos incluídos no total |
| `make lint` | Ruff/format143arquivos, mypy4arquivos, TypeScript e Prettier aprovados |
| `make audit` / pip check | npm zero; DiskCache5.6.3/PYSEC-2026-2447 conhecido/revisado e visível; requirements consistentes |
| Fonte | 329 arquivos,84Markdown,233links locais e14cabeçalhos PNG; scanner completo/release-check aprovados |

Aviso de depreciação Starlette/TestClient-httpx preservado. Build foi aprovado
no CI; não houve novo deploy, captura ou E2E porque não há mudança UI/API/runtime.
Prova offline e TLS loopback não são execução de laboratório real.

CI executável d6d49ad: **SUCCESS**, 835 Python / quatro skips Docker opcionais,
66 React, lint/tipos/build/auditoria;
[run40409355739](https://github.com/Buraddomoon/AEGIS/actions/runs/40409355739).
Commits posteriores só documentam operação/evidência/progresso e usam CI leve;
source-review bda2afc passou. Execuções intermediárias de código redundantes
canceladas por concurrency, sem repetir instalação/build remoto por docs.

Revisão especializada encontrou fsync de ancestrais incompleto e depois retry
incompleto após falha. ecb4713/a57f5da corrigiram ambos, com regressões; revisão
estática final confirmou resolução sem bloqueador concreto no delta. Não é
pentest. Fixture hardlink inicialmente tocava candidato compartilhado; corrigida
para cópia local antes do link e casos repetidos passaram. Falhas iniciais não
foram contadas como aprovação. Sessão da suíte anterior ficou sem recibo recuperável
após continuação; a rodada final foi executada novamente e registrada em log local.

### Prova e estado operacional

Candidato real90204499ca2144aca175fe809538b7e7 criado fora da origem, manifesto
SHA24179f34ad0a2c708496e9b0b3798a18d547c4648975c95893330458f0ed8d5f.
Prepare/verify sob audit hook restrito e nova verificação em2026-10-27 passaram:
offline_candidate_verified_not_activated, todas as flags de ativação/banco/diário/
lab/operação normal false. IDs/endpoint preservados, descritor mudou; bytes
públicos e metadados dos originais intactos. Folhas originais servidor/cliente
expiradas permaneceram assim; não declarar rotação aplicada. Candidato tem validade
curta e deve ser reverificado ou substituído por outro candidato antes de uso.

Demo localhost18780 ready, database/redis true, API/worker ainda na imagem
ec57c8c9177fa8a4a8a5141bb958ed86e6bcf245f003dcb2f7972ea34a5d0314.
Leitura READ ONLY confirmou schema a0d9c7e21b45,32tabelas,23runs e zero runs
não terminais/reservas/agendamentos retomáveis. Nenhuma senha humana alterada.
Linux/Wazuh sem containers, nove volumes históricos preservados. Sem novo efeito,
cleanup de evidências, imagens/backup removidos ou acesso a outros alvos.

### Pendências reais e continuidade

Entregue somente preparação offline. Ativação coordenada dos dois lados mTLS,
revisão/binding/preflight com descritor novo e recuperação de jobs sob vínculo
alterado continuam pendentes. Não converter recibo offline em autorização: jobs
ambíguos mantêm quarentena; preservar IDs/volume/diário sem replay ou reserva
liberada manualmente. PKI Indexer/manager/agente/Filebeat não foi rotacionada.

Também permanecem: backend/pipeline Sigma completos oficialmente compatíveis e
mapping físico/consulta validados sob escopo, recuperação entre hosts/configuração/
secrets/imagens/cutover/RPO/RTO. Custódia externa adiada pelo usuário, sem upload
ou compra. Windows/PDF/outros provedores/multi-workspace são expansões do roadmap.
Próximo passo da PKI: preparar um plano de ativação concreto com validade atual,
preservação do journal e revisão do binding; qualquer start/troca ativa/ensaio
precisa de escopo específico próprio e não reutiliza as autorizações consumidas.

Este marco acrescenta **10 commits granulares**, incluindo este checkpoint,
totalizando **292**. main exclusiva, push origin/main após cada commit, privado;
sem branch/PR/force/rebase. Código final d6d49ad; conferir hash/mensagem finais,
árvore limpa e sincronização após push deste checkpoint.


## 2026-10-27 — revisão segura de vínculo e preparação da ativação coordenada

Base f42bfed. Entregue API/UI administrativa de revisão persistida, reforço das
três mutações Linux/Wazuh e serialização de novas solicitações Linux. Rotação
física continua sem ativação; nenhum novo ensaio, marcador ou consulta SIEM.

### Funcionalidades, arquivos e decisões

- `binding_review.py`: predicado compartilhado exige Linux revogado, sem reserva,
  pais/filhos pendentes ou dispatch sem confirmação terminal íntegra de cleanup.
  Confere hashes/spec/geração/recibo/IDs/marker, sem reparar dados históricos.
- `GET /labs/{id}/binding-review`: administrador,30/min, snapshot próprio
  REPEATABLE READ READ ONLY/15s. Até1.000 dispatches, excesso bloqueia;
  amostra25 e contagem dos examinados explícitas. Sem runner/diário/ativação.
- `linux_labs.register`, `telemetry.bind/unbind` recalculam o predicado sob lock.
  `services.request_run` Linux adquire lab lock/populate_existing antes do scope,
  impedindo criar pedido após revogação usando leitura anterior.
- `BindingReview.tsx`/Management: pendências reais na tela administrativa,
  contexto/flags conferidos e sucesso cacheado ocultado após erro/refetch.
  Cadastro/revisão de isolamento e cancelamento continuam ações explícitas.
- ADR0019, comando `make test-binding-review`, runbook e plano coordenado de
  secrets/volumes, sem executor de ativação. Sem dependência/migração/versão nova.

[Operação](operations/linux-binding-review.md),
[plano a implementar](operations/runner-pki-activation.md) e
[evidência/revisão](evidence/binding-review-2026-10-27/README.md).

### Testes e problemas encontrados

| Verificação | Resultado observado |
|---|---|
| Rodada completa local |882 Python/79 React passaram;314,96s/3,93s; quatro opcionais Docker incluídos |
| Suíte nova depois dos cinco casos adicionais |48 passaram/33,20s;887 casos Python distintos exercitados e coletados no estado final |
| Linux/Wazuh dirigidos |70 passaram/90,79s antes dos cinco últimos casos, somente fixtures |
| `make lint` |Ruff/format145 arquivos, mypy4, TypeScript e Prettier aprovados |
| `make e2e`/build |Firefox PASS,4 runs/16 simulações Demo, zero browserErrors, SPA compilada |
| CI bdb31c1 |SUCCESS:883 Python/quatro opcionais Docker pulados/79 React; lint/tipos/build/auditoria |

[CI40513069341](https://github.com/Buraddomoon/AEGIS/actions/runs/40513069341).
Aviso Starlette/TestClient-httpx e advisory DiskCache5.6.3/PYSEC-2026-2447 conhecido
continuam visíveis; npm sem vulnerabilidades na auditoria do CI. Nenhuma alegação
de ausência geral de vulnerabilidades. Capturas novas privadas; galeria histórica
publicada preservada, sem commit de binários redundantes.

Revisão especializada encontrou a janela de criação sem lab lock; corrigida e
coberta por concorrência PostgreSQL real. Revisão estática final sem bloqueador
concreto no delta, sem pentest. Teste antigo de remoção Wazuh precisava exigir409
com pedido pendente e depois cancelar explicitamente antes de remover; reexecução
passou. Verificador do deploy supunha apenas not_linux no Demo; havia também
laboratory_authorized. Expectativa ajustada e GET repetido, sem mudar laboratório.

### Estado operacional e proteção local

Demo localhost18780 ready/database/redis true. Apenas API/worker atualizados para
sha256:92ffbc4e1de7f47aa6f6e53636cf3a3d9e153cf869228e669f8263368bcaff7d.
Imagem anterior ec57c8c preservada em aegis-before-binding-review:20261027;
DB/Redis não recriados. Schema a0d9c7e21b45/32 tabelas, mesmas23 runs, zero runs
não terminais/reservas/agendamentos retomáveis. Consulta live autenticada200,
blocked/not_linux+laboratory_authorized, sem gravação de auditoria pelo GET;
logout401. Duas contas temporárias desativadas, zero sessões próprias; credenciais
humanas preservadas. Nenhum laboratório/diário/evidência real alterado.

Backup pré-deploy20261027T133323Z-45b5e62652f24170b4fd16035c268162, dumpSHA
b78d9528476e49899edb1583afda190ed58c8a487b2330ba02ba8ef7e914e7fb,
restore verificado32 tabelas/3.390 linhas em5,759s, clone network=none removido e
sem aplicação. Backup privado em claro; não é nova cópia cifrada nem cutover.
Cópias/chaves/imagens anteriores preservadas; custódia externa continua adiada.

Linux/Wazuh permanecem sem containers; volumes históricos preservados. Candidato
PKI90204499ca2144aca175fe809538b7e7 reverificado offline com mesmo manifesto,
ainda sem ativação. Validade curta exige nova conferência antes de qualquer uso.
Um schema pytest antigo1405a560…58a, com contas/runs de2026-10-26T22:06:33Z, foi
identificado no inventário final e preservado; não assumir vazio global nem fazer
DROP automático de resíduo cuja proveniência não foi acompanhada neste marco.
Não é run/reserva ativa da aplicação. Detalhes e limites na evidência.

### Pendências e próximo passo

Implementar harness opt-in da troca coordenada com hash/perfil/imagens exatos,
inventário de volume/banco Linux parado e encerramento verificável, conforme o
plano. Só depois propor escopo específico de ensaio sem marcador. Recuperação
de jobs sob descritor alterado continua em quarentena; autorizações consumidas
não são reutilizadas. PKI Indexer/manager/agente/Filebeat continua separada.

Permanecem backend/pipeline Sigma completos compatíveis e mapping físico/consulta
validados, recuperação entre hosts/configuração/secrets/imagens/cutover/RPO/RTO e
custódia independente adiada. Windows/PDF/outros provedores são expansões.

Este marco acrescenta **10 commits granulares**, incluindo este checkpoint,
totalizando **302**. main exclusiva, GitHub AEGIS privado e push após cada commit;
sem branch/PR/force ou reescrita. Código de produção99b6758/c6fc456, casos finais
bdb31c1, evidência1531990. Conferir hash/mensagem, árvore limpa e origin/main
depois do push deste checkpoint; CI de código já aprovado, docs usam source-review.

## 2026-10-27 — harness de planejamento da ativação Linux

Base8acbf3a/302 commits. Entregue ferramenta host-only executável plan/recheck,
sem iniciar Linux/Wazuh, abrir banco/diário original, aplicar PKI ou executar
marcador/campanha. Este incremento prepara um gate concreto do executor futuro,
sem apresentar ativação como implementada.

### Implementação e decisões

- `scripts/runner_activation_metadata.py`: consultas Docker em catálogo fechado,
  Unix local, config vazia/env mínimo, projeções sem Config.Env/inspect bruto,
  limite agregado64KiB/10s e kill/reap do filho em falha. Exige zero containers
  inclusive parados/redes do projeto, zero consumidores dos volumes, labels/
  local/options/datas coerentes e quatro imagens locais distintas por ID.
- `scripts/runner_activation.py`: perfil Linux integrado172.30.88.2/API18785,
  PKI/hash antes/depois, descritores/IDs preservados e Compose por hash. Plano
  exclusivo0600/diretório0700/fsync; recheck exige hash canônico independente,
  política exata, material/metadata iguais e TTL15min antes/depois. Não altera
  fontes ou planos anteriores; erros não publicam recibo de sucesso.
- ADR0020, Make plan/recheck/test-runner-activation, AGENTS/runbook/README/roadmap
  atualizados. Nenhuma dependência/migração/endpoint/frontend novo ou deploy.
  Flags de autorização/banco/diário/mounts/rede/proveniência/ativação/operação
  normal false e oito gates pendentes explícitos; não há apply/lifecycle.

[Contrato](operations/runner-pki-activation.md),
[ADR0020](architecture/decisions/0020-runner-activation-plan.md) e
[evidência completa](evidence/activation-plan-2026-10-27/README.md).

### Testes, inspeção real e problemas encontrados

`make test-runner-activation`: **82 passaram/45,90s**. `make test-runner-pki`:
**52 passaram/28,90s**. Total134 casos dirigidos executados neste incremento,
sem somar rodadas repetidas. PKI real temporária, TLS echo loopback, fixtures
Docker e filhos Python para timeout/limite/reap; nenhum laboratório iniciado.
969 casos Python coletados no estado final; coleta não significa execução local
de todos eles. Lint completo aprovado: Ruff/format149 arquivos, mypy4, TypeScript
e Prettier. Aviso upstream Starlette/TestClient-httpx permanece visível.

Primeira consulta real recusou imagem PostgreSQL cujo Config.User era ausente.
Projeção corrigida com index/campo opcional; quatro regressões mantêm UID10001
obrigatório da API/runner, aceitando default root apenas nas imagens DB/cache.
Consulta repetida passou, sem enfraquecer os controles. Revisão arquitetural
especializada somente leitura não encontrou bloqueador concreto; não é pentest.

Plan real3f38362663b840009d3149cfd113c83b, hash
f7324e0999595546fcdfb3b43e4617c8938eb035f5b6bf9981773716300abee6;
recheck2026-10-27T14:20:06.673617Z aprovado somente como metadados.
Expiração14:34:27.588950Z, sem renovação implícita pelo registro desta prova.
Mesma PKI candidata90204499ca2144aca175fe809538b7e7 reverificada, sem ativação.
Volumes Linux journal/postgres-data com labels/data/local confirmados e sem
consumidores; nomes/metadados não comprovam conteúdo ou fences. Imagens/IDs,
limites e recibo privado estão na evidência, sem chaves ou credenciais publicadas.

CI final de código/Make d05a00f **SUCCESS**:
[run40520616501](https://github.com/Buraddomoon/AEGIS/actions/runs/40520616501),
965 Python passaram/quatro projeções Docker opcionais puladas/351,09s;79 React
passaram, além de lint/tipos/build/advisory review. DiskCache5.6.3/PYSEC-2026-2447
conhecido continua revisado e visível; npm sem achados nessa auditoria, sem alegação
de ausência geral de vulnerabilidades. CI de entrega b3e639a também SUCCESS;
redundantes canceladas conforme concurrency. E2E/frontend não foram repetidos
localmente porque não houve mudança do produto em execução; ver marco anterior.
Revisão final de fontes:343 arquivos/90 Markdown/262 links/14 cabeçalhos PNG e
scanner do índice aprovados, sem equivaler a pentest ou prova geral de segredos.

### Estado e próxima etapa

Demo localhost18780 continua ready/database/redis true, imagem API/worker92ffbc4e…
preservada. Sem restart/build/pull/seed/migração, conta nova ou mudança de senha.
Zero containers Linux/Wazuh, volumes/journals/backups/chaves/imagens históricos
intactos; schema pytest antigo não removido. Custódia externa continua adiada,
sem upload/serviço pago. GitHub AEGIS privado, somente main e push após cada commit.

Próximo: implementar o executor com intenção/ownership/cleanup duráveis e gates
do banco/diário Linux originais, mounts/isolamento/mTLS, registro ainda revogado
e encerramento verificável; manter worker parado. Só então apresentar escopo
específico para autorização real, sem reutilizar ensaios consumidos. Plano atual
não permite marcador e não libera jobs ambíguos sob descritor alterado. Wazuh PKI,
backend Sigma completo/mapping físico, recuperação entre hosts e custódia externa
continuam pendências separadas; Windows/PDF/outros provedores são expansões.

Este marco acrescenta **7 commits granulares**, incluindo este checkpoint,
totalizando **309**. Código ab662e0/27ea2db, contrato/Make d05a00f e evidência
b3e639a. Conferir hash/mensagem finais, árvore limpa e origin/main após o push;
nenhuma branch temporária, PR, force push ou reescrita de histórico.

## 2026-10-27 — continuidade, ownership durável e reconciliação somente leitura

Basebd4404e/309 commits. Continuação automática em três unidades verificáveis,
sem encerramentos intermediários do trabalho. Nenhum Linux/Wazuh iniciado,
marcador/campanha novo, troca de mounts/PKI ou leitura interna dos volumes reais.
Não houve deploy/restart/migração/seed, novas contas ou alteração de senhas.
Compactação é controlada pelo ambiente; este checkpoint permite retomada sem
afirmar que um comando /compact foi executado.

### Componentes entregues

1. **Continuidade banco/diário** — `continuity.py`, `persisted_review.py` e
   `journal_probe.py` em apps/api/aegis/lab_runner. Snapshot PG próprio READ ONLY/
   REPEATABLE READ15s, binding antigo exato, revogação/ociosidade, predicadoADR0019
   e todas as provas CLEANED conhecidas por hash. SQLite só em cópia privada DB+
   WAL, SHM reconstruído no scratch, lock/arquivos/schema/integridade/identidade/
   jobs/recibos/gerações/eventos. Probe fixo /state, stdin4MiB/hash, saída sem
   conteúdo dos jobs e import sem settings/modelos SQL/engine/server/rede/processos.
2. **Ownership durável** — `scripts/runner_activation_intents.py`, catálogo
   fechado sem worker/migrate/controller/Wazuh/volumes; nomes/labels derivados,
   eventos exclusivos0600/0700/hashchain/fsync, lock cooperativo e retomada por
   ID/hash. Histórico parcial bloqueia; publicação incerta invalida sessão.
   API incerta retém DB/cache/runner; containers incertos retêm redes. Novos
   dependentes são recusados durante/depois da remoção, inclusive após resume.
3. **Observador de ownership** — `scripts/runner_activation_ownership.py`, cruza
   nome, owner composto ID:papel e ID anterior; inspect de nome/ID/cinco labels
   exatos e repetição das listas. Uma label evita pressupor AND/OR de filtros
   repetidos. Nome parecido bloqueia, sem limpeza aproximada. Nunca interpretar
   erro como ausência; só consultas projetadas/Unix local/config/env isolados,
   10s/64KiB compartilhados. Nenhum lifecycle ou autorização é implementado aqui.

ADRs0021/0022, AGENTS, Make, README/changelog/roadmap/aceite/testing/runbook
atualizados. [Evidência completa](evidence/journal-continuity-2026-10-27/README.md).
`test-runner-continuity` usa PG/SQLite temporários; `test-runner-activation` inclui
plan/metadados/intents/ownership. Nenhum dos targets inicia laboratório real.

### Validação executada e problemas corrigidos

- `make test-runner-continuity`: **104 passaram/9,60s** (65 continuidade,
  30 PG/bundle e9 probe). DML de regressão foi rejeitado pelo PostgreSQL read-only.
- Rodada global `pytest -q`: **1.073 passaram/364,68s**, antes dos novos testes
  de intents/ownership. Quatro projeções Docker opcionais leram só objetos Demo
  existentes, sem criar recursos. Demais schemas/fixtures/temporários conforme
  contratos existentes, sem abrir o banco Linux original.
- `make test-runner-activation` final: **184 passaram/34,37s** (82 existentes,
  52 intents e50 ownership). **1.175 casos Python distintos exercitados localmente
  em rodadas distintas**, sem somar reruns; coleta final também confirmou1.175.
- Lint completo aprovado: Ruff/format159 arquivos, mypy4, TypeScript e Prettier.
  Aviso upstream TestClient-httpx permanece. Frontend/build/E2E não repetidos
  localmente por ausência de mudança nesses fluxos; CI valida frontend/build.
- Revisão de fontes356 arquivos/93Markdown/278links/14 cabeçalhosPNG e scanner
  do índice completo aprovados; não equivalem a pentest ou ausência de segredos.

Revisão especializada estática encontrou restart implícito seguido de falha/retry
de cleanup recusado pelo leitor; corrigido com teste do writer real temporário,
somente prepare/intent RUNNING, nunca start/supervise. Teste de import em processo
novo encontrou settings indireto no decoder; imports SQL restritos ao collect.
Revisão de ownership encontrou novo dependente após pedido de remover dependência;
bloqueio cobre caminho direto e retomada. Ajustes confirmados por nova leitura,
sem bloqueadores adicionais concretos, sem alegação de pentest.

Consulta real somente leitura do observador: nove papéis absent_snapshot,
nonceb46cbcbd00404c87a942062db5f8386d, em2026-10-27T17:00:17.687401Z;
reciboSHA bb5ca450e5603b996d2714c158714bc4a8d2743cce71b167fc90d5bb4c2dd6eb,
privado0600/pai0700, hash/permissões reconferidos. Sem recursos/intent real criado,
sem volume aberto. Isso valida listas ausentes; templates de inspect de objetos
presentes continuam só com fixtures e exigem ensaio autorizado futuro.

CI final de código fc5da3d **SUCCESS**:
[run40546471235](https://github.com/Buraddomoon/AEGIS/actions/runs/40546471235),
**1.171 Python passaram/quatro projeções Demo opcionais puladas/320,97s** e
**79 React passaram/12 arquivos**, além de lint/tipos/build/advisory review.
DiskCache5.6.3/PYSEC-2026-2447 conhecido continua revisado e visível, sem alegação
de ausência geral de vulnerabilidades. CI source-review8dc9fae também SUCCESS;
redundantes canceladas por concurrency. Logs completos privados em
.local/pki-milestone/ownership-code-ci-result.log; nenhuma evidência/confidencial
bruta foi adicionada ao Git.

### Estado preservado e sequência seguinte

Demo localhost18780 continua ready/database/redis true; imagens/contas/credenciais
humanas inalteradas. PKI/candidatos/planos, journals/volumes/backups/imagens e
evidências históricos preservados; nenhum schema antigo foi limpo. Plano3f3836…
expirado não foi reusado; PKI exige nova conferência de validade, sem inferir >=24h
de uma prova passada. Custódia externa permanece adiada, sem upload ou serviço pago.

Próximo: integrar componentes a executor de lifecycle **fixo/opt-in** com intenção
antes dos efeitos, query de ownership e prova de mounts/rede/UID/limites/imagem;
verificar banco/journal Linux originais e mTLS novo sem marcador, registrar binding
explicitamente ainda revogado e encerrar recursos com ausência verificada. Worker
parado, sem migrate/seed/smoke/efeito implícito. Só após ter harness completo e
reviewable apresentar escopo específico para nova autorização real; não pedir
aprovação de implementação incompleta nem reutilizar ensaios consumidos. Jobs
ambíguos seguem em quarentena, sem replay ou liberação manual de reserva.

Permanecem PKI de serviços Wazuh separada, backend/pipeline Sigma completo/mapping
físico compatível, recuperação entre hosts/config/secrets/imagens/cutover/RPO/RTO
e custódia independente adiada. Windows/PDF/outros provedores são expansões.

Este incremento acrescenta **13 commits granulares**, incluindo este checkpoint,
totalizando **322**. main exclusiva e GitHub AEGIS privado, push após cada commit.
Código de continuidade92901e9/1bf7d87/b3833f3/ca75231, intentsf2250ef, casos/contrato
6fd1f1f e observadorfc5da3d; evidências8760feb/8dc9fae. Conferir hash/mensagem
finais, árvore limpa e origin/main após publicar; sem branches/PR/force ou reescrita.

## 2026-10-27 — runtime fixo dos probes, start intent e cleanup por ownership

Baseb502080/322 commits. Continuação automática em unidades conectadas, sem
interromper ao fim de cada componente. Não houve novo ensaio Linux/Wazuh, abertura
interna de volumes originais, marcador/campanha, troca de PKI/binding, build/deploy/
migração/seed, criação/parada/remoção Docker ou mudança de credenciais humanas.

### Implementado e limites

- `runner_activation_probe_runtime.py`: receita fechada journal-before/after,
  Python isolado/módulo fixo, imagem por ID, UID10001, rede none, /state read-only/
  nocopy e limites. Revisão de imagem sem VOLUME declarado e runtime projetado:
  mounts efetivos/configurados, argv/UID/imagem/namespace/limites/estado/ownership.
  Ambiente só key/boolean por allowlist sem duplicatas, loader ou overrides.
- `probe_start_requested` no intent durável: só probe observado, hashes de receita/
  gates/bundle, sem replay após retomada. `ActivationIntents.review` reconfere
  histórico/estado/lock antes de efeito externo, sem acrescentar evento.
- `runner_activation_probe_result.py`: decoder estrito/bundle/descritor/identidade/
  flags/contagens/hash e comparação de inventário lógico completo, inclusive jobs
  adicionais. Piso/teto derivam dos estados conhecidos e restarts implícitos.
- `runner_activation_cleanup.py`: driver concreto interno stop SIGTERM/5s e rm por
  ID completo. Durabilidade/ownership/imagem antes de efeito, reconciliação de
  erro ambíguo por consultas, retenção de dependências e ausência final repetida.
  Sem force/volumes/global delete; driver real não foi aplicado a recurso algum.

ADR0023, AGENTS, Make, README/changelog/roadmap/aceite/testes/runbook atualizados.
Sem dependência/migração/endpoint novo. Não há CLI apply, create/start/transporte
de bundle ou coordenador completo. Bibliotecas internas não autorizam abrir os
volumes nem provar mTLS/registro revogado. [Evidência](evidence/probe-runtime-2026-10-27/README.md).

### Verificação e correções

Revisão especializada estática encontrou loader override possível apesar de -I;
corrigido por allowlist projetada sem valores. Consulta real de metadados mostrou
LANG ausente na imagem Python (receita agora o define, runtime exige) e Mounts
opcional no HostConfig (index). Regressão opcional só lê DemoAPI existente.
Revisão do resultado encontrou contagens impossíveis para job conhecido SUCCEEDED;
piso/teto por estado corrigidos e seis casos de writer/probe SQLite temporário
acrescentados. Deltas reconferidos por leitura, sem alegação de pentest/runtime real.

- Suíte global local: **1.352 passaram/376,43s**, antes do último ajuste e seis
  casos. Cinco projeções opcionais somente sobre objetos Demo existentes.
- Target final `make test-runner-activation`: **367 passaram/28,32s**; inclui o
  decoder corrigido e todos os seis novos casos. **1.358 casos distintos locais
  em rodadas separadas**, sem somar reruns. Aviso TestClient/httpx permanece.
- Lint completo aprovado: Ruff/format165 arquivos, mypy4, TypeScript/Prettier.
  Frontend/build/E2E não repetidos localmente por ausência de mudança nesses fluxos;
  CI código6d4174a ainda em andamento, sem tratar execução pendente como sucesso.

Consulta real somente leitura: recibo91aa6eaa5bc34447b49a7fe970e14a8e,
2026-10-27T18:08:57.725953Z, SHA canônico
8aaee0e5025f25ac1ad3e8c916140737a3e77594025a3d6f28dc2a92ff38b53e.
Arquivo0600/pai0700/hash reconferidos/fsync. Projeção completa parseada no DemoAPI
existente e metadados da imagem runner local; sem valoresEnv/Source físico e sem
afirmar runtime do probe ou proveniência/código atual da imagem. Demo continua
ready/database/redis true, imagemAPI92ffbc4e… inalterada. PKIs/volumes/journals/
backups/imagens/histórico preservados; custódia externa permanece adiada.

### Próximo trabalho real

Conectar os componentes a coordenador fixo opt-in: create/start com transporte
limitado do bundle, plano/escopo/imagens/proveniência atuais, vínculo físico do DB
Linux e revisão persistida, journal antes do construtor Runner, novo mTLS/recusa
de trust antigo sem confundir expiração, registro ainda revogado e encerramento
verificado. Worker parado, sem migrate/seed/smoke/marker. Só depois do harness
completo apresentar escopo específico para nova autorização; ensaios consumidos
não são reutilizados. Plano antigo expirado, PKI exige nova conferência; jobs
ambíguos continuam em quarentena, sem replay/liberação manual de reservas.

Este registro acrescenta **10 commits**, incluindo este arquivo de evidência,
totalizando **332**. main exclusiva/push após cada commit/repositório privado;
nenhuma branch/PR/force. Código635dc41/3c99f95/c261a03/99ebd4a/fcb41cf e correção
final6d4174a; target/projeçãoad75285, contrato2123901 e docs6f822c9. Conferir hash
final/sincronização e registrar o resultado final do CI no próximo checkpoint.

### Fechamento da validação deste incremento

CI código6d4174a **SUCCESS**:
[run40557124921](https://github.com/Buraddomoon/AEGIS/actions/runs/40557124921).
**1.353 Python passaram/cinco projeções Demo opcionais puladas/409,50s**,
**79 React passaram/12 arquivos**, lint/tipos/build577ms/advisory review.
DiskCache5.6.3/PYSEC-2026-2447 conhecido permanece revisado/visível, sem alegação
de ausência geral de vulnerabilidades. Fontesfe82f67 **SUCCESS**, run40557736451;
redundantes canceladas por concurrency. Logs completos privados em
.local/pki-milestone/probe-runtime-code-ci-result.log, sem dados brutos no Git.

Revisão local de fontes/scanner completo aprovados para364arquivos/95Markdown/
284links locais/14cabeçalhosPNG; isso não equivale a pentest ou ausência de segredos.
Este fechamento acrescenta o **11ºcommit deste incremento**, totalizando **333**.
Mensagem: `docs(progress): checkpoint verified probe runtime and cleanup validation`.
Conferir hash final, main limpa e origin/main após push; repositório AEGIS privado.
PKIs/planos/volumes/journals/backups/imagens e credenciais preservados. Sem novo
ensaio, deploy ou alteração de configurações humanas. Próxima unidade continua
sendo o coordenador fixo de create/start/transporte e gates físicos/mTLS/binding;
não declarar rotação operacional concluída nem reutilizar autorizações consumidas.

## 2026-10-27 — continuidade sem encerramento entre marcos: lifecycle dos probes

Basee377a4b/333 commits. O usuário reiterou continuidade automática; regra registrada
em AGENTS. Marcos passam a ser comunicados em commentary, com checkpoint durável e
sequência imediata de trabalho. /compact é recurso controlado pelo ambiente, sem
ferramenta para o agente invocá-lo; não foi simulado um comando executado.

Implementado componente interno de create/start para journal-before/after:
recipe/imagem/ownership/runtime/intents/decoder/cleanup conectados, sem endpoint
ou CLI apply. Callback confiável obrigatório vincula contexto/escopo/receita/bundle/
identidade/descritor e checks completos, UTC/idade<=10s/validade<=30s. O coordenador
real precisa computar os gates; fixtures não são autorização ou prova operacional.
Start intent e última revisão precedem RPC; ambiguidade não repete create/start.

Transporte compartilhado Unix local saneado agora suporta stdin privado4MiB,
drain simultâneo stdout/stderr, saída total64KiB e prazo<=20s com kill/reap; consultas
read-only continuam DEVNULL. Rejeita tipos/prazos indevidos. Testes substituem CLI
Docker por filhos Python pequenos, sem executar Docker de lifecycle real.

Cleanup selecionado deixa intent pai aberto, respeita dependências e não toca
outros recursos. CONFLICT persiste colisão vista antes da tentativa de create;
retomada/cleanup não adotam nem removem o objeto, não há desbloqueio automático.
KeyboardInterrupt aciona cleanup próprio e é propagado, sem recibo falso de sucesso.

Validação: `make test-runner-activation` **430 passaram/42,75s** no código676f636:
base367 +21 transporte +6 cleanup selecionado +4 conflito +32 lifecycle. Revisão
especializada somente leitura não encontrou bloqueador concreto; lembrou atualizar
estado documental de create/start, corrigido. Nenhum driver real, Linux/Wazuh,
volume interno, PKI/binding, build/deploy/migração/seed ou credencial foi alterado.
CI código676f636 em andamento no momento do checkpoint, sem declarar sucesso;
run40562305626. Redundantes canceladas pela política de concurrency.

Este checkpoint é o **6ºcommit** desdee377a4b, totalizando **339**; cinco anteriores:
04a26cd/c9f38aa/23d6c97/0d6e494/676f636. main exclusiva e push após cada commit.
Não encerra o trabalho. Próxima unidade já em desenvolvimento: metadados de operação
com recursos próprios presentes, consumidor exclusivo do journal, inventário fixado
e bloqueio de recursos estrangeiros. Código em trabalho separado ainda não deve
ser apresentado como validado antes de seus testes. Depois: recheck de plano ativo,
origem física PG, mTLS/binding e coordenador completo antes do escopo de novo ensaio.

## 2026-10-27 — checkpoint ativo de metadados e plano, continuidade imediata

Desde0b59aa9/339: e44e6ee entrega inventário sem inferir quiescência e revisão
durante operação com ownership durável;1eed10e conecta essa revisão à PKI/Compose/
inventário do plano original e ao ID/SHA do intent. Recheck CLI público permanece
quiescente; novo componente é interno e não aceita exceções de recursos por API.

Snapshots de todos os membros do projeto/nomes reservados/consumidores de volumes,
incluindo parados e consumidores de outros projetos, precisam coincidir com os
IDs/nomes/cinco labels/imagens próprios. Runner/outcome ambíguo/CONFLICT/remoção
impedem novo efeito. Prazo absoluto20s, por query com orçamento restante, comparação
repetida e releitura durável final. Flags SQL/volume físico/proveniência/rede/
autorização continuam falsas. load_plan preserva hash/política/TTL sem daemon;
active_plan revalida inputs e TTL depois do último IO. Nenhum lifecycle real.

Testes locais: **28 metadados ativos** e **14 plano ativo** passaram, além das
34 regressões do plano quiescente. Target ampliado final: **472 passaram/57,60s**.
Ruff/format172 arquivos passaram nesse marco. Revisão especializada encontrou
prazo não abrangendo IO final: corrigido/regressão inicial+final. Integração inicial
expôs fixture hardcoded em planlabela64 (nove falhas); derivação do SHA real do
intent corrigiu a fixture sem afrouxar guardas,42 casos passaram depois.

CI de1eed10e **SUCCESS**, [run40564482908](https://github.com/Buraddomoon/AEGIS/actions/runs/40564482908):
**1.458 Python passaram/cinco projeções opcionais puladas/508,58s**,
**79 React passaram/12 arquivos**, build636ms e lint/tipos/advisory review.
DiskCache5.6.3/PYSEC-2026-2447 conhecido permanece revisado e visível. Log completo
privado em .local/pki-milestone/active-plan-code-ci-result.log. Não é ensaio real
nem prova de ausência geral de vulnerabilidades. CI redundante cancelado.

Este checkpoint é o **9ºcommit** desdee377a4b, totalizando **342**. main exclusiva,
GitHub privado/push direto após cada commit, sem branch/PR/force. Não houve novo
Linux/Wazuh, leitura interna de volumes, marcador/campanha, troca PKI/binding,
build/deploy/migração/seed ou alteração de credenciais humanas; originais preservados.

Continuação já em andamento: leitor PostgreSQL fixo em loopback no namespace DB,
senha por stdin e contexto público separado, sem destino/settings livres. Perfil
e schema precisam ser conferidos NA MESMA sessão RR/READONLY da coleta, com locks
antes do snapshot, sem RLS/herança/views/tipos incompatíveis. Revisão encontrou
TOCTOU de duas conexões e correção foi implementada/testada em schemas PG próprios;
esse código ainda está em trabalho e terá checkpoint próprio. Depois: transporte
privado do bundle, runtime físico/proveniência e harness completo antes de novo
escopo autorizado. Nenhum fim de etapa encerra automaticamente o trabalho.

## 2026-10-27 — leitor PG fixo, snapshot único e provas privadas; trabalho segue

Desde82bf8a3/342:1a5cf77 acrescenta modo interno de raízes à revisão, preservando
escopo padrão da API;38c7987 conecta hook/perfil/coleta no mesmo snapshot protegido;
f03a4f8 entrega persisted_probe e ADR0024;f745f31 oferece cap privado4MiB sem ampliar
limite64KiB das consultas. Este checkpoint é o **14ºcommit** desdee377a4b, total347.

Leitor não oferece URL/SQL/host livre, settings fallback ou PG* ambiental. Apenas
loopback5432/aegis/aegis_app/public/PID1/UIDGID10001 com pipe. Senha só stdin16KiB,
excluída do contexto público; sem argv/env/log. Role não elevada, PostgreSQL17,
read-only/RR/schema/search_path e ausência de temporários conferidos. Catálogos
exigem tabelas ordinárias/SELECT/cols/types/nullability e sem RLS/herança. Sem
consulta a alembic_version, grant ou migração. Provas<=4MiB incluindo newline,
emitidas só depois de dispose; nenhuma saída parcial/segredo em erros.

Revisão especializada encontrou TOCTOU entre conexão do perfil e coleta. Agora
ACCESS SHARE ONLY/NOWAIT nas sete tabelas vem antes do primeiro SELECT, e hook
recebe a MESMA conexão/snapshot da coleta. RLS/type/replacement DDL fica bloqueado;
row_security=off faz erro em vez de filtragem, sem bypass/controle global alterado.
AS não congela todo DDL: teste real anexou childQUEUED depois do guard, leitura
semONLY o vê e collector estrito ignora expansão das relações verificadas. API
binding padrão continua contando child pendente (regressão própria). Nenhum modo
de raízes é recebido por endpoint público nem usado para contornar schema inválido.

Verificação: **52 testes persisted_probe** passaram/4,36s, **31 persisted_review**
passaram/10,68s; rodada final com binding: **132 passaram/49,23s**. Inclui catálogos/
DDL revertido/mesmo backend/ALTER RLS bloqueado55P03, DDL prévio recusa antes do
snapshot, hookDML rejeitado25006 e herança tardia. Transporte+metadata: **78 passaram/
1,22s**,30 transporte/48metadata, com perfis64KiB/4MiB e limites/tipos arbitrários
recusados. Testes usam PG/schema próprio/fixtures de endpoint e filhos Python;
nenhum Linux original/namespace de produção/driver real foi validado.

Suíte global em andamento sobre basef745f31, log privado
.local/pki-milestone/persisted-probe-global-tests.log; não declarar aprovação antes
de finalizar. Nenhum ensaio Linux/Wazuh, leitura interna de volumes, novo marcador,
campanha, build/deploy, troca PKI/binding ou credencial humana. Só DDL próprio em
schemas pytest, revertido/removido; dados e configuração originais preservados.

Continuação imediata: runtime/driver fechado do leitor no namespace do DB próprio,
captura0600 do bundle, imagem/proveniência e harness completo de revisão sem
simulação antes de solicitar nova autorização. PGSQL read-only não torna PGDATA
read-only: startup escreve metadados operacionais e precisa de escopo explícito.
Sem iniciar o lab para resolver implementação incompleta nem reaproveitar aprovação.
PKI/mTLS/registro revogado da rotação continuarão separados do primeiro diagnóstico.

## 2026-10-28 — runtime e captura privada dos leitores PostgreSQL; continuação automática

Baseeb39b4e/347confirmada privada e sincronizada. Suíte global daquele código:
**1.526 Python passaram/372,42s**, um aviso Starlette/httpx conhecido. Não é ensaio
real; log privado .local/pki-milestone/persisted-probe-global-tests.log.

Desde o checkpoint:ca8bdc4 acrescenta dois papéis de leitura com dependência durável
do DB, start contextual sem senha/sem replay e cleanup antes do namespace pai;
f1c9b12 extrai inspeção de processo;d8c1459 implementa perfil físico/inspeção;
82302cf corrige formatação de assertion após rename;97c0e0d captura provas privadas.
Este commit estende recheck ativo aos leitores e bloqueia probes simultâneos;
será o **6ºcommit** desdeeb39b4e, total **353**. main/pushdireto/repoPRIVATE mantidos.

Leitor deriva namespace do DB OBSERVED próprio; não recebe IDdestino/endereço
livre, mount ou segredo em argv. Configexata:PID1/UIDGID10001/rootRO/capdropALL/PNP,
256MiB/0,5CPU/16PIDs/tmpfs16MiB,semports/init/logs;imagem semVOLUME/EXPOSE/PG*.
Ownership DBrunning/leitor repetido antes/depois e durável inalterado. Gates de
volume físico/isolamento DB/HBA/SQL/proveniência/autorização ainda separados falsos.

Captura host fixa identidade+descritor, request16KiB/passwordstdin,reply4MiB sem
ampliar64KiB dos metadados. Parser recusa duplicatas/contexto/flags inconsistentes.
Artefato fora dos intents,0700/0600/O_EXCL/O_NOFOLLOW/fsync/releitura;falha preserva
resíduos,sem sobrescrita/retry automático. Recibo só hashes/contagens, nuncaprovas.
Reload exigeSHAindependente e recusa links/permissões inseguras.

Verificação: **166 testes** intents/cleanup/rechecks passaram22,74s; **130 testes**
regressão runtime/lifecycle de diário passaram0,96s; **195 testes** leitor+diário
passaram1,41s; **96 testes** captura+runtime passaram0,76s; **89 testes** rechecks+
captura passaram26,56s. Rondas parcialmente sobrepostas, não somar como testes únicos.
Lint/formatação/tipos locais passaram. CI d8c1459falhou só no formatter da assertion
renomeada; corrigido em82302cf, sem alegar sucesso remoto antes da execução final.
Source-review97c0e0dSUCCESS; CI código97c0e0d ainda pendente na última consulta.

Sem Docker lifecycle/build/deploy,leitura interna dos volumesoriginais,SQLdoLab,
Linux/Wazuh/marcador/campanha,PKI/binding/migração/seed ou credencialhumana alterada.
Testes somente fixtures/filhosPython/SQLite temporário; globals anteriores usaram
schemasPGdescartáveis. DB runtime e seus templates ainda não foram ensaiados.

Continuação imediata: driver fechado do leitor com gates frescos, captura e cleanup
em falhas; depois runtime DB físico/proveniência/harness diagnóstico completo.
Somente quando concreto/revisável pedir autorização específica para novo ensaio;
startupPGescreve metadados noPGDATA,SQLreadonly não implica volumeRO. Não encerrar
pelo marco/CI,não simular /compact; checkpointsduráveis e compactação do ambiente.

## 2026-10-28 — lifecycle do leitor concluído em testes locais; servidor continua

Sobre ecab15e/353, 023358c compartilha somente o mecanismo interno de intents,
quarentena de colisão e cleanup entre perfis fechados. c685b74 entrega o driver
fixo do leitor, gates antes de create/start, transporte privado e captura após
exit/configuração conferidos. A captura não transforma cleanup incerto em sucesso;
DB é retido e nenhuma inicialização é repetida após resultado ambíguo. Sem CLI/API
para efeitos. Os gates SQL não alegam conhecer a história antes de consultá-la.

Rodada após refatoração: **156 passaram/2,33s**. Leitor, diário, runtime e captura:
**157 passaram/2,02s**. Suíte completa `make test-runner-activation` sobre c685b74:
**647 passaram/72,09s**; log privado em
.local/pki-milestone/database-reader-lifecycle-suite.log. Um aviso Starlette/httpx
permanece. SQL do fluxo lifecycle é fixture; testes não alcançam o PostgreSQL do Lab.

Este commit adiciona política HBA fixa por operação e ADR0025: **11 testes passaram/
0,29s**, sem DB/Docker. Arquivo0444 em pais0700, escrita exclusiva/fsync/verificação
sem sobrescrita, alteração do original, credenciais ou grants. Apenas SCRAM da
conta/banco/loopback fixos, demais acessos rejeitados; runtime ainda não comprovado.
Total previsto após este commit: **356**, nove desde eb39b4e; main/GitHub privado e
push após cada commit. Lint/format/tipos locais aprovados; CI final ainda a confirmar.

Continuar sem encerrar pelo checkpoint: receita/inspeção e ownership do servidor
PostgreSQL, imagem/proveniência e coordenador diagnóstico completo antes de pedir
nova autorização específica. Nenhum lifecycle Docker/build, leitura de volume
original, novo ensaio/marker/campanha, alteração de PKI/binding/credenciais humanas
ou migração foi executado. Demo e fontes Linux/Wazuh preservados.

## 2026-10-28 — receita e inspeção do servidor prontas para composição; global em execução

Base16131ee/356: d5b616c adiciona receita fixa do PostgreSQL não root e 95648b5
adiciona inspeção projetada de imagem/runtime/mounts. Este checkpoint será o
**12º commit desde eb39b4e**, total **359**; fonte de código95648b5, main e privado.

Receita não executa entrypoint/initdb/chown/migration/seed e não aceita banco,
volume, parâmetros ou rede livres. Volume original RW/nocopy e HBA da operação
RO/rprivate, namespace none e escuta127.0.0.1; sem publicação de portas ou secrets
em env/argv. Limites384MiB/1CPU/64PIDs; preserva TLS, autovacuum/preload/logging da
fonte. Create só é compilado depois do intent DBREQUESTED. Não foi invocado.

Inspeção exige mounts/configuração/estado exatos, ownership repetido e HBA/estado
durável iguais antes/depois. Imagem deve declarar só VOLUME PGDATA/EXPOSE5432;
Config.User omitido é tratado por index e labels vazias por with. Consulta real
revelou ausência de User e dois metadados upstream adicionais (GOSU_VERSION e
DOCKER_PG_LLVM_DEPS); guard agora distingue estes nomes revisados de variáveis
PG*/loader livres. PATH/LANG/PG_MAJOR/PGDATA continuam fixos, valores não expostos.

**20 testes** receita+política passaram/0,51s; rodada final incluindo inspeção:
**86 passaram/0,98s**. Inclui consulta real somente de metadados da imagem
b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24 e do DB Demo
existente, nunca SQL ou aprovação desse DB como servidor de Lab. Imagem passou no
perfil de metadados; proveniência/autenticação/conteúdo do volume seguem falsos.

Lint/formatação de187arquivos e tipos locais passaram. Suíte global iniciada sobre
95648b5 em .local/pki-milestone/database-server-global-tests.log; aguardar resultado,
sem declarar aprovação ainda. Não executar outra suíte PostgreSQL/Redis15 durante
a global. CI código95648b5 em andamento; source-review SUCCESS na última consulta.

Nenhum Docker lifecycle/build, leitura interna de volume original, SQL Linux,
marcador/campanha, PKI/binding, credenciais humanas, grants ou migração alterados.
Só ps/imageinspect/containerinspect de objetos Demo existentes e artefatos privados
em testes temporários. Próximo trabalho: lifecycle/readiness do DB, imagem atual e
proveniência, coordenador diagnóstico completo. Novo ensaio exige escopo humano
específico depois de tudo preparado/revisável. Continuar automaticamente entre
marcos; checkpoint não encerra o trabalho nem finge invocar /compact.

## 2026-10-28 — global aprovada, fonte privada conferida e startup sem replay

Suíte global sobre95648b5: **1.778 Python passaram/424,18s**, um aviso conhecido
Starlette/httpx. Log privado .local/pki-milestone/database-server-global-tests.log.
CI dessa base foi cancelada pelo push subsequente conforme concurrency; não alegar
validação remota completa. Source-review22653f8SUCCESS. Código novo posterior tem
verificações específicas abaixo; a global não cobre alterações ainda posteriores.

c0ace72 entrega preparação/verificação host-only da fonte, com **24 testes passando/
1,32s**. Main limpa, blobs rastreados/allowlist, limites, tar determinístico privado,
manifesto e integridade; nunca workspace/env/chaves locais. Comando Make real foi
executado e CLI verify confirmou **65 arquivos** do commit
c0ace72df3031295fd01ee4572e5520e4d0afe25. Artefato local
.local/pki-image-sources/8ea11e031b3f473caf9b655f8fbc80cf, manifestoSHA
86c9ec4abe1c087e255e18a03d35fecca84757b4213c7bfec3595d44dcd21adc e sourceTreeSHA
 ee28a33e512e5e4879821b2a62ef5ee18aaa6e7d8d267ff5d94ed0985c7cd668.
Recibo privado em .local/pki-milestone/runner-source-receipt.json. Sem build/pull,
proveniência/autorização falsas. Hash local não é assinatura.

0a9f549 registra database_start_requested antes de RPC e database_runtime_observed
sem apagar intenção original nem permitir replay após OBSERVED/resume. Dependentes
abertos impedem start; cleanup preserva volume. **235 testes passaram/3,27s** na
rodada intents/cleanup/inspeção/lifecycle; rodada adicional com fases de inspeção:
**170 passaram/1,16s** (sobreposição, não somar como casos únicos).

Este commit estende recheck ativo ao DB em create/start/running, com consumidores
vazios antes e somente DB próprio depois; running exige start e evidência duráveis.
**72 testes passaram/25,94s**. Runtime/HBA/auth/SQL/proveniência não são inferidos de
metadados. Lint/formatação/tipos locais passaram. Total após este commit: **362**,
15 desde eb39b4e; privado/main/push direto preservados, sem branch/PR/force.

Continuar automaticamente: driver do servidor com gates e readiness de prazo
limitado, cleanup em falhas e retenção do pai após sucesso; depois build/proveniência
e coordenador diagnóstico completo antes de pedir ensaio específico. Não houve
novo Docker lifecycle/build, acesso interno aos volumes Linux/Wazuh, SQL do Lab,
marcador/campanha, troca PKI/binding, credenciais humanas, grants ou migração.

## 2026-10-28 — startup/readiness testados e CI completa aprovada; seguir imagem

296679a compartilha cleanup sem adoção em colisões; **99 testes passaram/2,75s**.
4223e34 implementa driver interno do servidor: create/start únicos com intents,
gates frescos incluindo ID conhecido e recipe/HBA/escopo/plano, runtime antes/
depois e readiness fixo de15s/oito tentativas. Só health pode repetir; não é prova
de autenticação. Sucesso mantém pai, falha/interrupção limpa ownership próprio;
colisão mantém CONFLICT, falha de cleanup retém ID/volume. **127 testes passaram/
3,90s** na rodada com probes/cleanup; **96 passaram/1,89s** com inspeção. Rodadas
sobrepostas. Nenhum desses drivers foi executado contra um container real.

Suíte completa sobre4223e34: **793 testes passaram/83,10s**, log privado
.local/pki-milestone/database-server-lifecycle-suite.log. Lint/formatação191arquivos
e tipos passaram. CI de4223e34 **SUCCESS**, [run40762985073](https://github.com/Buraddomoon/AEGIS/actions/runs/40762985073):
**1.856 Python passaram/seis projeções opcionais puladas/379,79s**,
**79 React passaram/12arquivos**, build439ms e advisory review. DiskCache5.6.3/
PYSEC-2026-2447 continua explicitamente revisado, não zero vulnerabilidades. Log
completo privado em .local/pki-milestone/database-server-final-code-ci.log.

Leitura adicional somente de imageinspect revelou runner antigo75059996 com três
labels herdadas do Compose. Não serve como base do novo perfil de cinco labels
exatas; não remover/alterar a imagem histórica nem relaxar o guard. Tag local
python:3.13-slim não estava disponível na leitura de metadados. Próxima etapa é
preparar nova imagem com base oficial identificada e fonte já conferida, mantendo
Docker/run/lab separados. Recursos lidos: MemAvailable5.611.160KiB e espaço do
workspace431.655.960.576bytes; não houve parada de serviços ou mudança de sistema.

Ferramentas de build consultadas no PyPI oficial: pip26.2.2/setuptools84.2.1/
wheel0.48.0, hashes das wheels públicas e compatibilidade de Python/MIT. Ainda
não instalado/baixado nenhum desses artefatos nesta etapa; pesquisa/metadata HTTP
somente, sem tokens/credenciais. Fixar/verificar inputs antes do próximo build.

Este checkpoint é o **18ºcommit desde eb39b4e**, total **365** após commit;
main/privado/push direto. Continuar automaticamente com imagem/proveniência e
coordenador diagnóstico revisável. Não houve novo Docker lifecycle/build/pull,
SQL ou leitura interna de volumes Linux/Wazuh, marcador/campanha, troca PKI/binding,
credenciais humanas, grants ou migração. Fonte/volumes/imagens históricos intactos.
Nova autorização só quando houver harness completo e escopo concreto; não repetir
ensaio antigo ou encerrar por marco/CI. O agente não possui invocador de /compact.

## 2026-10-29 — imagem efetiva construída e revisão sem replay concluída

Commits484128e..1080bb4 implementam checker, consulta registry, cache hash-verificado,
conferência nativa da base, contexto/build offline e revisão sem repetir efeitos.
Foram baixadas46wheels/21.223.287bytes em cache privado; nenhum pacote instalado no
host pelo downloader. Base oficial Python3.13-slim foi baixada por digest como
preparação de desenvolvimento (43.069.135bytes comprimidos), sem subir Lab.
Docker29.8.1/containerd usa manifesto como imageID, distinto do config digest;
primeira conferência recusou essa diferença e foi corrigida com perfis explícitos.
Tentativas/artefatos antigos preservados, sem afrouxar guards históricos.

Build real8d455299e9d845799fc917699d1962a9 executou RUNs networknone, somente inputs
selados/wheels conferidas, sem .env/keys/workspace/volumes de Lab. Checker real
Python3.13/UID10001 confirmou62arquivos,43versões runtime/três ferramentas e imports
dos probes. Não iniciou Compose/runner/SIEM/worker nem executou marcador/SQL Linux.
Saída exportou imagem local; pós-validação inicialmente recusou config digest
ausente no metadata-file. 1080bb4 suporta annotation do descritor nativo com
coerência estrita, e review usa só imageinspect, sem repetir build.

Revisão real passou em .local/pki-milestone/runner-image-readonly-review.json:
- native_image_id/result: sha256:b0a4879a0d89b98b3184c579566612d0ddf5837a0508a4a8125a4e1a4a0eaa17;
- config: sha256:0c4413aee64bcbbc91f58b2d98f48cc49844852a9337ee0c1bfb0f7ef73ae457;
- receiptSHA: 587b1c698adc6207e09fdf362535d621785ebe5c5895d7901ff2a7ca663d3091;
- local_build_inputs_verified=true, publisher_signature_verified=false,
  build_client_exit_verified=false (artefato durável de exit0 não existia na versão
  que construiu; não inventar essa prova). Nenhuma autorização de Lab decorre disso.

make test-runner-image-build: **134 passaram/3,35s**, um aviso Starlette/httpx.
CI d83d38e **SUCCESS**, [run40773965241](https://github.com/Buraddomoon/AEGIS/actions/runs/40773965241):
**1.974 Python passaram/seis projeções opcionais puladas/424,47s**, **79React/12arquivos**,
lint/tipos/build/advisory review. Essa CI não cobre1080bb4; este tem37testes diretos
mais a rodada134 acima. Logs privados image-review-tests.log e runner-image-build-code-ci.log.

Após este checkpoint: **374commits**, main e privado, push direto; último código
1080bb4 fix(build): reconcile exported runner images without replaying builds.
Continuar com plano diagnóstico separado do candidato PKI expirado, gates concretos
e coordenador/cleanup testados. Não acessar interior dos volumes Linux, iniciar
PostgreSQL original ou rodar probes antes de novo escopo específico autorizado.
Startup original escreve metadados/WAL mesmo com SQL de análise somente leitura.
Demo/credenciais humanas/PKI/binding/migrações/grants preservados. Checkpoint não
encerra a tarefa e não representa execução de /compact pelo agente.

## 2026-10-29 — diagnóstico composto preparado; ensaio original ainda não autorizado

498f9ac/d2d571f separam plano diagnóstico e recheck ativo da ativação PKI. Plano
fixa origem pública/identidade/descritor, daemon/volumes/imagens e main limpa; não
renova candidato expirado. Gate ativo só admite cinco papéis próprios, sem outros
consumidores/worker/rede. **24 testes** iniciais do plano/20,90s e **20 rechecks**/
22,82s passaram. Preflight real de metadados /1 preparou plano5cba6be... e não abriu
volumes; esse formato foi superado, preservado e não é executável implicitamente.

6fc4132 verifica índice/manifesto oficiais da imagem PostgreSQL já existente, por
TLS anônimo/headers+SHA, sem blobs/layers/pull. **60 testes PG+Python registry**/
0,62s passaram. Consulta real confirmou imagem
sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24,
receiptSHA1e14ced28accd9c0e62e18d077f046e73f540c3ce4863fc40530e3160d5d601a,
em .local/pki-milestone/postgres-official-origin.json. Assinatura do publicador e
hash dos bytes de layers locais permanecem false; vínculo local confia no daemon.
8388163 fixa receipt/hash no plano, sem refetch no recheck; **29 testes/21,64s**.

1ccfc4f calcula gates de runtime/política/identidade a partir de evidências, sem
JSON de aprovação externo; **22 testes/24,25s**. 45e4a5a compõe DB→SQL antes→diário
antes/depois→SQL depois→comparações→cleanup. Pedido exclusivo por plano, sem replay;
compara todas as provas exceto timestamp UTC explícito da revisão, sem afirmar
comparação de todo o banco. Falha/interrupção limpa ownership próprio; dependente
incerto retém DB. **15 testes/34,35s** exercitam fluxo e falhas com daemon fixtures,
SQLite privado/decoders/capturas reais, sem Docker lifecycle ou SQL Linux real.

db59492 expõe run opt-in e cleanup por planSHA/opID/beginSHA. Formato /3 anuncia
executor preparado; /1 e /2 continuam recusados. Confirmação explícita do startup
original+scopeSHA exato, lock compartilhado e recheck antes de ler somente o segredo
runtime gerado no .env. Não resetar credenciais/ler segredo via argv ou ambiente.
Cleanup aceita expiração, não abre senha nem reativa etapas. Procedimento concreto
em labs/linux/DIAGNOSTIC.md, ADR0028 e AGENTS. Ainda exige nova autorização humana
específica antes de qualquer run sobre dados originais. Startup PG escreve WAL/
metadados operacionais; SQL é READONLY e diário é RO. Sem marcador/API/worker/Redis/
Wazuh/runner servidor, PKI/binding/grants/migração ou remoção/criação de volumes.

Suíte conjunta: **143 passaram/103,58s**, um aviso Starlette/httpx; log privado
.local/pki-milestone/diagnostic-complete-fixture-tests.log. Ajustes finais de entrada
/plano /3: **48 passaram/26,78s**, diagnostic-cli-final-tests.log. Lint/formatação213
arquivos e mypy4arquivos passaram. Suíte global iniciada sobre db59492 e ainda em
andamento no último acompanhamento: .local/pki-milestone/diagnostic-final-global-tests.log.
Não rodar outra suíte PostgreSQL/Redis15 enquanto essa global estiver ativa.

Revisão nativa só de metadados encontrou ExposedPorts ausente na imagem limpa;
template do leitor falhava, diário passava. edcd8b8 usa index para campo opcional
de imagem/container, sem aceitar portas expostas. **95 testes runtime+lifecycle**/
1,63s passaram, incluindo consulta real da imagem b0a4879a... (imageinspect somente).
Fixtures de intent/DBid são temporárias/sintéticas, não ownership real. Documento
desse achado foi anexado ao ADR0024 existente em40a052e, corrigindo um arquivo ADR
criado com nome duplicado no commit anterior; histórico publicado preservado.

Recursos lidos:16CPUs, MemAvailable5.139.324KiB e431.163.277.312bytes livres no
filesystem Docker/workspace. Demo API/DB/Redis saudáveis e worker ativo, sem restart.
Docker informa seccomp builtin/cgroupns. Não alterado host/swap/sysctl/rede/serviços.
Nenhum novo diagnóstico run/cleanup foi executado sobre os volumes originais.

Este checkpoint é o **12ºcommit desde d83d38e**, total **384** após commit; último
código edcd8b8 fix(labs): handle absent exposed ports in native reader image projections,
e documentação40a052e. Main/privado/push direto preservados. CI edcd8b8 em andamento
na última consulta (run40877894805); source-review40a052eSUCCESS. Não declarar CI
final aprovada antes de observar resultado. Continuar: revisar saída global/CI,
corrigir achados, preparar plano /3 em main limpa e apresentar autorização somente
quando todo procedimento/preflight estiver concreto. Checkpoint não encerra tarefa.

Pedido do usuário sobre /compact respondido com franqueza: as ferramentas desta
sessão não oferecem invocador do comando. OpenAI Docs confirma que é comando da
interface; não fingir execução. Estado durável/checkpoints preservam continuidade,
mas não equivalem à compactação. Continuar automaticamente entre marcos.

## 2026-10-29 — global/diagnóstico finais passaram; CI interrompida pelo teto antigo

Global local sobre db59492: **2.139 passaram/520,20s**, um aviso Starlette/httpx,
em .local/pki-milestone/diagnostic-final-global-tests.log. A correção de projeção
posterior edcd8b8 tem95testes runtime+lifecycle passando, incluindo imageinspect real.
Rodada completa mais recente do diagnóstico sobre9a53ae1: **143 passaram/104,42s**,
em diagnostic-current-final-tests.log; cobre /3, gates, coordenador e CLI atuais.
Sem pytest/PG local ainda ativo deste marco. Não somar rodadas sobrepostas como
casos únicos. Revisão integral do índice419arquivos e release-check passaram.

Plano /3 real foi preparado/revalidado em main limpa9a53ae1, ID5ef5e00968b04923948a215557954399,
planSHA5ef34dbdcd9fbb85eedd4c65d611d294a65f1648e9cc313ee8999df837d5ca39,
sem abrir volumes/SQL; artefatos privados diagnostic-v3-preflight/recheck.json.
**Esse plano já ficou desatualizado após o novo commit da CI**; preservá-lo e gerar
outro em main limpa quando as verificações finais terminarem. Não fornecer flags
de execução até nova autorização humana específica. Nenhum run/cleanup real ocorreu.

CI edcd8b8 [40877894805](https://github.com/Buraddomoon/AEGIS/actions/runs/40877894805)
terminou **CANCELLED por timeout**, não aprovada: annotation “The job has exceeded
the maximum execution time of12m0s”. Pytest chegou a77%, sem falha registrada antes
da interrupção; frontend/build/advisory dessa execução não foram concluídos.
Log privado diagnostic-ci-timeout.log. Aumentar apenas a duração não prova testes.

a7d7597 ajusta teto finito do job para18min e adiciona durações dos15testes mais
lentos e faulthandler_timeout60 para diagnóstico, mantendo concurrency/cancelamento
redundante, cache e runner padrão. YAML/flags do pytest instalado foram verificados;
nenhum recurso pago habilitado. Nova CI **em andamento** no run40880305312:
https://github.com/Buraddomoon/AEGIS/actions/runs/40880305312 . Aguardar resultado,
investigar falhas/durações, não declarar sucesso enquanto estiver pendente.

Após este checkpoint: **386commits**,14desde d83d38e; último código a7d7597
chore(ci): bound the expanded suite at eighteen minutes and record slow tests.
Main privada e sincronizada. Próximo trabalho: concluir CI, registrar evidência,
preparar/revalidar plano /3 atual e pedir autorização do escopo pronto, conforme
labs/linux/DIAGNOSTIC.md. Se CI falhar, corrigir primeiro. Não encerrar por marco;
continuar automaticamente. /compact não pode ser invocado pelas ferramentas desta
sessão; o checkpoint não substitui nem finge execução desse comando.

## 2026-10-29 — CI final aprovada; próximo efeito depende de autorização específica

CI a7d7597 **SUCCESS**, [run40880305312](https://github.com/Buraddomoon/AEGIS/actions/runs/40880305312),
job15min45s: **2.133 Python passaram/sete inspeções nativas opcionais puladas/844,95s**,
**79 React passaram/12arquivos**, build/lint/tipos/advisory review aprovados. Aviso
Starlette/httpx e advisory DiskCache previamente revisado permanecem explícitos.
Log privado .local/pki-milestone/diagnostic-ci-final-success.log. A execução anterior
cancelada não foi tratada como sucesso. O teto18min permitiu a suíte terminar sem
remover checks; concurrency continua cancelando trabalhos redundantes.

Durações observadas: chamadas do coordenador13,61s/13,58s/11,04s e outros gates até
5,54s; não foi registrado um teste individual travado por minutos. O custo agregado
de Git/PKI/rechecks e demais testes no runner explica o teto antigo insuficiente.
Otimizar custo de fixtures pode ser evolução posterior, preservando cenários e
sem usar esta aprovação como prova de runtime no laboratório original.

Validações locais complementares já registradas: global2.139passaram, rodada
final143diagnóstico passaram,95runtime+lifecycle com imageinspect real passaram;
rodadas sobrepostas, não somar. SG/release-check de419arquivos passaram. Sem novo
startup/SQL/diário original, marcador/campanha, PKI/binding, migração, grants,
credenciais humanas ou serviços do host alterados. Demo preservado/saudável.

Após este checkpoint: **387commits**,15desde d83d38e; último código a7d7597
chore(ci): bound the expanded suite at eighteen minutes and record slow tests.
Privado/main/push direto, sem branch/PR/force. Gerar/revalidar novo plano /3 em main
limpa APÓS este checkpoint; planos anteriores fixavam commits antigos e não podem
ser usados. Guardar retorno independente em .local/pki-milestone, sem editar plano
ou apagar intenções para liberar. Hash canônico/recibo local não é assinatura.

Procedimento concreto pronto em labs/linux/DIAGNOSTIC.md: um diagnóstico local,
cinco papéis sequenciais/dois simultâneos, novos efeitos até300s, PG17 original RW
para metadados/WAL, SQL fixo READONLY, diário RO duas vezes, comparações e cleanup
próprio preservando volumes. Sem worker/runner servidor/API/Redis/Wazuh/marcador,
PKI/binding/grants/migração. **Ainda não executado nem autorizado para esta rodada**.
Pedir confirmação específica sobre esse escopo antes de fornecer flags run. A
confirmação é necessária porque os ensaios anteriores eram de uso único e foram
encerrados; “continuar desenvolvimento” não é licença para repetir runtime antigo.

Continuar trabalho já autorizado automaticamente; somente o efeito novo sobre os
volumes originais depende dessa decisão. Checkpoint não aciona /compact nem encerra
por conta própria a tarefa. Testes/CI e preparação não substituem evidência nativa.

## 2026-10-29 — diagnóstico autorizado interrompido antes do start, cleanup confirmado

Usuário respondeu “aprovado” ao escopo concreto de300s. Main limpa7ce1c7d,
plano faea59ae780747cbb2cb3b1dcceeb72a/SHAd1ed508b... e escopo b3067435...
revalidados. Host tinha4285MiB disponíveis e402GiB de disco; nenhum serviço alheio
parado. Um único run executado, operação de7aabdff5b04c5da116a86bb2d10496.
Container PG criado, inspeção anterior ao start falhou, container removido e
operação fechada. Resultado diagnostic_failed_and_closed; start_requested=false,
readiness_attempts=0. Nenhum SQL/probe/diário/marcador/worker/Wazuh/PKI/binding.

Reconferência de metadados: nenhum container/rede Linux, zero consumidores dos dois
volumes existentes; ambos preservados. SHA256 dos bytes do recibo privado:
efdab22c39de406d17de24d073004b55e0b7c3c13cab46becaea488c742f08d7.
Detalhes e limites em docs/evidence/diagnostic-2026-10-29/README.md. Autorização
consumida, pedido/intent preservados, não repetir esse plano. Main privada confirmada.

Investigação posterior sem lifecycle reproduziu erro de template Docker quando
campos opcionais de mount são omitidos. Demo existente não cobria esse caminho,
pois seus configured_mounts são vazios. A falha exata original não foi preservada
pelo erro genérico; não afirmar causalidade conclusiva. Continuar correção offline,
regressões e diagnóstico seguro da etapa antes de preparar novo ensaio específico.

## 2026-10-29 — mounts opcionais corrigidos, regressão com CLI real sem daemon

1418c78 corrige ReadOnly/BindOptions/VolumeOptions opcionais por index/defaults
explícitos. Docker CLI real, sobre socket Unix HTTP temporário/sintético, reproduz
falha do formatter legado de mapas brutos. Struct tipado dá valores zero; teste
precisa usar index .HostConfig como o template real. Guardas de RW/nocopy, HBA RO/
rprivate e fonte exata continuam recusando adulterações. Nenhum container criado
por esses testes, nenhum acesso ao daemon real a partir do HTTP fixture.

95817c3 adiciona failure_phase e failure_code em allowlist fechada ao recibo do
startup. 46 testes lifecycle/coordenador passaram/35,20s, incluindo sentinela secreta
omitida; após simplificação do filtro, 31 lifecycle passaram/1,41s. Rodada anterior
mounts+inspeção+lifecycle:106passaram/2,85s. Projeções completas created/running
adicionadas depois; conjunto final de12testes do CLI passou/1,04s. Rodadas se
sobrepõem; não somar como casos únicos. Ruff passou. Aviso Starlette/httpx conhecido.

Rodada final make test-runner-diagnostic sobre5379c63: **143 passaram/107,72s**,
log privado .local/pki-milestone/diagnostic-after-assay-tests.log. Ruff/formatação
de214arquivos e mypy4arquivos passaram. Não há suíte local ainda em andamento.
CI5379c63 [40896470899](https://github.com/Buraddomoon/AEGIS/actions/runs/40896470899)
ainda em andamento nesta escrita; lint/tipos já passaram, sem afirmar suíte total.

Quatro commits desde7ce1c7d até a adição dos testes completos; documentação deste
checkpoint será o quinto, total392. Main privada/push direto preservados, sem PR.
CI de código mais recente deve ser acompanhada antes de declarar aprovação; CI
anterior7ce/a7d está registrada, não valida esses deltas. Nenhum replay do diagnóstico
de7aabd... ou novo efeito original. Próximo: testes finais específicos, preparar
plano novo em main limpa, verificar CI e pedir nova autorização sobre o mesmo
procedimento delimitado. Não usar aprovação consumida como licença para repetir.

## 2026-10-29 — segunda autorização executada; PG validado, leitor ainda inconclusivo

CI5379c63 SUCCESS, run40896470899: **2.148 Python passaram/7 inspeções opcionais
puladas/828,37s**, **79 React passaram**, lint/tipos/build/advisory review passaram.
Log privado diagnostic-followup-ci-success.log. Usuário aprovou nova tentativa
única condicionada a essa CI. Main limpa ea2c61d, plano ef77bb4c21b04bc6af696c46d2730024,
SHA49269adc.../scope6397d9fe... revalidado antes do efeito. Host3.892MiB disponíveis,
402GiB livres, sem parar serviço alheio ou mudar host/rede.

Operação e6566b9db97d47e88f9e8197a0f85c15, 15:12:24–15:12:51UTC: PG criado/iniciado
uma vez, inspeções físicas e readiness na primeira tentativa confirmadas. Leitor
inicial criado/start solicitado, mas não produziu prova validada. Sem captura SQL
ou leitura de diário; não inferir causa exata, autenticação ou continuidade a partir
do erro genérico. Nenhum grant/migração/reset/PKI/binding/marcador/SIEM.

Cleanup removeu ambos os recursos, operação fechada; reconferência independente
de metadados confirmou ausência de containers/redes Linux e consumidores dos dois
volumes, ambos preservados. Startup PG escreve metadados/WAL conforme o escopo.
Recibo privado SHAae9df81d79228f47c2420f60fc77bd657951b796b720d2885d93f72ba33f3eef.
Segunda autorização consumida, não repetir plano nem apagar intent. Evidência
atualizada em docs/evidence/diagnostic-2026-10-29/README.md.

Continuar investigação offline e tornar a falha do leitor diagnosticável sem
mensagens brutas/segredos. Não migrar nem relaxar privilégios do banco original
para passar no teste. Este checkpoint será393ºcommit (primeiro desde ea2c61d).

## 2026-10-29 — rejeições do leitor rastreáveis; nova imagem construída sem Lab

279315d implementa envelope de rejeição fechado/contextual até4096bytes, com
categorias revisadas de ContinuityError/SQLSTATE e etapa, sem mensagens do driver,
SQL, senha ou traceback. Descarte de respostas desconhecidas/duplicadas/adulteradas
e flags falsos estritos. **66 testes do probe passaram/4,55s**, incluindo PostgreSQL
em schema próprio descartável; nenhuma consulta adicional ao banco Linux original.

3e12c0b preserva rejeição estática pelo transporte não zero, somente callback
interno no perfil privado4MiB, sem retornar stderr/bytes brutos de falha. Driver
também recusa envelope de rejeição com saída0. c41ff43 preserva a etapa informada
pelo probe após validar o vocabulário, além da etapa do host. **104 testes de
transporte/lifecycles passaram/2,16s**; rodada intermediária100passou/2,20s.
**183 testes de diagnóstico/review/probe passaram/114,95s**, antes do pequeno ajuste
final de etapa. Após esse ajuste, **16 coordinator+imageinspect passaram/33,00s**,
incluindo inspeção da nova imagem real, sem criar/iniciar container nesse teste.
Rodadas se sobrepõem. Ruff/formatação214arquivos e mypy4arquivos passaram.

Build de desenvolvimento novo, sem Lab, usa a mesma base oficial fixada e já
presente; nenhum pull adicional. Cache46wheels/21.223.287bytes conferidos, sem
instalação no host. Fonte3e12c0b selada/SHA
bf5ffb976cf0ce77570d20e8e5c6f46b2757decaa763f61cc50b3928af995945.
BuildID5993245cd7e9432e920043e70ade74be, planSHA
7bef6bb79315ee68fc3a0d48e3bec6196d5365a2da1b0dc21bd122fdbc4295ec.
Imagem local sha256:8673e8d9ccb06f2e7e9d2d57655e4ad9c1293fb54a5e18c9dc56ae781b023ecd;
config3e69a165...; receiptSHA21754bacf6f97b1e8c8469d2f981e1411695dcbdf75102ceab263c96caae039a.
Cliente de build terminou0 e isso foi persistido: build_client_exit_verified=true.
Checker executado como10001 conferiu62arquivos do pacote,43versões de runtime,
3ferramentas de build e imports reais. RUNs sem rede, contexto sem .env/keys/volumes.
Sem assinatura de publicador, push de imagem, PKI/binding ou permissão de Lab.
Imagem histórica preservada. Artefatos privados reader-diagnostics-{source,wheels,
build-plan,build-result}.json em .local/pki-milestone; não publicar conteúdos brutos.

A causa exata da segunda falha original permanece desconhecida; a melhoria permite
diagnosticar uma tentativa futura, não prova que corrigiu aquela causa. Consulta
histórica fechada de eventos Docker do leitor retornou vazia; não prova exitcode
ou ausência de erro. Não reiniciar/retomar o plano consumido para coletar detalhes.

CI c41ff43 [40902712786](https://github.com/Buraddomoon/AEGIS/actions/runs/40902712786)
ainda em andamento; não declarar aprovada. CI5379c63 anterior passou conforme
marco acima, mas não valida estes novos deltas. Este checkpoint será397ºcommit,
quinto desde ea2c61d; main privada/push direto. Próximo: preparar/revalidar plano
novo em main limpa usando a imagem8673e8d9..., aguardar CI e solicitar autorização
específica antes de qualquer novo startup original. Não encerrar por marco; continuar
o que não depende dessa autorização. Nenhum /compact foi acionado pela ferramenta.

## 2026-10-29 — terceiro diagnóstico revelou rejeição de perfil; cast inet corrigido

Usuário respondeu “continuar” à pergunta específica0388cd1e; interpretação como
autorização única condicionada à CI foi explicitada antes do efeito. CI40902712786
SUCCESS: **2.175 Python passaram/7 opcionais pulados/688,45s**, **79 React passaram**,
lint/tipos/build/advisory review passaram. Log privado reader-diagnostics-ci-success.log.
Main limpa fccc6b9/plano853141b3.../scope8d10d4e2... revalidados,3.632MiB/402GiB livres.

Operação9bb5b0847b8543548cd0db8373128b4d,17:30:25–17:30:49UTC: PG validado,
leitor rejeitou persisted_probe_database_profile_mismatch/reported_phase=collect.
Sem prova SQL validada/diário; cleanup/fechamento e ausência externa de recursos/
consumidores confirmados, volumes preservados. Autorização consumida, sem replay.
SHA dos bytes do recibo9c8519db15e75a71e62c735eaf407612dfd9b3c9eeab5b3386b7fe06d78723c4.
Evidência atualizada, sem mensagens brutas/credenciais ou mudança PKI/binding/grants.

Investigação no PG de desenvolvimento reproduziu inet '127.0.0.1'::text =
127.0.0.1/32, host() =127.0.0.1. Teste novo executa SELECT real do probe em conexão
de schema pytest próprio, parando antes de interpretar esse banco como Lab, e usa
ipaddress para exigir IP sem máscara. **Falhou antes da correção**; a0591af troca
somente expressão por pg_catalog.host(inet_server_addr()), guarda exata preservada.
**67 testes do probe passaram/4,20s**, Ruff/formatação dos dois arquivos passaram.
Não atribuir sucesso ao diagnóstico nativo: ele terminou antes desse código.

Continuar: nova fonte/imagem conferidas para essa alteração, checks e CI, plano
novo em main limpa e autorização específica antes de qualquer outro startup.
Imagens anteriores e recibos preservados. Este checkpoint será399ºcommit,
sétimo desde ea2c61d; último código a0591af. Sem branches/PR/force ou reset de dados.

## 2026-10-29 — imagem com endereço SQL corrigido construída e conferida

Fonte a15b7f6/SHA1f60a73ebb6730be6a2fcefb65bedf36507491e4094dc2f84828f8af90ad4edd,
62arquivos de pacote. Build novo02204960dac2472d9f19da40bddf853b,
planSHA4019c3adeceaec6dee31df212658948fe51f727c12a063a27a12a681ca41f622,
imagemsha256:6b9033b966eb33b9c2be6d98a3be1d1d8276617e091a39a8e851bac57f4860f0,
config8b8f3782..., receiptSHA2db00cdd11bb9bcc1b1e632c6fe5613ba732cc4460476e8d19a4cbcc1451975b.
Cliente0 persistido, checker novo como10001 confirmou fonte instalada,43versões
de runtime/3ferramentas/imports. Base oficial fixada já presente, RUNs sem rede;
46wheels conferidas, sem instalar no host ou puxar base de novo. Imagens/recibos
antigos preservados; sem assinatura de publicador ou autorização de Lab.
Artefatos privados .local/pki-milestone/inet-fix-{source,wheels,build-plan,build-result}.json.

Depois do build, **teste nativo opcional de imageinspect passou**, sem criar/iniciar
container ou abrir volumes; Ruff/formatação214arquivos e mypy4arquivos passaram.
Teste de regressão de SQL real e suíte do probe:67passaram/4,20s, conforme marco
anterior. Nenhum novo efeito original após9bb5b084..., cuja autorização foi consumida.

CI a0591af [40922479654](https://github.com/Buraddomoon/AEGIS/actions/runs/40922479654)
ainda em andamento nesta escrita; não declarar aprovada. Source-review a15b7f6
passou. Após este checkpoint:400commits,8desde ea2c61d. Último código a0591af
fix(labs): compare PostgreSQL loopback addresses without inet netmasks. Main privada,
push direto. Preparar/revalidar plano novo em main limpa com imagem6b9033b9...;
novo startup só após CI e autorização específica, sem reuso de plano consumido.
Pendência real: verificar SQL/diário completos e só depois preparar ativação PKI.

## 2026-10-29 — diagnóstico nativo completo verificado e encerrado

Usuário confirmou “Autorizar essa confirmação após a CI passar” para54f5b12d.
CI40922479654 SUCCESS sobrea0591af: **2.176 Python passaram/7 opcionais pulados/
847,90s;79 React passaram**, lint/tipos/build/advisory review passaram. Log privado
inet-fix-ci-success.log. Main limpa a283b6a, recheck passou,3.743MiB/402GiB livres.
Sem mudança de host, serviços alheios, segredo humano ou ambiente Demo.

Operação **4c28e0bfdb2a4d5f9d88076e55628b86**,17:50:17–17:51:47UTC, resultado
**diagnostic_verified_and_closed**. PG criado/iniciado uma vez, quatro probes
completos/removidos. Uma prova SQL/binding/histórico iguais antes/depois; só
review.reviewed_at UTC ignorado. Dois jobs/oito eventos do diário, um adicional,
uma prova conhecida casada; inventários lógicos iguais nas duas leituras.
implicit_restart_histories=0, não inventar restart implícito neste volume.

Cleanup confirmou cinco recursos removidos/fechamento; consulta externa repetiu
ausência de containers/redes Linux e consumidores dos dois volumes, ambos intactos
quanto à existência. PG pode escrever WAL/metadados conforme escopo; não dizer
que todo o diagnóstico foi RO ou que todas as tabelas do DB foram comparadas.
Recibo privadoSHA0be41f1dfedd58c23222a7e96538150bc43fbe851cccccf0553f07b63d343a88.
Detalhes e limites em docs/evidence/diagnostic-2026-10-29/README.md. Sem marcador,
worker/Wazuh/migração/grants/PKI/binding; normal_operation_permitted=false.

Autorização consumida; preservar pedidos/intents/capturas/imagens e não repetir.
Este checkpoint será401ºcommit,9desde ea2c61d; main privada/push direto. Continuidade
histórica agora demonstrada, sem licença permanente de ativação. Continuar para
preparação offline da PKI e dos contratos faltantes de ativação, sem efeitos reais
adicionais. Candidato anterior expirado não pode ser ativado nem ter TTL burlado;
novo material/escopo precisa de revisão própria conforme o procedimento de rotação.

## 2026-10-29 — contrato da rede isolada da rotação implementado

Novo runner_activation_isolated_network compila somente network-isolated com
bridge/local/internal, IPv4/defaultIPAM172.30.88.0/29/gateway reservado.1 e
gateway_mode=isolated; sem opções de usuário, IPv6/Swarm/attachable/config-from.
Exige intent REQUESTED para compilar e ID OBSERVED para network inspect concreto.
Ownership antes/depois, flags/IPAM/membros/labels exatos e intent inalterado.
Conferir configuração não prova alcance de tráfego/host ou concede autorização.
Sem CLI/create/start/lifecycle; active_metadata não foi ampliado nesta unidade.

**130 testes de rede/ownership/cleanup passaram/1,85s**, incluindo formatter sobre
network Demo já existente, somente ls/inspect; nenhum recurso criado ou adotado.
Fixtures recusam driver externo, gateway/range/subnet/aux/opções extras, membros,
tipos/labels errados, drift no intent e segredos em erros. Fresh import inerte.
Rodadas anteriores35e90casos se sobrepõem. Ruff/formatação216arquivos e mypy4passaram.
Decisão e limites no ADR0029; make test-runner-activation inclui a nova suíte.

Este commit será402º,10desde ea2c61d; main privada/push direto. Nenhum novo efeito
Linux após diagnóstico4c28e0bf... encerrado. Próximo: lifecycle interno de criação
única/ownership/cleanup e gates concretos antes de expor executor de rotação.
Não gerar candidato curto só para renovar TTL antes do procedimento reviewable.

## 2026-10-29 — lifecycle interno da rede com criação única e cleanup

runner_activation_network_lifecycle implementa driver fechado de create e fluxo
interno: request antes da RPC, callback confiável/fresco com plano/escopo/receita,
contexto imutável, ID/ownership/configuração conferidos, rede vazia retida somente
no sucesso. Sem CLI ou gates concretos de coordenador; não invocado em Docker real.
Falha/interrupt limpa só ownership próprio, nunca retry. CONFLICT, membro estrangeiro
ou dependente inesperado mantêm bloqueio; não relaxar dependências para passar.

**195 testes lifecycle/rede/cleanup/intents passaram/2,63s**. Regressão ajustada
respeita a retenção correta quando callback introduz dependente REQUESTED; não foi
enfraquecido cleanup para satisfazer teste. Import inerte dos dois módulos testado.
Ruff/formatação218arquivos e mypy4arquivos passaram. Teste opcional só leu metadados
Demo existente; nenhum recurso Linux/volume/PKI/binding alterado.

Este commit será403º,11desde ea2c61d; main privada/push direto. ADR0029 e AGENTS
atualizados. Próximo: gates derivados do plano/inventário em operação, e depois
runtime mTLS sem marcador; aprovação real continua necessária antes de qualquer
novo ensaio. O sucesso original4c28e0bf... não é lease ou permissão de criação de rede.

## 2026-10-29 — preflight local de subnet sem alterações de rede

runner_activation_subnet_review compara dois snapshots de subnets Docker e rotas
IPv4 de todas as tabelas via iproute2 fixo. Subnet única172.30.88.0/29, sem URLs/
nomes/comandos do usuário, plugin desconhecido ou exclusão por labels próprias.
Colisão, metadata incompleta, mudança durante IO ou prazo bloqueiam. Prazos20s/
query5s/saída64KiB incluindo stderr, limite128redes/16pools/2048rotas. Kill/reap
somente do filho próprio, ferramenta ausente explicitamente desconectada.

Review nativo somente leitura: **15redes e46rotas,1default ignorado, nenhuma
sobreposição observada**. Não criou recurso, mudou rota/sysctl ou enviou probe de
tráfego. Saída privada só counts/subnet fixa/hash, não IPs/interfaces/gateways de
outras redes. Comparação normaliza destino/tabela/tipo, não expiry/cache; não é
prova de reachability/firewall nem lease para criação. Native SHA do snapshot
33a8b9bb914a255b0f3b181ada300ff68e607f3c55698db375fc0a61e67bc519.

**30 testes preflight passaram/0,35s;86 testes combinados de preflight/rede/lifecycle
passaram/1,35s**, rodadas sobrepostas. Ruff/formatação220arquivos e mypy4passaram.
Cobrem colisões Docker/host, plugins/malformed/IPv6,
inventário mutado, clock expirada, EOF sem exit, tool ausente, limites/stderr/reap.
Não repetir ensaio Linux para validar esse preflight. make test-runner-activation
inclui módulo novo. Próximo: ligar fatos atuais aos gates do ciclo de rede; ainda
sem CLI ou autorização de create. Este commit será404º,12desde ea2c61d; main privada.

## 2026-10-29 — recheck ativo para preparação da rede isolada

active_metadata/active_plan agora conferem network-isolated/create ou created,
exigindo REQUESTED/ausente ou OBSERVED/vazia. Sem start/running, outros roles ou
API/Redis ativos. Network membership global/nomes reservados/ownership/consumidores
continuam exatos, duas consultas e prazo integral. Plano/PKI/Compose relidos e TTL
reconferido após IO; retorno ainda sem autorização/ativação/isolation proof.

**106 testes active_metadata/active_plan/diagnostic_recheck passaram/62,84s**,
incluindo os contextos novos e a preservação do perfil Demo/Linux de diagnóstico
/3 (rede não foi adicionada aos cinco papéis daquele plano). Fixtures de daemon e
PKI temporária, sem rede/serviço/volume real criado. Lint/formatação dos arquivos
passaram. Este commit será405º,13desde ea2c61d, main privada/push direto.

Próximo: plano da rotação deve fixar a versão exata do executor e escopo antes de
compor gates concretos de autorização/subnet/runtime. Formato público atual ainda
não é operacional, sem CLI apply ou permissão de usar planos antigos como aprovação.

## 2026-10-29 — plano /2 fixa executor main e escopo único com validade

runner_activation plan/snapshot agora conferem main limpa antes/depois de PKI/
Compose/metadata e fixam tool_commit. scope_sha256 inclui formato/ID único/criação/
expiração/perfil e snapshot completo; mesmo input com nova preparação tem outro
escopo. Active_plan exige escopo exato do intent e snapshots com todos os campos,
sem omitir source pin. /1 permanece intacto/recusado, sem conversão por rehash.
Janela15min e perfil executor_implemented=false mantidos, sem novo CLI de efeito.

**65 testes de planejamento/active_plan passaram/86,24s**, após a última mudança
de nonce/validade; **uma regressão adicional passou/2,19s** para commit limpo trocado
durante metadata, antes de publicar plano. Ruff/formatação220arquivos e mypy4passaram.
Testes usam Git main temporária e PKI descartável. A expectativa antiga de Compose
drift foi atualizada para o bloqueio mais cedo por dirty source; nenhum guard foi
relaxado. Ignorar/alterar `.env` fixture não permite ler ou publicar seu conteúdo.

Este commit será406º,14desde ea2c61d, main privada/push direto. Documentação de
operação identifica candidato antigo expirado e diagnóstico original já encerrado;
não gerar certificado curto só para renovar artefato antes do executor reviewable.
Próximo: compor gates concretos de rede com plano /2/fatos de subnet/ownership e
orçamento da confirmação local. Nenhuma rede Linux/PKI/binding foi alterada.

## 2026-10-29 — gate concreto da rede derivado de verificações atuais

NetworkGates compõe confirmação local do scopeSHA exato/plano/operação, validade
UTC<=300s/orçamento monotônico, duas revisões ativas de PKI/main/Compose/inventário/
ownership e preflight de subnet novamente observado. Callback create-only com
receita fixa, sem aprovação JSON, CLI ou efeito nativo. Fatos são datados no início
do IO; idade<=10s/validade<=20s limitadas pelo plano/confirmação. Nenhum certificado,
binding, recurso Linux ou configuração do host foi alterado.

**115 testes de gates/lifecycle/rede/subnet passaram/48,34s**, incluindo PKI/Git
temporários e consumo do gate pelo lifecycle sobre daemon fixture. Revisão anterior
encontrou uma chamada inexistente no teste de histórico encerrado; corrigida usando
o evento closed verdadeiro, suíte combinada reexecutada. Ruff/check,222arquivos
formatados e mypy4passaram. Aviso Starlette/httpx conhecido permanece. Hashes de
evidência só em memória; coordenador deverá persistir. Não é assinatura humana,
atestado de tráfego ou autorização para invocar Docker create em recursos reais.

Este commit será407º,15desde ea2c61d; main privada/push direto. CI do406º ainda em
andamento ao conferir, sem alegar aprovação do delta novo. Próximo: preparar uma
superfície de identidade mTLS sem rotas de jobs para a futura conferência PKI,
sem abrir diário/workspace ou executar marcador. Ensaio nativo segue pendente de
procedimento completo/revisão/autorização própria.

## 2026-10-29 — identidade mTLS sem superfície de execução

Servidor agora oferece opt-in de implantação identity_only, sem instanciar Runner,
Workspace ou Journal: apenas GET /v1/identity, tests=[]/header explícito, demais
métodos503 e nenhum acesso a /state ou /work. Cliente operacional recusa allowlist
vazia antes de preparar job. Modo padrão anterior preservado, sem alterar Compose,
reiniciar Demo ou invocar containers/volumes Linux. Configuração inválida impede
boot. Mesmo entrypoint continua exigindo cliente TLS e proxy_headers=false.

**48 testes identity/transport/engine/protocol passaram/2,19s**, incluindo mTLS real
somente em loopback com certificados temporários, recusa sem certificado, ASGI,
entrypoint sem diretórios/Runner e compatibilidade do modo anterior. Primeira
rodada27pass mostrou warnings do helper de fixture exportando campos não usados;
helper corrigido para exportar só os três IDs, suíte combinada executada novamente.
Permanece apenas aviso conhecido Starlette/httpx. Ruff/check,223arquivos formatados
e mypy4passaram. ADR0030 descreve limites. Imagem6b9033b9 preservada não inclui este
recurso, novo build selado será necessário; nenhum ensaio nativo novo foi feito.

Este commit será408º,16desde ea2c61d; main privada/push direto. Commit407º1725645
sincronizado; CI remota em andamento, redundante406º cancelada automaticamente.
Próximo: compilar perfil fechado do container de identidade com secrets folha RO,
sem journal, portas publicadas ou parâmetros livres; ainda sem driver/CLI de start.

## 2026-10-29 — receita fechada do container de identidade, sem lifecycle

runner_activation_identity_runtime compila somente plano /2/intent correspondente
e network-isolated OBSERVED/ID completo, IP172.30.88.2. Python-I/-B/server, env
identity-only/trêsUUIDs, três secrets RO/rprivate do candidato, nenhum journal/
workspace/porta/stdin/comando livre. Caps ALL removidas, rootfs RO,192MiB/0,5CPU/
16PIDs/tmpfs16MiB, sem restart/log/healthcheck. Compilador não lê chaves ou faz RPC.
Create exige runner REQUESTED novo; não reutiliza estado OBSERVED nem modifica
o histórico. Revisão física/conteúdo/env herdado/imagem sem VOLUME ainda pendentes.

**15 testes passaram/16,59s**, planos/PKI/Git temporários: argumentos/mounts fixos,
rede ausente/em cleanup, scope/ID/hash errados, plano expirado, CSV injection e
fontes de secret divergentes; import sem efeitos. Ruff do delta passou. Referências
oficiais Docker create/gateway modes conferidas; não executar argumentos no daemon
real para validar preparação. Nenhum recurso Linux, PKI/binding ou Demo alterado.

Este commit será409º,17desde ea2c61d; main privada/push direto. Commit408ºb73f8f9
sincronizado. Próximo: inspeção fechada do container/imagem/environment/mounts e
endpoint de rede, antes de driver/gates/coordenador. A imagem histórica6b9033b9
continua preservada e não foi atualizada implicitamente pelo código novo.

## 2026-10-29 — inspeção fechada da configuração de identidade

identity_inspection confere imagem sem VOLUME/ports/env imprevisto e container
owned OBSERVED/START_REQUESTED em created/running, configuração/env/mounts exatos
e endpoint172.30.88.2/rede própria. Binds folha RO/rprivate, nenhum volume original,
porta, extra IPv6/link-local/links/opção de driver. Fonte host/env só predicados,
sem valores retornados. Reconfere plano/receita/intent após IO. Perfil antes do
start distingue endpoint ainda não alocado; depois exige ID/IP/prefixo reais.
Metadados não demonstram mTLS, execução do modo, proveniência ou alcance de tráfego.

**92 testes inspeção/compilador/templates/servidor de identidade passaram/19,14s**.
Incluem Docker CLI real sobre HTTP Unix daemon falso, sem criar recursos; testes
de expiração/drift e guards adversariais. Check inicial Ruff encontrou tail de
teste inserido no bloco errado durante edição; movido ao caso de tmpfs duplicado,
suite combinada executada após a correção. Ruff/check,227arquivos formatados e
mypy4passaram. Inspeção nativa somente de image6b9033b9 confirmou formato/perfil
básico, mantendo implementação do modo/proveniência falsos; imagem antiga intacta.

Este commit será410º,18desde ea2c61d; main privada/push direto. Commit409ºf311157
sincronizado; CI remota em andamento na última consulta, sem aprovação do delta
novo alegada. Próximo: registrar start do servidor de identidade de forma durável,
sem replay, antes de conectar gates/lifecycle. Nenhum startup Linux, PKI/binding,
marcador ou interferência no Demo decorreu desses incrementos.

## 2026-10-29 — fence durável de start apenas para identidade

Intents agora registram identity_start_requested antes da futura RPC: runner
OBSERVED/sem start anterior, modo identity-only, hashes PKI/receita/gates e rede
isolada própria/ID. Qualquer outro papel nãoABSENT bloqueia. Estado START_REQUESTED
nunca pode repetir start após resume; configuração observada preserva esse fence
mesmo voltando a OBSERVED. Cleanup permanece permitido, rede retida até ausência
do runner. Flags de autorização/daemon/mTLS/operação não são inferidas do evento.

**155 testes intents/cleanup passaram/1,90s**. Uma expectativa do teste novo usava
o retorno resumo como se fosse evento; corrigida para ler JSON durável e comparar
event_sha256, suíte reexecutada. Cobertura inclui resume real do hashchain, perfis
errados, papéis concorrentes, ordem dos eventos, duplicação e fechamento. Ruff/
formatação228arquivos/mypy4passaram antes dessa correção pequena de teste; Ruff do
teste passou novamente. Sem daemon, startup, arquivos PKI ou volumes originais.

Este commit será411º,19desde ea2c61d; main privada/push direto. Commit410º0752a5a
sincronizado, CI40937969087 em andamento. Próximo: contextos ativos fechados para
o servidor de identidade, sem ampliar contextos de execução normal/diagnóstico /3.

## 2026-10-29 — membros da rede conferidos por ID antes de ampliar contexto ativo

Inspeção do próximo gate identificou que count sozinho não vincula membro à rede.
Preparado identity_network somente leitura: dois snapshots de configuração e
endpoints, ownership rede/runner, nome/ID/IP/prefixo exatos e fence identity-only
para running. Create exige vazio, start aceita vazio/runner próprio parado;
contagem igual com ID estrangeiro bloqueia. Plano/receita/intent/tempo após IO,
orçamento20s e queries limitadas pelo restante; nenhuma alteração ou tráfego.

Rede vazia original conserva contrato estrito. Extraída só validação privada de
campos não membership, usada junto da conferência explícita dos endpoints novos.
**76 testes de identity_network/rede/lifecycle passaram/11,73s**, incluindo fixtures
adversariais de endpoint/ownership/count/clock/intent/expiração, sem startup real.
Ruff/check,230arquivos formatados e mypy4passaram. Não há quiescência global ou
isolamento de tráfego comprovados por esse retorno; inventário ativo ainda deve
ser combinado antes do efeito. Nenhum novo recurso Linux/volume/PKI foi alterado.

Este commit será412º,20desde ea2c61d; main privada/push direto. Commit411º5ee0126
sincronizado. Próximo: contextos ativos identity-only que preservem recusas antigas
para runner operacional, probes e diagnóstico /3, então gates/lifecycle concretos.

## 2026-10-29 — contextos identity-only sem ampliar execução genérica

active_metadata/active_plan aceitam apenas fases identity-create/identity-start/
identity-running para runner. Fases genéricas continuam negadas; outros papéis não
recebem identity. Só runner/rede isolada nãoABSENT, membership global/nomes reservados
e consumidores dos volumes exatos. Running exige fence de start e configuração
observada; plano também compara recipe/manifestoPKI/rede do fence ao conteúdo
atual. Ownership não prova implementação do modo, mounts ou tráfego: inspeções
físicas continuam necessárias no próximo gate. Diagnóstico /3 não foi ampliado.

Validação após as últimas mudanças: **make test-runner-activation:230passed/72,92s
e832passed/1skip/93,26s**, skip opt-in de metadata de imagem. **23 testes novos de
contexto ativo passaram/12,51s**, incluindo fence com hash errado preservado e
rejeitado antes de metadata. **14 testes de recheck diagnóstico selecionados por
identity passaram/20,26s,9deselected**, incluindo recusas das três fases novas antes
de consultar inputs. Rodada anterior128pass/82,95s se sobrepõe e não deve ser somada.
Ruff/check e mypy4passaram; nenhum ensaio Linux, volume ou material PKI alterado.

Este commit será413º,21desde ea2c61d; main privada/push direto. Commit412º3a231ea
sincronizado, CI40938992208 em andamento na última consulta. Próximo: compor gate
identity-only com confirmação exata, fonte/imagem revisadas e inspeções físicas,
então lifecycle/coordenador; ainda sem CLI/driver de start ou nova autorização.

## 2026-10-30 — fonte da imagem de identidade e retomada da validação

identity_image exige recibo de build selado já existente/hash independente, cliente
terminado0, imagem/commit fixados e pacote/dependências iguais à main limpa atual.
Reusa verificadores de inputs do diagnóstico sem chamar seu run/SQL/diário. Não
adota recibo ausente, imagem diferente, exit boolfalse/inteiro ou fonte desatualizada.
Confere commit/recibo após IO, sem build/pull/start, chaves ou permissões inferidas.

**12 testes passaram/1,93s** em retomada confirmada, com fixtures de build/imagem/
Git temporárias e import inerte; Ruff/check e formatação do delta passaram. Processo
de teste anterior à pausa não estava mais disponível: seu resultado não foi
presumido, suíte reexecutada. Recibo fixture permanece com bytes/mtime intactos no
sucesso; teste de remoção atua somente em temporário, nunca em evidência original.

CI do413ºe641e5f/run40940163204 encerrou cancelled: annotation oficial confirmou
**limite de18min excedido**, sem suíte completa aprovada. Não atribuir a timeout
como erro funcional dos testes nem alegar green. Próxima prioridade é particionar
CI preservando cobertura completa/cancelamento/caches. Este commit será414º,
22desde ea2c61d, main privada/push direto. Nenhum efeito Linux/PKI/binding novo.

## 2026-10-30 — CI completa em duas partições complementares

Corrigido o gargalo de runtime do job único, confirmado por annotation oficial
do run40940163204: limite18min excedido. Nova matriz0/1 divide pytest pelo SHA256
do caminho do arquivo, coletando tudo e selecionando cada caso uma vez. Cada job
tem PG/Redis próprios; frontend separado sem serviços Python. Lint/tipos/advisory
Python somente0, caches/cancelamento redundante mantidos e fail-fast=false entre
shards. Sem alteração de máquina/plano pago, skips novos ou redução de verificações.

**81 testes particionamento/continuidade passaram/0,34s**, incluindo16casos novos.
Coleta real de pytest completo e ambos os comandos confirmou **2490 =1273+1217**,
zero overlap/omissões. Primeira comparação encontrou dois nodeIDs UUID aleatórios
entre processos, não uma omissão do plugin; IDs por nome foram fixados, mesmos
dados/casos mantidos, coletas repetidas e comparação exata passou. Lint/formatação
235arquivos/mypy4passaram. actionlint não está disponível; sintaxe YAML/contratos
foram testados, execução real da workflow nova ainda deve ser acompanhada.

Este commit será415º,23desde ea2c61d; main privada/push direto. Commit414º873faf2
sincronizado. Próximo: confirmar CI dos dois shards/React e continuar a composição
dos gates identity-only. Nenhum novo startup Linux/PKI/binding foi autorizado ou feito.

## 2026-10-30 — confirmação não renova a janela original da operação

Revisão do próximo gate encontrou que calcular300s por construção permitiria
estender orçamento ao reconstruir objetos. Extraído ConfirmedPlan, utilizado pelo
NetworkGates: beginSHA/ID originais fixados e expiração <=beginUTC+300s. Janela15min
do plano não renova operação vencida; clock anterior ao último evento durável
também bloqueia, além do limite monotônico já existente. Sem efeito externo,
assinatura humana ou mudança no diagnóstico histórico. Cleanup continua independente.

**49 testes confirmação/gates/lifecycle passaram/32,12s**, incluindo4regressões:
reconstrução com prazo estendido, restante da janela, operação vencida/plano ainda
válido e clock rollback após evento. Ruff/check,236arquivos formatados e mypy4passaram.
Execução local da partição0 do415º: **1272passed/1skip/1217deselected/303,98s**;
partição1 em andamento; contagem final deve ser apurada no resultado do comando.
CI415º41056361290: React SUCCESS, dois Python em andamento na última consulta.

Este commit será416º,24desde ea2c61d; main privada/push direto. Commit415º9421095
sincronizado e repositório novamente confirmado PRIVATE. Próximo: finalizar
validação completa/CI e compor gate de identidade com fonte e inspeções físicas.
Nenhuma renovação PKI, startup Linux ou binding foi feito/implicitamente autorizado.

## 2026-10-30 — CI completa aprovada e probe TLS com incerteza explícita

**CI416º/run41057596645 SUCCESS**: Python0 **1270passed/3skip/355,20s**, Python1
**1216passed/5skip/399,11s**, React SUCCESS e checks configurados concluídos. O
particionamento resolveu o limite18min sem excluir testes; diferenças de skips
nativos opcionais são de ambiente. Log privado preservado em .local/ci-validation.
Execução local iniciada no415º terminou **1272+1217passed/1skip**, em303,98s+372,84s.
Ela coletou2490casos, sem os quatro casos de confirmação adicionados depois;
corrigida a expectativa provisória do checkpoint anterior, sem somar rodadas.

Novo identity_probe /1 só GET fixo emTLS1.3, contexto/hash/identidade/CA/folha
conferidos,12s integral/caps HTTP, sem redirect/compressão/URL livre/volumes/jobs.
Guard PID1/UID10001/container/pipe, sem overrides TLS/keylog, certificados públicos
regulares/nonblocking/nofollow. Chave antiga não é lida. Saída factual não concede
operação nem transforma controles TLS em detecção ATT&CK.

Teste real revelou que omissão de cliente termina em reset sem alerta TLS explícito,
tantoTLS1.3 como no experimentoTLS1.2. Esse reset não foi aceito como prova: mantido
TLS1.3, identidade/CA antiga registradas e requisito cliente INCONCLUSIVE. Servidor
que aceita identidade sem cliente é recusado. Expiração10/falha de rede não podem
virar rejeição de issuer; códigos19/20/21 são conferidos. Exit0 pode ser revisão
inconclusiva, host futuro deve validar status/flags. Autenticação do cliente ainda
precisa evidência do transporte servidor. Nenhum ensaio nativo novo foi executado.

**60 testes probe/servidor/transporte passaram/6,78s**, incluindo TLS loopback real,
ASGI inseguro controlado para recusa, controles sintéticos explícitos, I/O/HTTP
adversarial, keylog/overrides, FIFO/symlink/size e erros sem segredos. Ruff/check,
238arquivos formatados e mypy4passaram. Imagens anteriores não incluem o novo módulo.
Este commit será417º,25desde ea2c61d; main privada/push direto. Próximo: evidência TLS
do peer no servidor, antes de gate/lifecycle/coordenador e autorização de ensaio.

## 2026-10-30 — certificado cliente observado no transporte TLS

tls_peer captura SHA256 DER diretamente de ssl_object/CERT_REQUIRED e vincula
dataclass imutável à conexão por wrapper ASGI. Identity-only emite headers de
hash/política/versão somente desse objeto, ignorando headers de request. Scope é
copiado/extensão sobrescrita e instância de protocolo não pode ser reutilizada;
sem dependência de contextvars/agendamento. Main seleciona H11 adapter só no modo
identity-only, preservando auto no runner normal. Versão exata Uvicorn0.54.0 guardada
antes do boot; detalhe interno self.app exige revisão em upgrade.

**make test-runner:102passed/8,22s**, incluindo TLS real loopback com fingerprint
cliente exato, tentativa de spoof via header, conexões independentes, recusa de
ausência/validação opcional/DER malformado e versão desconhecida. Rodada71pass se
sobrepõe e não é adicional. Ruff/check,240arquivos formatados e mypy4passaram.
Sem container/rede Linux, diário original, PKI/binding ou Docker socket. Probe /1
ainda não valida headers novos; não foi anunciado cliente autenticado por ele.

CI417ºf80b104/run41060922484 SUCCESS nos dois shards Python/React na última consulta.
Este commit será418º,26desde ea2c61d; main privada/push direto. Próximo: versão de
request/resultado do probe que confere peer esperado e mantém controle negativo
inconclusivo quando falta razão TLS; depois gates/lifecycle/coordenador.

## 2026-10-30 — contrato /2 valida o peer cliente e limita sua janela

Probe /2 vincula DER cliente esperado aos headers do transporte revisado, política
required/TLS1.3 e identidade/folha servidor. Peer/política observados não apagam a
incerteza independente do controle sem certificado. Reset/EOF continuam inconclusive;
flags operacionais/volumes/marker/cliente antigo continuam falsas. /1 é recusado,
sem upgrade automático. Decoder4KiB fecha campos/hash/booleans/classificação e
preserva leitura histórica após expiração sem permitir novas conexões.

Janela UTC<=300s conferida antes de material/rede e de cada conexão; prazo async
min(12s, restante). **make test-runner:127passed/11,22s**, reexecutado porque a sessão
anterior deixou de estar disponível, sem presumir seu resultado. Inclui TLS real,
headers ausentes/peer errado, wire adulterado/legado/replay e expiração durante
controles. Ruff/check,240arquivos formatados/mypy4passaram. Sem ensaio Docker real.

CI418º1e06044/run41062809372 SUCCESS nos três jobs. Este commit será419º,27desde
ea2c61d; main privada/push direto. Próximo: preparação do request no host e gates/
lifecycle fechados; imagem atualizada e autorização própria ainda serão necessárias.

## 2026-10-30 — pedido do host validado com mTLS real em loopback

identity_request deriva request /2 de ConfirmedPlan/operação e material público
fixado ao plano. Confere manifesto/descritores/IDs/URL e fonte limpa antes/depois;
não lê chaves privadas/ids.env/.env nem escreve PKI. Janela expira com a confirmação
original. Nenhum Docker/SQL/diário/volume original foi aberto. Gate completo de
pares de chaves/imagem/runtime permanece separado e ainda precisa ser integrado.

**11 testes novos passaram/17,33s**: preservação bytes/mtime, leitura pública apenas,
JSON sem confirmação, expiração antes/durante IO, commit/material alterado e fluxo
host→probe→decoder com TLS real em loopback. Nome TLS/SAN/DER do candidato mantidos,
somente TCP roteado no teste. **make test-runner127passed/10,67s**; Ruff/check,242
arquivos formatados e mypy4passaram. Warning conhecido de Starlette/httpx registrado
na saída; sem falhas. Reset sem alerta continua INCONCLUSIVE.

Este commit será420º,28desde ea2c61d, main privada/push direto. CI419º84e5ee3: revisão
de fonte SUCCESS; React SUCCESS e partições Python em andamento na consulta.
Próximo: gate concreto que combina inventário ativo, imagem selada e inspeções
físicas para servidor de identidade, antes de lifecycle/coordenador/ensaio nativo.

## 2026-10-30 — gate composto para o servidor de identidade

IdentityGates combina revisões ativas antes/depois, imagem selada/fonte atual,
perfil da imagem, membros da rede e mounts/configuração física. Usa o mesmo
ConfirmedPlan e prazo original; start com fence prévio bloqueia replay. Schema,
contexto, booleans estritos, drift e freshness validados antes de publicar; sem
Docker lifecycle novo. Hashes em memória ainda dependem do coordenador durável.

**49passed/66,80s**:26casos de gates,11request e12verificação real de recibos/fontes
seladas, sobrepostos às rodadas anteriores. Composição usa daemon falso e fixture
só na fronteira de build, sem alegar ensaio nativo. Recusa worker/consumidores
originais, endpoint estranho, mounts RW, portas, modo ausente, fonte antiga,
recibo inteiro, receita/tempo/intent alterados. Corrigido erro de import na coleta
isolada, após ordenação Ruff; repetição passou. Ruff/check,244arquivos formatados
e mypy4passaram. Make test-runner-activation inclui os novos arquivos.

420ºdfdf19d sincronizado. Este commit será421º,29desde ea2c61d, main privada/push.
CI419º foi cancelada por supersessão após novo push; não tratada como sucesso.
CI420º em andamento e source-review SUCCESS na consulta. Próximo: lifecycle interno
create/start único com fences e cleanup próprio; autorização nativa segue pendente.
