# Registro de progresso — ÆGIS

Estado atual: **Demo/Linux 0.2.0 com preparação Wazuh (Marco Wazuh A ao final)**. Demo saudável em localhost:18780; usuário ainda não tem Wazuh e pediu sem instalar. Coleta validada localmente, sem consulta externa ou novo ensaio Linux. Os registros anteriores abaixo são históricos, não o estado atual.

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
