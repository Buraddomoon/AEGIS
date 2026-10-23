# Registro de progresso — ÆGIS

Estado atual: **Demo/Linux 0.2.0, pipeline Wazuh real validado em um único ensaio encerrado e engenharia Sigma com revisões, análise estática e diagnóstico de preparação; backup/restore Demo e boot da API recuperada em quarentena verificados (marcos ao final)**. Demo saudável em localhost:18780. Ensaio COMPLETED/DETECTED/CLEANED, synthetic=false; laboratório revogado, contas desativadas e stack encerrado com volumes preservados. Autorização de uso único consumida. Registros anteriores abaixo são históricos.

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
