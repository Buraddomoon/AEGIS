# Testes e evidências

## CI particionada — 2026-10-30

O job único atingiu o limite18min após o crescimento da suíte. A CI agora executa
duas partições Python complementares, cada uma com PostgreSQL/Redis próprios no
runner GitHub, e um job React sem esses serviços. Runners padrão Ubuntu, caches e
cancelamento de runs redundantes permanecem; nenhum recurso pago foi habilitado.
Lint/tipos/advisory Python rodam uma vez, no shard0; checks React continuam completos.
Falha em um shard não cancela o outro, mas impede aprovação da workflow inteira.

`python scripts/run_ci_tests.py --shard 0` e `--shard 1` coletam a suíte completa e
selecionam por SHA256 do caminho canônico do arquivo, mantendo todos os seus casos
no mesmo shard. Duas atribuições explícitas em `run_ci_tests.PINNED` movem arquivos
inteiros de lifecycle/coordenador para0, com base nos durations da run41080108097
(537,18s no0 contra942,53s no1). Isso preserva dois jobs/limite18min; melhoria de
tempo ainda depende da próxima execução completa. Cada arquivo pertence exatamente
a uma partição, incluindo os fixados. Adições/ordenação não movem arquivos existentes;
alterar atribuições exige evidência e nova conferência de união. Shard
inválido/vazio, arquivo fora de tests ou PYTEST_ADDOPTS herdado impedem sucesso.
CLI não aceita filtros/ignore; `--collect-only` permite conferir a seleção.

Localmente, executar os dois comandos **em sequência**, nunca junto de outra suíte
PG/Redis15. `make test`/pytest normal continuam completos e sem particionamento.
Coleta não significa execução aprovada; conferir resultados de ambos os jobs e
do React. Comparação real de coleta da alteração conferiu2490casos =1273+1217,
zero omissões/overlap; contagem muda conforme testes novos. Após o rebalanceamento,
coleta real2726 =1379+1347, também sem omissões/overlap; coleta não executa casos.
IDs de dois casos UUID
do diário foram fixados por nome para comparação entre processos, sem mudar dados.

Referências: [hook de coleta pytest](https://docs.pytest.org/en/stable/reference/reference.html#pytest.hookspec.pytest_collection_modifyitems)
e [matriz GitHub Actions](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/run-job-variations).

## Execução local

`make infra` é pré-requisito dos testes de integração. `make test-unit` não exige serviços. `make test` roda pytest e Vitest; `make lint` verifica Ruff/format, mypy do domínio e TypeScript/Prettier; `make build` constrói a SPA.

PostgreSQL real é usado com um schema aleatório por sessão. A fixture aplica Alembic e trunca apenas tabelas desse schema entre testes, removendo o schema criado ao finalizar. Redis utiliza DB 15 nos testes de API, com chaves somente do namespace ÆGIS. Não usar Redis DB 14/15 para dados importantes no ambiente de desenvolvimento.

Não executar simultaneamente duas suítes de integração compartilhando DB15.
Fixtures usam schemas/bancos aleatórios próprios e desabilitam somente
autovacuum de suas tabelas descartáveis, antes do seed, para não disputar locks
NOWAIT com manutenção de fundo. Nenhuma configuração do banco ativo muda;
produção conserva NOWAIT e autovacuum. Testes de conflitos explícitos continuam
usando conexões/escritores concorrentes reais.

Suíte cobre identidade/CSRF/RBAC, ausência de segredos nas respostas, limite de payload/login, aprovação e alteração de escopo, estado, concorrência de claim/entrega, cancelamento, timeout, cleanup, recuperação, classificação/correlação, persistência, duplicação, relatório HTML seguro, versão Sigma, YAML inseguro, pinning TLS, paginação Wazuh e upgrade de banco populado. Agendamentos cobrem grant original, limite persistente, expiração, busy, atraso, rollback, dispatcher concorrente, pausa/retomada, revogação ativa com cleanup e alterações de autorização/escopo.

## E2E real

`make e2e` constrói a aplicação, cria um schema descartável, aplica migrações e seed, cria administrador com senha aleatória em memória, inicia API/worker separados e utiliza Puppeteer Core com o Firefox do host. Nenhum navegador é instalado automaticamente. Variáveis opcionais: `AEGIS_BROWSER=chrome`, `AEGIS_BROWSER_PATH=/caminho/navegador`. Não desabilitar sandbox ou certificados para passar o teste.

Fluxo: login → catálogo → campanha → revisão/aprovação → início → worker → eventos/evidências → exportação → nova solicitação → nova aprovação → comparação → indicadores → criação e aprovação de agendamento → ocorrência automática no worker → relatório com grant de origem → páginas auxiliares → viewport móvel. O script valida respostas reais e produz `docs/images/*.png`. Schemas e processos do teste são removidos em finally; logs ficam em `.local/e2e/`, ignorados pelo Git. Capturas não contêm credenciais.

Fixtures Wazuh usam `httpx.MockTransport`, sem rede, e representam testes de contrato escritos manualmente, com identificadores fictícios; não comprovam integração real. Testes de componentes podem simular respostas para estados vazios/erro, enquanto o fluxo E2E não usa mocks.

## Resultado inicial observado

Na primeira rodada ampliada: 52 testes backend passaram; 3 testes frontend passaram; E2E Firefox concluiu 2 runs / 8 testes sintéticos com zero erros JavaScript. Docker build e Compose completo foram executados, health ready retornou database/redis true, runtime confirmou `aegis_app` sem superuser e sem UPDATE em auditoria. Consulte `docs/PROGRESS.md` para a validação final mais recente e limitações.

Existe aviso de depreciação do upstream Starlette para o transporte httpx de TestClient; os testes executam com sucesso, sem ocultar o aviso. Migração para httpx2 poderá ser avaliada separadamente.

## Catálogo ATT&CK controlado

`pytest tests/test_attack_document.py tests/test_attack_artifacts.py
tests/test_attack_publication.py tests/test_attack_cli.py tests/test_attack_api.py
-q` cobre perfil/membros/flags/grafo/identidades, JSON ambíguo, limites, transporte
HTTP simulado incluindo headers lentos/cancelamento, arquivos privados/links,
renormalização/integridade, publicação PostgreSQL transacional, stale plans,
ator/downgrade/licença/drift/concorrência/rollback e adoção legada conhecida.
Fixtures reduzidas e baseline19.2 são sintéticas, sem pretensão de serem releases
oficiais. API/worker preservam relatório, separam releases e recusam scopes antigos
antes de efeitos. Permissões SQL reais cobertas pelo ciclo runtime recuperado.

UI testa paginação vinculada e recusa mistura/duplicação/incompletude,
filtros de ciclo de vida, histórico pesquisável e recarga após troca da release.
E2E Firefox consulta proveniência e abre/pesquisa snapshot real da API antes de
campanha/worker/relatórios, sem mocks; captura `attack-catalog.png` é do snapshot
inicial distribuído. A publicação oficial completa foi verificada separadamente
com a CLI/candidato real e dois ciclos sintéticos, sem acessar Linux/Wazuh.
[Recibos e limites](../evidence/attack-catalog-2026-10-23/README.md).

Marcação final:655Python/43frontend e lint passaram; build e E2E passaram,71casos
de recuperação foram repetidos após tornar a fixture determinística. Consulte
PROGRESS para o resultado remoto e checks finais; não somar casos repetidos como
novos testes. O E2E usa Redis14; o ensaio oficial isolado usou13, com limpeza de
chaves próprias. Nenhuma dessas bases deve guardar dados importantes.

Recuperação em quarentena: `make test-recovery` inclui rotas isoladas, token
independente, bloqueio dos entrypoints, drift de permissões/revisão e erros de
create/boot/cleanup. Testes de API criam banco e papel PostgreSQL aleatórios,
aplicam migrations/seed nesse banco e removem somente esses recursos ao terminar.
Exigem conta administrativa de desenvolvimento (como a da CI); não alterar grants
PUBLIC no banco ativo para passar testes. Verificam permissões reais incluindo
tentativas em READ WRITE; sessões/filas/reservas restauradas permanecem intactas.
`make verify-recovered-app` é ensaio operacional Demo explícito com imagem local
e backup confiável, fora dos testes padrão/CI; não inicia laboratórios reais.

Reconciliação: `make test-recovery` inclui banco/papel temporários reais para
transação, drift de dados/estrutura, locks concorrentes, idempotência, preservação
de timestamps/histórico e rollback por falha final/trigger. A fixture substitui
somente DB/usuário fixos pelo destino aleatório de teste; recusa do destino
original e ensaio Docker verificam as guardas de implantação. Mocks de CLI
cobrem ownership/rede/mounts/portas, stdin privado, aplicação/boot/cleanup sem
falso recibo. Histórico não satisfaz binding atual de ID/hash e filhos pendentes
bloqueiam review. `make reconcile-demo-backup BACKUP_ID=...` é opt-in e utiliza
somente um clone novo; nunca faz reconciliação no Demo em uso nem inicia workers.

Ciclo recuperado: make test-recovery inclui API/worker sobre PostgreSQL real com
role runtime temporário próprio, sem acesso à baseline privada ou DELETE em
histórico imutável. Fixtures trocam somente nomes de implantação por DB/role
aleatórios; nunca alteram aegis_app do ambiente em uso. Redis DB15, casos seriais,
limpeza só de chaves próprias. O callback de teste processa a fila pelo worker;
make verify-recovered-cycle valida separadamente processos Docker reais.
Mocks de Docker cobrem create antes/depois, start, probe, fechamento, ownership,
cleanup/retenção de dependências e ausência de segredo em argv/intents.

## Marco de agendamento Demo

Na rodada ampliada: **85 testes Python** e **5 testes frontend** passaram; E2E Firefox concluiu **3 runs / 12 testes sintéticos**, incluindo agendamento automático, com zero erros JavaScript. O smoke Compose inclui run manual e agendada, verificação de grant, relatório e revogação usando API/worker com papel SQL restrito. Consulte PROGRESS para comandos e CI final.

## Runner Linux independente

`make test-runner` verifica protocolo, filesystem, supervisor, journal, cliente/servidor, TLS real em loopback, morte do pai e isolamento de configuração. Não inicia containers. Fixtures de software criam somente arquivos/processos fixos em diretórios pytest; o programa bloqueante usado em timeout não existe na allowlist runtime. O teste PDEATHSIG utiliza um subreaper separado e recolhe seus próprios filhos.

`make lab-smoke` é um ensaio **real opt-in**, exige autorização e container previamente iniciado; não integra `make test` nem CI. O ensaio de 2026-10-21 foi autorizado explicitamente e seu resultado está em PROGRESS. Nenhum Wazuh externo foi acessado.

## Recortes e relatórios — marco2026-10-26

`test_analytics_selection/queries/api` e `test_analysis_export` cobrem período/
fuso/legado/release, snapshot coerente com conclusão concorrente, SQL read-only,
cap sem truncamento, hash/export/escape/misto/RBAC e comparabilidade incompleta.
UI `coverage-filters.test.tsx` testa paginação/races, filtros pendentes, export
preso ao hash e refetch com erro após comparação. E2E valida exports reais e
período/legado, com12capturas. Final688Python/53frontend, lint/build/CI aprovados;
[evidência e limites](../evidence/coverage-reports-2026-10-26/README.md).
Snapshot_at é metadado de consulta: invariâncias comparam todos os outros campos,
sem enfraquecer verificações de métricas, escopos, relatórios ou auditoria.

## Campanhas Linux integradas

`tests/test_linux_campaigns.py` exercita API/worker/PostgreSQL reais com runner de fixture em diretório pytest e transporte HTTP local de teste; mTLS real é coberto separadamente no transporte e no ensaio Docker. Abrange aprovação segregada, confirmação real, binding/usuários/allowlist revogados, preflight vencido, agendamento recusado, recibos, indicadores/relatórios por modo, crash/quarentena, geração e respostas perdidas em prepare/start/cleanup e rollback após cleanup remoto. Recuperações concorrentes devem produzir um sucesso e um conflito.

`make linux-platform-smoke` é opt-in real e não faz parte de make test/CI. Requer autorização específica do escopo em labs/linux/README.md. O ensaio integrado de 2026-10-21 executou uma única campanha. Falha inicial da captura opcional por falta de espera pelo formulário foi corrigida; apenas o histórico foi reaberto com conta temporária de visualização, sem novo marcador. As três contas temporárias foram desativadas e o stack próprio encerrado.

## Coleta Wazuh preparada sem SIEM

`make test-wazuh` cobre contrato de Search/Scroll, shards/total/paginação, ausência de índice e permissão, agente errado incluindo UUID interno, ingestão atrasada e janela completa, deduplicação/conflitos, cancelamento/HTTP lento e TLS real contra fixture HTTPS loopback. Fixture altera somente a conexão do backend de teste para loopback, mantendo IP aprovado e SNI/TLS do provider de produção; CA errada e hostname incompatível são recusados. Nenhum Wazuh é instalado. Campanhas usam PostgreSQL/worker/runner de fixture descartável; seus DETECTED são resultado de contrato, não evidência externa. Observador é testado contra Workspace real com UUID.hex e links/FIFO/conteúdo inválido recusados. UI cobre configuração ausente, revisão, admin/viewer e laboratório revogado.

`make test-wazuh-preparation` testa recursos insuficientes sem iniciar/download,
configuração privada e ausência de segredos na saída, certificados reais com SAN
e DN compatíveis, Compose renderizado com redes/mounts/credenciais separados,
ambiente externo sem sobrescrever destino, segredo apenas stdin no contrato da
ferramenta de hash e encerramento sem remoção de volumes. Log real em filesystem:
fsync/restart/dedupe, conflito da mesma execução, limite, escritor exclusivo,
links/FIFO/permissões e linha parcial. O hash tool é simulado nesse teste: isso não
valida BCrypt ou a imagem oficial. Nenhum Wazuh sobe na CI.

O mesmo target inclui `test_wazuh_runtime_inspection.py`: snapshots Docker
explicitamente fictícios, com mutações de portas, socket Docker, mounts RO/RW,
volumes de outro projeto, namespaces do host, usuário root, rede extra, membro
externo, imagem sem digest, ausência de limites e saúde/migração incompletas.
Testa também que o coletor só usa ps/ls/inspect no daemon local e no projeto exato,
omite Config.Env e não expõe erros/paths brutos. `make wazuh-lab-inspect` é somente
leitura e retorna exit1 se o projeto não existe. Esses testes não validam um
runtime Wazuh nem substituem a inspeção das permissões/mounts dentro do container.

O ensaio [real documentado](../../labs/wazuh/ASSAY.md) passou pelo preflight e foi
executado e encerrado em 2026-10-22. `check-rule` foi verificado com log sintético
no sandbox wazuh-logtest; a ingestão real foi conferida separadamente no ensaio.
A autorização foi consumida e não permite iniciar novamente o laboratório.

## Ensaio Wazuh real registrado em 2026-10-22

O único ensaio autorizado foi executado: uma campanha, marcador de 43 bytes,
alerta Wazuh original 100200, COMPLETED/DETECTED/CLEANED com synthetic=false.
[Artefatos, hashes e limites](../evidence/wazuh-2026-10-22/README.md). Laboratório
revogado, contas desativadas, containers/redes encerrados e volumes preservados.
Essa autorização foi consumida; nenhum teste padrão inicia esse stack ou efeito.

`tests/test_wazuh_assay_guard.py` usa HTTP de fixture para conferir ordem durável
de START_INTENT, um único start, ausência de retry em resposta ambígua, recusa de
histórico prévio, revogação e retenção de credenciais para recuperação. Credenciais
temporárias são removidas somente após desativação confirmada. Faz parte de
`make test-wazuh-preparation`; não executa marcador real.

`pytest tests/test_wazuh_recorded_assay.py -q` verifica os artefatos gravados,
normalização do schema real e recusa de identidade/regra alteradas, sem serviços
ou acesso ao SIEM. Esse reprocessamento offline não equivale a nova coleta real.
Na rodada do marco Wazuh: make test, **311 Python e 14 frontend passaram**; lint e CI aprovados.
Não foi repetido E2E de navegador nem criado screenshot Wazuh nesta rodada.

Revisões Sigma/teste: `pytest tests/test_rule_links.py tests/test_coverage_comparison.py tests/test_migrations.py -q` verifica revisões concorrentes/obsoletas, RBAC/CSRF, imutabilidade no banco, invalidação de início/agendamento, migração populada e comparação histórica. `npm --prefix apps/web test` cobre payload confirmado versus atualização de cache e resposta atrasada da comparação. `make e2e` inclui importar/revisar/versionar/retirar vínculos e prova de relatório histórico idêntico, somente Demo sintético. `make smoke` confere também privilégios SQL/trigger no papel runtime. Nada inicia ou repete Wazuh.

Análise estática Sigma: `pytest tests/test_sigma_analysis.py -q` inclui parser/condições, fatos, checks, versões históricas, hash divergente, RBAC, rate limit, limites de seleções/condições e processo novo com audit hook que recusa importação de DiskCache, rede e gravações. `sigma-analysis.test.tsx` cobre versões/erro/hash e resposta atrasada. E2E Firefox consulta versões com/sem achados, sem alterar o relatório anterior. `make smoke` usa a imagem implantada com papel SQL runtime para importar uma regra demonstrativa e consultar sua análise; `make audit` exercita parsing/análise e preserva a ocorrência transitiva revisada. Regressões de expansão e filter/correlation/action substituem SigmaCollection por função proibida e provam que o parser não é chamado para entrada fora do escopo/orçamento, sem expandir payloads perigosos.

Preparação Sigma: `pytest tests/test_sigma_readiness.py tests/test_sigma_analysis.py -q` exercita constraints publicadas versus runtime, perfil/paths do alerta gravado, campos ausentes/logsource/keywords, história de versões, sessão/viewer, hash, rate limit e metadados ausentes/malformados. Guard offline em processo novo também chama assess, recusando cache/rede/gravação. UI sigma-readiness.test.tsx cobre histórico, erro/vazio e identidade/perfil divergentes. Firefox E2E inclui regra genérica não mapeada e exemplo candidato mapeado com conversão bloqueada; relatório anterior idêntico. Smoke Compose verifica essas APIs no papel SQL runtime. Não há backend ou pipeline executado.


Recuperação: `make test-recovery` verifica inventário/estrutura em PostgreSQL real,
hashes internos, snapshot exportado excluindo alterações posteriores, roundtrip
de constraints e retenção somente leitura. Guardas da CLI usam mocks de Docker
para falha de start/restore/comparação/ownership/cleanup, rejeição de dump alterado,
permissões e symlinks. `make test` inclui esses testes, sem iniciar clones ou labs.
O ensaio operacional `make backup-demo` seguido de `make verify-backup BACKUP_ID=...`
é local e explícito; cria só PostgreSQL offline e compara o dump real. Não é
executado pelo CI nem testa boot de API/worker recuperados. Ver [procedimento](../operations/backup-recovery.md).

As suítes locais compartilham Redis DB15 e limpam seus contadores entre casos.
Não executar dois processos pytest/E2E com essa mesma configuração em paralelo.
Schemas PostgreSQL são exclusivos por processo, mas isso não isola Redis. Uma
rodada deste marco confirmou essa interferência no teste de rate limit; executar
a suíte completa sozinha, sem reduzir limites ou alterar o controle da aplicação.

## Backups cifrados — marco2026-10-26

`test_backup_vault.py` usa pyrage real (21casos), sem Docker: streaming, bytes
originais, corrupção/final/truncamento/extra, chave/hash errados, corrida in-place,
limites, ownership/links/FIFO, publicação exclusiva e retenção read-only com
snapshots distintos/verificados. Subprocesso impede import opcional na API/worker.
Cinco casos novos de CLI provam que verify-sealed não usa dump/banco fonte, remove
staging em falha e só publica recibo após restore/cleanup. Mocks não provam Docker.

make setup instala a dependência dev fixada por hash; operadores podem usar
make backup-tools para o extra isolado. requirements.lock da aplicação não muda;
a auditoria abrange requirements-backup.lock, sem ocultar advisory existente.
`make test-recovery` inclui os casos. Não executar duas suítes Redis15 em paralelo.
[Restore real local registrado](../evidence/encrypted-backups-2026-10-26/README.md):
32tabelas/3.169linhas a partir da cópia cifrada, origem intacta e cleanup aprovado.
Sem E2E navegador novo ou Linux/Wazuh; essa entrega só acrescenta ferramentas host.

## Consolidação de entrega — 2026-10-26

`test_init_env.py` cobre configuração privada/aleatória/idempotente, preservação
do histórico, recusa de segredos vazios/exemplos/duplicados, links/FIFO/mode/limites,
UTF-8 inválido e concorrência. Não usa `.env` real. `test_repository_checks.py`
exercita índices Git descartáveis, segredos redigidos, arquivo seguro só no worktree
e nomes com newline. `test_release_check.py` usa Git real temporário para versões,
locks, destinos ausentes/escape/esquema de URL, PNG inválido e leitura do índice.

`make release-check` só lê o índice; adicione previamente os arquivos revisados.
Confere metadados/links inline locais/cabeçalhos PNG e padrões, sem serviços/rede.
Não valida âncoras/links externos, procedência de pixels ou ausência de segredos;
não substitui `make test`, `make audit` ou ensaio de instalação. CI source-review
aplica esse check a documentação/metadados sem instalar o stack. Resultados da
suíte e CI desta consolidação em [PROGRESS](../PROGRESS.md).

## Prévia Sigma — 2026-10-26

`test_sigma_mapping.py`: pipeline oficial real, igualdade de valores/condições,
listas/AND/OR/NOT, hash completo, subconjunto recusado antes do parser/pipeline,
limites, drift e falha de invariância. Processo novo com audit hook recusa imports
cache/backend, rede, subprocesso e gravações; loaders de pipeline são proibidos.
`test_sigma_mapping_api.py`: PostgreSQL/API, histórico imutável, RBAC, rate limit,
Redis indisponível, perfil/SHA/version drift e erro sem echo. Nenhum SIEM consultado.

`sigma-mapping.test.tsx`: ação explícita, antes/depois, unsupported, contexto/flags
incompatíveis, refetch com erro e resposta atrasada. E2E Firefox acrescenta a prévia
ao ciclo Demo, confere os dois objetos de detection e relatório antigo idêntico.
Contagens finais, CI e evidência em PROGRESS; não confundir teste com conversão SIEM.

## Preparação offline da PKI do runner

Planejamento de ativação: `make test-runner-activation` executa os testes de
`test_runner_activation_metadata.py` e `test_runner_activation_plan.py`. Fixtures
de daemon cobrem queries/IDs/labels/consumidores/arquitetura/UID; filhos Python
curtos verificam timeout/limite somado de stdout+stderr, kill/reap e ambiente sem
DOCKER_HOST/config/proxies herdados. PKI real em temporários verifica hash/identidade,
drift, política exata/flags, TTL antes/depois, proteção de arquivos, fsync interrompido
e preservação de planos anteriores. Nenhum container/banco/journal/SIEM é iniciado.
Uma consulta real de metadados é evidência separada da forma das projeções; não
comprova conteúdo do volume, imagem confiável, mTLS de laboratório ou ativação.
[Contrato operacional](../operations/runner-pki-activation.md).

O mesmo target inclui `test_runner_activation_intents.py`: diretórios temporários,
eventos/ownership/transições, fsync interrompido, hashchain/retomada, lock concorrente
e substituído, histórico parcial/unsafe, limites e recursos proibidos. Regressões
recusam dependentes novos durante/depois da remoção, antes/depois de resume; estado
em memória não sobrepõe o histórico. Processo novo proíbe rede/processos/segredos
no import. Esses casos não consultam Docker nem criam recursos de laboratório.

Também inclui `test_runner_activation_ownership.py`: fixtures de containers/redes
presentes/ausentes, colisão/rename/labels/ID histórico, listas repetidas/drift,
estado parcial, projeções limitadas e catálogo de consultas sem mutações. Não
assumir AND de múltiplos filtros label nem tratar falha de inspect como ausência.
Esses testes não comprovaram templates em objetos reais de ativação; nenhum foi
criado para esse fim. Executor compartilhado já tem testes de timeout/limite/env.

`make test-runner-pki` executa 52 casos de geração, inspeção, preparação,
integridade, limites, drift, tempo, SAN/EKU, pares e fsync/retry. Três desses
casos usam TLS real de echo em loopback, aceitando o novo par e recusando
confiança/cliente antigos. Processo novo com audit hook recusa rede, arquivos
privados da origem e importações de banco/worker/runner. Não representa sandbox
contra root nem ensaio de laboratório; não inicia API, runner, marcador ou Wazuh.
Scanner do repositório também recusa arquivos .key. Consulte
[operação PKI](../operations/runner-pki.md).

## Revisão persistida do vínculo — 2026-10-27

`make test-binding-review`: 48 casos PostgreSQL em schema descartável, com cliente
runner proibido. Estados desconhecidos, pais/filhos pendentes, isolamento entre
laboratórios, cleanup ausente/corrompido, hashes/spec/geração/recibos/identidades,
limites, RBAC e ausência de mutações. GET prova READ ONLY/REPEATABLE READ; as três
mutações revalidam após um GET positivo. Teste concorrente real mantém revogação
sob lock e prova que nova solicitação aguarda e rejeita a leitura antiga.

`binding-review.test.tsx`: 13 casos para bloqueios, denominador da revisão
incompleta, consulta GET, acesso administrativo, flags/contexto contraditórios e
sucesso cacheado ocultado após erro. Nenhuma operação do laboratório é acionada.

Rodada completa antes dos cinco últimos casos adicionais: **882 Python** em314,96s
e **79 React** em3,93s. A suíte de revisão foi repetida depois: **48 passaram** em
33,20s, incluindo esses cinco; total de887 casos Python distintos exercitados.
O aviso conhecido Starlette/TestClient-httpx permanece. E2E Firefox Demo com API/
worker/PostgreSQL reais: PASS,4runs/16testes/zero browserErrors; build aprovado.
Não é ensaio Linux/Wazuh nem prova browser da ativação. Capturas dessa rodada
ficam privadas; imagens históricas publicadas preservadas. Estado final em
[PROGRESS](../PROGRESS.md).

CI bdb31c1 aprovado:883 Python passaram/quatro opcionais Docker pulados,79 React,
lint/tipos/build/auditoria. Inclui os cinco casos adicionais em uma rodada única;
advisory DiskCache conhecido continua revisado/visível, não ocultado.
[Execução40513069341](https://github.com/Buraddomoon/AEGIS/actions/runs/40513069341).

## Continuidade do diário e provas persistidas — 2026-10-27

`make test-runner-continuity` executa três arquivos, sem iniciar Linux/Wazuh:

- `test_runner_journal_continuity.py`: SQLite real em temporários, schema do writer,
  origem imutável, lock/arquivos/limites/identidade, jobs/recibos/gerações/eventos,
  WAL confirmado/incompleto/corrompido, SHM ausente reconstruído só no scratch,
  inventário independente do layout, timeout/cleanup e SQL authorizer restrito.
  Regressão com Runner real usa somente prepare e intent RUNNING, sem start:
  reinício → falha de cleanup → retry; conta o restart implícito preservando eventos.
- `test_runner_persisted_review.py`: PostgreSQL/schema descartável, readonly/isolation/
  timeout reais e tentativa DML rejeitada pelo servidor; binding/IDs/revogação/
  pendências/histórico/provas. Bundle completo decodificado e combinado a SQLite
  temporário; nenhuma chamada ao runner, Docker ou banco Linux original.
- `test_runner_journal_probe.py`: stdin/hash/limites/duplicatas/JSON inválido, caminho
  fixo, saída sem conteúdo de jobs e import em processo novo sem settings/engine/
  servidor, arquivos de segredo, rede ou subprocessos. CLI help não inicia probe.

PG/Redis de desenvolvimento devem estar configurados como no restante dos testes;
Redis DB15 é reservado pela fixture comum, sem executar outra suíte de integração
simultaneamente. Contagens finais/CI no PROGRESS; o aviso upstream de TestClient
permanece visível. Testes não comprovam volume original, mounts Docker ou ativação.

## Runtime/resultado/cleanup dos probes — 2026-10-27

`make test-runner-activation` inclui:

- `test_runner_activation_probe_runtime.py`: receita fechada, limites efetivos,
  mount read-only/nocopy, namespaces, env sem valores/duplicatas/loader, identidade
  e ownership repetido. Um caso opcional parseia o template no DemoAPI **existente**;
  daemon/API ausentes resultam em skip. Nunca criar recursos para passar o teste,
  nem interpretar metadados do Demo como runtime aprovado para o probe.
- `test_runner_activation_intents.py`: start intent exclusivo de probe observado,
  hashes de receita/gates/bundle e recusa de replay antes/depois de retomada.
- `test_runner_activation_cleanup.py`: intents reais em temporários e daemon
  simulado, incluindo API incerta/dependências retidas, erro com efeito ambíguo,
  ID descoberto após create incerto, daemon/bytes duráveis alterados, fsync falho,
  ausência final alterada e catálogo sem force/volumes/start/exec/global delete.
- `test_runner_activation_probe_result.py`: saída real do probe sobre SQLite
  temporário, hash/identidade/descritor/flags/contagens, resposta inválida e
  comparação de inventário completo. Não autentica origem física/imagem.

O driver concreto de cleanup nunca é chamado pelos testes; somente o método
interno `_execute` substituído por fixture. Não há target/CLI de lifecycle novo.
Contagens/CI finais estão no PROGRESS; testes não autorizam ensaio Linux/Wazuh.

Lifecycle de probes: o target também inclui `test_runner_activation_transport.py`
e `test_runner_activation_probe_lifecycle.py`. Transporte usa filhos Python locais
pequenos, entrada até4MiB, leitura/escrita concorrentes, timeout/overflow/EOF e
kill-reap. Nenhum desses filhos é Docker ou inicia o laboratório. Lifecycle usa
daemon fixtures e saída real do probe sobre SQLite temporário; valida ordem
durável, gate ausente/stale/alterado, falha antes/depois de create, start ambíguo,
resultado inválido, cleanup falho e KeyboardInterrupt. Collisão antes de create
fica em CONFLICT persistido e não pode ser removida por cleanup posterior.
Testes de cleanup selecionado provam que o intent pai segue aberto e dependências
continuam protegidas. A função interna não expõe CLI apply e exige um coordenador
confiável real para computar gates; JSON de fixture não é autorização de ensaio.

Metadados ativos: `test_runner_activation_active_metadata.py` e
`test_runner_activation_active_plan.py` juntam daemon fixtures/intents temporários
e PKI real descartável. Cobrem membros/consumidores extras, fontes alteradas,
estado/labels/imagens, snapshots repetidos, prazo inclusive IO final, SHA/ID do
plano/intent, PKI/Compose e expiração após últimas consultas. Recheck público
continua recusando projeto ocupado. Não leem volumes nem consultam SQL de lab.

Leitor PostgreSQL: `test_runner_persisted_probe.py` usa perfis de conexão em
fixtures e schema/histórico PostgreSQL real descartável. Testa input/contexto/
senhas privadas, env libpq, perfil fixo/role, types/nullability/RLS/views/herança,
mesma sessão/backend/snapshot e DDL concorrente bloqueado. Metadados alterados em
schemas aleatórios são revertidos; child de herança criado pelo teste é removido.
Herança anexada após o guard não amplia leituras ONLY. `test_runner_persisted_review`
verifica também que o hook não pode escrever (SQLSTATE25006). Endpoint/netns de
produção continuam só fixtures, sem original Linux. `test-runner-continuity`
inclui o novo arquivo; não executar junto de outra suíte PG/Redis15.

Transporte privado também testa cap4MiB para provas, stderr contado e overflow/
kill-reap; metadata continua com64KiB por padrão e limites arbitrários são recusados.
Esses filhos são Python local com bytes sintéticos, nunca Docker ou dados reais.

Leitores e servidor PostgreSQL do harness: `make test-runner-activation` inclui
`test_runner_activation_database_{runtime,result,lifecycle,policy,server,inspection}`.
Os testes usam intents/arquivos privados/SQLite temporários e daemon/engine fixtures.
Exercitam gates/contexto/identidade, senha em stdin, cap16KiB/4MiB, captura exclusiva,
fsync/reload, cleanup/collision/interrupção e retenção do DB. Não somar rodadas
sobrepostas como casos únicos. A política HBA é só arquivo local, não prova auth.

O teste opcional de inspection consulta somente ps/inspect da imagem e do DB Demo
já existentes (labels exatas aegis/db); sem objetos, SQL ou startup. Recusa campos
opcionais inseguros e expõe ambiente apenas como chave/booleano, nunca valor.
Config.User omitido na imagem é aceito; runtime ainda exige70:70. GOSU_VERSION e
DOCKER_PG_LLVM_DEPS são metadados oficiais fechados, não prefixos de env liberados.
Ausência do Demo/daemon significa skip; fixtures e projeção não provam o Lab real.
