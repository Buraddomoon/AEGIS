# ÆGIS — instruções de engenharia

Estado de autorização em 2026-10-22: o único ensaio Wazuh autorizado foi
**executado e encerrado**, run 987bd48f-fafc-4a34-bf2a-2d310e7ca794. COMPLETED/
DETECTED/CLEANED, uma execução; laboratório revogado, contas desativadas, senhas
temporárias removidas, containers/redes encerrados, volumes/journal preservados.
A autorização anterior foi consumida: não iniciar novamente o stack, repetir o
marcador ou remover intent/journal para contornar replay sem novo escopo autorizado.
Testes offline e leitura das evidências são permitidos. Ver docs/evidence/wazuh-2026-10-22.

Inspeção Wazuh antes do efeito: `make wazuh-lab-inspect` só usa ps/ls/inspect do
daemon Unix local e projeto exato; não iniciar, executar dentro de containers ou
consultar SIEM nesse comando. Política revisada independente de Compose, campos
opcionais com index nos templates Docker; nunca imprimir Config.Env/inspect bruto.
Recusar DeviceCgroupRules, mounts e membros inesperados. Testes opcionais de
projeção só leem objetos Demo já existentes; ausentes significam skip, sem criar
infraestrutura. Passar metadados não substitui mounts/permissões internos, mTLS,
agente Active, regras, ACL ou ingestão nem autoriza marcador. Ver ADR0006/ASSAY.

## Política obrigatória de versionamento

Use exclusivamente `main`. Não criar branches temporárias nem pull requests. Reutilizar `origin` privado; o nome autorizado do repositório GitHub é `AEGIS`, em maiúsculas, em `Buraddomoon/AEGIS`. Se o remoto estiver ausente, reutilizar esse repositório privado antes de considerar criar outro. `ÆGIS` permanece o nome do produto; GitHub aceita somente ASCII no nome do repositório. Verificar visibilidade antes do primeiro push. Nunca tornar público nem mudar visibilidade sem autorização.

Criar commits Conventional Commits pequenos, frequentes e coerentes, incluindo unidades parciais verificáveis; não aguardar uma funcionalidade completa. Antes de cada commit, revisar arquivos staged, executar o check relevante e verificar segredos/temporários. Após cada commit, tentar `git push origin main` sem nova confirmação. Se a rede falhar, preservar commits e tentar sincronizar depois. Conflito remoto: parar somente sincronização e solicitar orientação; nunca force push, rebase de histórico publicado ou exclusão de commits. Continuar o desenvolvimento entre commits.

CI com cancelamento de execuções redundantes e cache; não habilitar recursos pagos. Em cada marco, informar quantidade de commits, último hash/mensagem, sincronização, funcionalidades, testes e próximas tarefas. Essa política foi explicitamente autorizada pelo usuário nesta sessão.

Continuidade explícita pedida pelo usuário: informar marcos em commentary, salvar
checkpoint no PROGRESS e seguir automaticamente pelo trabalho autorizado; não
encerrar o turno apenas porque uma etapa ou CI terminou. Interromper trabalho
dependente somente diante de bloqueio real/decisão ou autorização necessária,
continuando tarefas independentes quando possível. O agente não tem ferramenta
para invocar /compact: não fingir execução desse comando. Manter checkpoint e
estado Git duráveis para a compactação controlada pelo ambiente.

Leia `docs/PROGRESS.md` e os ADRs antes de alterar o código. Monólito modular Python + React; domínio em `apps/api/aegis/domain`, integrações atrás de Protocols. PostgreSQL é a fonte de verdade e fila durável; Redis atende limites de login e heartbeat. Não implemente shell remoto, execução de comandos de API, acesso ao socket Docker ou download/execução automática de testes Atomic.

Todos os resultados Demo, eventos e relatórios devem indicar `synthetic=true`. Ausência de alerta nunca prova ausência de telemetria. Evidências devem casar execução, marcador, ativo, laboratório, tipo de comportamento e tempo. Não modificar evidências históricas ao editar regras.

Use migrações Alembic explícitas. Mantenha aprovações de uso único delimitadas pelo hash do escopo, validade e duração. Toda mutação autenticada exige RBAC e CSRF. Somente administrador aprova; Demo permite autoaprovação explicitamente; Lab real precisa revisão separada antes de habilitar. Nunca publicar credenciais. Não iniciar Wazuh nem executar operações ofensivas reais sem autorização específica.

Comandos: `make setup`, `make up`, `make test`, `make lint`, `make build`, `make e2e`, `make down`. Testes de integração usam PostgreSQL e Redis exclusivos do projeto. Nunca limpar dados de outros projetos. Não declarar checks aprovados sem executá-los. Atualize docs/PROGRESS.md com evidência e pendências. UI em pt-BR; nenhuma ação decorativa. Interfaces não operacionais devem informar indisponibilidade.

Entrega: `make release-check` lê o índice Git (versões, links locais inline,
cabeçalhos PNG e padrões de credenciais). Adicionar somente arquivos revisados;
não confundir índice/HEAD/worktree nem tratar o check como testes/instalação ou
ausência garantida de segredos. `scripts/check_staged.py --all` varre todo índice.
CI source-review valida docs sem dependências/bancos; CI principal continua para
código. `init_env.py` recusa arquivos inseguros/vazios/exemplos e preserva válidos;
não sobrescrever/resetar .env ou segredos humanos para contornar erro. Testes
test_init_env/test_repository_checks/test_release_check são locais/descartáveis.
Sem mudar versão/tag/visibilidade ou repetir ensaios para consolidar portfólio.

Agendamentos operam somente em Demo: planos imutáveis, até 16 ativos/64 abertos, grant exato por run/ocorrência, validade e orçamento incluindo descartes. Não reativar runs antigas ao reaprovar. Locks de controle: schedule → run → lab; worker lê plano/grant sem row lock. Dispatcher usa sessão SQL própria por thread/transação e savepoint no laboratório ocupado. Cleanup permanece obrigatório após revogação. Ver ADR 0002 e docs/operations/scheduling.md.

Runner Linux standalone: leia ADR 0003 e labs/linux/README.md. Allowlist contém somente linux-file-marker/v1. Não aceitar comandos/paths/scripts de API. Comprovante execution_receipt não é telemetria defensiva e não pode virar DETECTED. Campanhas Linux opt-in integram API/worker/UI conforme ADR 0004: registro derivado da configuração de implantação, isolamento revisado, preflight mTLS de 5 min, autorização do laboratório e aprovação explícita por administrador diferente do solicitante. Dispatch durável antes da RPC; geração antes de start; recibos/cleanup imutáveis separados de telemetria. Sem SIEM, INCONCLUSIVE. Crash real mantém reserva até recuperação verificada do job original; 404 não libera. Métricas/histórico por modo, scheduler somente Demo. O usuário autorizou dois ensaios específicos em 2026-10-21 (standalone e uma campanha integrada), ambos encerrados; isso não autoriza Wazuh, alvos externos, recorrência ou novos tipos de teste. Não iniciar Lab automaticamente com make up/test/CI. Testes: make test-runner. Watchdog deve kill/reap antes de SQLite; resultado terminal/ownership sob mesmo lock. Preservar diário, identidade e fences após restart; nunca reaplicar efeito ambíguo.

Ensaio integrado é opt-in: make linux-platform-config/build preparam; up/smoke/down exigem autorização específica. Projeto aegis-linux-lab, API loopback 18785, banco próprio, rede runner isolada. Não repetir smoke para corrigir captura visual: consultar histórico sem novo efeito. Ver labs/linux/README.md e PROGRESS para escopo/evidência.

Coleta Wazuh preparada no ADR 0005: o pedido inicial foi preparar sem instalar; o único ensaio posterior está encerrado, conforme o estado no início deste arquivo. Não iniciar Wazuh nem repetir Linux para testar esta preparação. WAZUH_COLLECTION_CONFIG é política local; binding administrativo exige Lab revogado/sem reserva e agent.id externo exato (nunca UUID interno como fallback). Janela/espera coerentes, timeout HTTP integral com asyncio.timeout, resposta sem compressão e limites. Resumo de coleta append-only; sem evidência não declarar DETECTED. Observer passivo usa Workspace.name/UUID.hex e não é iniciado automaticamente. Exemplos XML precisam wazuh-logtest futuro; testes locais não provam engine Wazuh. make test-wazuh inclui fixtures e TLS loopback. Lógica aprovada deve igualar LOGIC_VERSION; upgrade invalida aprovação antiga.

Histórico ADR0006 (autorização consumida, não reutilizar): em 2026-10-21 o usuário autorizou **“Autorizar somente esse ensaio quando o preflight passar”** para o escopo exato de labs/wazuh/ASSAY.md: projeto separado aegis-wazuh-lab, três imagens Wazuh 4.14.9 fixadas por digest, builds próprios, API loopback18786, SIEM sem portas publicadas, regra/TLS/agente, contas temporárias e aprovação segregada, um marcador43 bytes/filho5s/campanha120s, evidências/cleanup/revogação/desativação de contas e down preservando volumes. O ensaio foi concluído e encerrado em 2026-10-22; qualquer nova execução exige outro escopo autorizado. Condição obrigatória original: preflight4CPU/8GiB MemAvailable/50GiB discoDocker/vm.max_map_count262144; o bloqueio inicial por RAM foi resolvido antes daquele ensaio. Não parar outros serviços nem alterar sysctl/swap/cache. Essa autorização substitui o pedido anterior sem instalar somente dentro deste escopo; não permite repetição, outros alvos ou novos testes. Scripts lifecycle não executam marcador; antes do efeito conferir runtime, rule engine, agente Active, TLS, conta read-only e indexação reais. Logs do observer têm limite1MiB, flock/fsync, retomada/dedupe; não truncar evidências ou journals. Dados locais .local/wazuh-lab nunca entram em Git/build. Não declarar runtime Wazuh validado só por fixtures/config --quiet.

Associações Sigma/teste (ADR0007): planejamento humano, nunca sinal de implantação ou veredicto. RuleTestLink fixa RuleVersion/hash e test_version; substituição exige replaces_id sob lock da regra. Trigger permite somente primeira retirada, sem reescrita/exclusão. DTO current_rule_title é título atual, não título do conteúdo antigo. Formulário confirma payload exato e invalida ao refetch alterado. Scope novo inclui links relevantes ordenados; sem campo antigo significa desconhecido. Não editar scopes históricos para revalidar autorizações; nova solicitação/plano e aprovação. Comparação usa apenas snapshots e não infere causalidade. Testes: tests/test_rule_links.py, test_coverage_comparison.py; UI rules/comparison.test.tsx e make e2e. Nenhuma autorização adicional de laboratório real decorre desse recurso.

Análise Sigma (ADR0008): somente leitura, por versão/hash; sigma-static/1 identifica checks parciais AEGIS sobre parser/modelo pySigma. Não importar sigma.validators.core (descoberta transitiva carrega DiskCache), não usar cache/loaders MITRE ou plugin dinâmico. Preservar teste de DiskCache ausente. safe_sigma_document deve limitar expansão ANTES do parser tanto no import quanto no analyze: cadeia até6 sem repetição, estimativa256KiB/valor,1MiB total,4096variantes; YAML depth32. Rejeitar filter/correlation/action e detection não objeto antes do dispatch. Não testar com expansão real grande. Revisar estimativas/novos modificadores ao atualizar pySigma. Campo declarado não comprova telemetria e zero achados não comprova semântica/eficácia. Sem backend/pipeline, compatibility permanece not_configured e não realizar conversão/implantação. UI confere identidade/hash e não mostra resposta atrasada de outra versão. Testes: tests/test_sigma_analysis.py, UI sigma-analysis.test.tsx e fluxo Demo E2E.

Preparação Sigma (ADR0009): diagnóstico offline, can_convert=false; não converter nem instalar backends ignorando constraints. Wheels revisados OpenSearch2.0.3/Elastic2.1.1 exigem pySigma<2; core2.0.1 permanece. METADATA/snapshot versionado em fixtures/sigma, verificado por hash na captura; runtime não acessa rede nem importa backend. Perfil wazuh-aegis-marker/1 só mapeia logsource product=aegis/service=marker_observer e campos próprios do alerta registrado; nunca Image/CommandLine→full_log. _source não comprova mapping físico. Perfil não é pipeline executável. fieldref precisa de bloqueio explícito e field_mapping_complete=false até tratamento de pipeline, incluindo referências de nome conhecido. UI confere versão/hash e perfil/hash; novos perfis/metadados exigem revisão controlada. Testes: test_sigma_readiness.py e UI sigma-readiness.test.tsx; E2E somente Demo.

Backup Demo (ADR0010): ferramenta host-only scripts/demo_backup.py, nunca API/worker
ou mount Docker na app. Fonte somente projeto aegis/db local18782 e public/PG17;
cluster deve coincidir, snapshot compartilhado READ ONLY com pg_dump. Restore só
em clone aegis-recovery-UUID network=none, tmpfs, sem portas/volumes/workers e
mesma imagem local por ID. Não aceitar destino arbitrário, reativar jobs, restaurar
no banco em uso ou apagar backups/journals/volumes de labs. Recibo verificado só
após hashes/estrutura/linhas/cleanup. pg17-literal-array-casts/1 normaliza somente
casts de literais varchar[]→text[]; não enfraquecer comparação SQL genericamente.
Arquivos privados0700/0600, .local e dumps fora do Git; logs de erro também privados.
Retenção só plano, sem exclusão. Testes: make test-recovery; ensaio real de restore
Demo é explícito e não autoriza laboratório ofensivo ou Wazuh.

Backup: não herdar config/proxies do Docker do usuário. Manter config vazia/env
saneado, intenção durável antes de create, reconciliação por nome exato/label
mesmo após erro ambíguo e fsync dos diretórios. Preservar typmod de arrays,
collation/flags e rejeição de RLS/tipos/procedures não suportados. Não declarar
recuperação de recursos que o inventário não verifica.

Quarentena de recuperação (ADR0011): OPERATING_MODE=recovery fixa no boot apenas
health e review agregada com token independente; não montar rotas normais,
login, docs ou frontend. Worker/scheduler/CLI/migrations devem abortar antes de
conectar. Make verify-recovered-app restaura só em clone offline e API com o
mesmo namespace network=none, sem portas/mounts/Redis/runner/SIEM. Role SELECT
sem ownership/membership/DDL/DML/TEMP/EXECUTE public ou large objects pg_catalog;
read-only sozinho não basta. Substituir trust TCP por SCRAM do papel efêmero e
rejeitar TCP administrativo antes do boot. Não alterar grants do banco ativo.
Revisão não modifica sessões/jobs/autorizações; não é permissão de retomada.
Recibo exige API removida antes do banco e inventário inalterado. Se cleanup API
for incerto, reter DB com retained_api_cleanup_unconfirmed e nenhum sucesso.
Revisar intents próprios; nunca limpar globalmente ou iniciar labs. Testes de
ACL usam banco/papel temporários próprios, jamais revogar PUBLIC na fonte.

Reconciliação Demo (ADR0012): make reconcile-demo-backup restaura somente clone
novo com nome/label próprios, network=none e nenhum mount/porta. Plano/hash de
todas as tabelas e estrutura, locks em ordem fixa/NOWAIT, aplicação transacional
e comparação de colunas/histórico. Recusar dados reais pendentes, dispatchs,
reservas ambíguas, estados desconhecidos e tabelas extras; nunca deduzir cleanup
real. Invalidar sessões/contas/labs/grants antigos, cancelar só Demo por transições
válidas de pais e filhos, preservar timestamps existentes e scopes/aprovações.
Auditoria append-only, idempotência por ID/hash; nenhuma API de escrita recovery.
Review atual exige par id/hash esperado e fences incluindo filhos não terminais;
auditoria histórica sozinha não prova aplicação atual. API segue em quarentena,
normal_operation_permitted=false; sem worker/Redis ou retomada/cutover. Fonte,
backup e evidências anteriores intactos. Não repetir Linux/Wazuh para validar.

Ciclo recuperado Demo (ADR0013): somente make verify-recovered-cycle pode iniciar
API/worker normais e Redis novo após restore/reconciliação/quarentena conferidos.
Todos compartilham network=none do DB descartável, sem portas/mounts/runner/SIEM;
imagens locais por ID e segredos via env0600/stdin, nunca argv/recibo. Conta/lab/
ativo/campanha/aprovação novos, catálogo Demo fixo; não reativar identidades ou
jobs restaurados. Provar linhas antigas intactas por baseline privada sem acesso
runtime, quatro resultados sintéticos, métricas/relatórios e fechamento da conta,
lab/sessão. Cleanup worker→API→Redis→DB; falha retém dependências sem sucesso.
Não reinterpretar o recibo como cutover ou permissão de novo ensaio Linux/Wazuh.

Catálogo ATT&CK (ADR0014): scripts/update_attack.py separa prepare/plan/apply.
Fonte Enterprise numerada fixada por commit40hex, TLS/sem proxies/redirects,
limites e asyncio.timeout absoluto incluindo headers/corpo. Cache privado
0700/0600, artefatos exclusivos e renormalização no load; não atualizar fixture
ou baixar no startup. Plan READ ONLY fixa destino/schema, base/projeção/candidato,
testes e impactos; apply host-only exige hash revisado e administrador ativo,
locks NOWAIT/transação e zero runs/reservas/agendamentos retomáveis. Runtime
só SELECT no catálogo; não conceder UPDATE para obter locks de leitura.
Releases imutáveis, projeção preserva IDs/metadados ausentes e distingue
revoked/deprecated oficiais; absent não é revogação inferida. Não reescrever
allowlist, scopes/aprovações/relatórios/evidências antigos. Worker recusa contexto
ausente/desatualizado antes de efeitos; cleanup continua obrigatório. Cobertura
atual só mesma release/mode; indicadores históricos mantêm denominador explícito.
Histórico legado permanece desconhecido. UI/API somente leitura, paginação fixa
release e recusa mistura. Normalizador é perfil parcial, não validador STIX geral;
hash não é assinatura. Licença diferente/downgrade/reescrita/conflito/drift bloqueiam.
Testes: test_attack_document/artifacts/publication/cli/api e attack-catalog.test.tsx.
Fixtures reduzidas/19.2 são sintéticas, nunca fonte oficial de publicação.
Schema atual a0d9c7e21b45 tem32tabelas; backups977fd0c42ae8 precisam código/imagem
antigos compatíveis. Preservar imagens/dumps; não enfraquecer guardas de recovery.

Cobertura/relatórios (ADR0015): Selection em analytics.py valida modo/release e
período RFC3339 com offset, [requested_from,requested_before) por created_at da
solicitação. Legacy desconhecido retorna catálogo/avaliação null, sem backfill.
Sessão analítica própria REPEATABLE READ READ ONLY, SQL15s, limite5000runs; não
alterar isolamento da sessão de auth nem truncar métricas. Manter pais/filhos
COMPLETED no denominador e contar estados das runs separadamente. Comparação
exige manifesto igual aos test_id presentes, filhos/resultados completos, hashes
de scope íntegros e contexto conhecido; parcial/desconhecido não comprova
equivalência e não sustenta delta. Arredondar delta só após calcular frações.
Exportações HTML escapadas/JSON autocontidas, hash de todo documento sem seu
próprio campo,30/min/usuário; logs só tipo/formato/hash. UI fixa recorte/IDs,
recusa paginação mista/incompleta e bloqueia/oculta comparação cacheada após erro,
dirty ou divergência. Snapshot_at é metadado volátil, não mudança de métrica.
Tests: test_analytics_selection/queries/api, test_analysis_export e UI
coverage-filters/comparison.test.tsx; E2E Demo separado de qualquer lab real.
Autovacuum só das tabelas dos schemas/bancos pytest descartáveis é desabilitado
antes do seed para determinismo de NOWAIT; nunca fazer isso no banco ativo.

Backups cifrados (ADR0016): vault.py é host-only e pyrage1.4.0 é extra opcional
backup/dev; nunca importar crypto na API/worker ou adicionar ao lock runtime.
Somente age v1/X25519, sem plugins/SSH/senhas/cripto própria. Chave0600 separada,
sem imprimir segredo/argv. Framing fixo, manifesto4MiB/conteúdo1GiB; autenticar
stream inteiro e conferir hash/count dos bytes consumidos antes de unpack/restore,
incluindo corrida in-place. Expected SHA precisa de origem independente confiável;
public-key encryption não autentica remetente e pg_restore executa SQL.
verify-sealed usa staging privado e mesma engine/guardas offline, sem fallback ao
banco/dump fonte. Só publicar recibo após cleanup de clone E staging. Sem upload,
cutover ou limpeza de backups/keys/imagens/journals. Plano cifrado só leitura:
mínimo7snapshots distintos verificados/com chave e30dias; re-selagem não verificada
não influencia idade/ordem dos bons. Recibos locais são registros, não assinaturas.
Testes test_backup_vault e test_backup_cli; make test-recovery. SIGKILL pode deixar
staging e unlink não apaga seguramente. Chave/cópia locais não protegem contra
perda do host; destino/custódia externos precisam de decisão própria do usuário.

Prévia Sigma (ADR0017): somente rename em ProcessingPipeline/FieldMappingTransformation
oficiais core2.0.1, por versão/hash e perfil candidato inalterado. Não carregar YAML de
pipeline, vars, templates, plugins, fontes externas ou finalizers. Subconjunto plano
de strings literais, sem modificadores/fieldref/keywords/nesting; recusar antes do
parser/pipeline. Preservar valores/condição sob rename e falhar fechado em drift.
Não editar RuleVersion/histórico/escopos/veredictos ou habilitar can_convert por essa
prévia. Backend core<2 ainda incompatível; não reduzir parser ou ignorar constraints.
UI rejeita contexto/flags divergentes e sucesso cacheado depois de erro. Testes
test_sigma_mapping/test_sigma_mapping_api, sigma-mapping.test.tsx e E2E Demo.
Revisar imports upstream: registrar classes externas não autoriza instanciá-las;
guard em processo novo impede cache/backend/rede/processo/gravação e loaders.

PKI do runner (ADR0018): scripts/runner_pki.py é host-only inspect/prepare/verify,
sem apply, Docker, banco, rede ou efeitos. Ler apenas cinco arquivos públicos da
origem, nunca chaves/ids.env/journal; candidato exclusivo privado preserva IDs,
endpoint e nomes de secrets, com duas CAs/quatro chaves novas e distintas. Hashes
canônicos revisados; validar material real, pares, tempo atual e >=24h nas folhas.
Ignorar tempo somente para inventário explícito de origem expirada. OpenSSL fixo
/usr/bin/openssl, ambiente mínimo sem overrides de usuário, preservando política
padrão do sistema. fsync de arquivos, publicação e ancestrais privados, inclusive
em retry após erro; falha não produz recibo de sucesso nem apaga resíduos. Chaves
folha0444 só sob pai0700 para secrets UID10001, CAs0600; .key fora de Git/build.
Comandos make runner-pki-inspect/prepare/verify e make test-runner-pki. TLS dos
testes só echo loopback, sem runner/marcador. Preparação não prova volume/journal,
não rotaciona PKI Wazuh nem ativa lab ou renova aprovação. Troca altera descritor;
jobs ambíguos continuam em quarentena, sem replay/liberação de reserva. Ativação
e novo preflight/revisão exigem escopo próprio. Ver docs/operations/runner-pki.md.

Revisão de binding (ADR0019): GET /labs/{id}/binding-review é admin-only,
snapshot READ ONLY/REPEATABLE READ, sem runner/SIEM/auditoria de escrita. Exigir
Linux revogado/sem reserva, zero pais/filhos pendentes e confirmação terminal
CLEANED íntegra por spec/hash/geração/identidades para todo dispatch. Limite1000
bloqueia, nunca truncar sucesso; amostra25 não representa total completo. Mesmo
predicado obrigatório sob lab lock em registro Linux e bind/unbind Wazuh. Nova
solicitação Linux adquire lab lock/populate_existing antes do scope, sem inverter
run→lab de start/cancel. Cancelar pedidos pendentes explicitamente antes da
revisão; não editar histórico para passar. UI esconde sucesso cacheado após erro
ou contexto divergente. Testes make test-binding-review e binding-review.test.tsx.
Pré-requisito persistido não comprova diário/volume, PKI atual ou autorização.
Harness de ativação e ensaio real ainda pendentes; ver runner-pki-activation.md.

Planejamento de ativação (ADR0020): scripts/runner_activation.py só plan/recheck,
sem apply/lifecycle/Compose, banco/journal/runner/SIEM. Metadados via catálogo
fechado em runner_activation_metadata.py, /usr/bin/docker/Unix local, config vazia,
env mínimo, timeout10s e stdout+stderr64KiB com kill/reap; nunca Config.Env/inspect
bruto. Exigir quatro IDs sha256 locais distintos, zero containers/redes do projeto
inclusive parados, zero consumidores dos volumes, labels/local/options/datas e
arquitetura/UID revisados. Config.User ausente só normaliza root em DB/cache;
API/runner ainda exigem10001:10001. Não criar volume/imagem ausente. PKI validada
antes/depois, Compose hash, artefato0600/exclusivo/fsync em0700, SHA canônico e15min
incluindo conferência no final. Todos os gates operacionais continuam falsos;
não inferir proveniência de imagem, conteúdo do volume ou autorização. Não
regenerar plano para contornar bloqueios. Executor futuro ainda pendente, requer
intents/cleanup e novo escopo antes de iniciar Linux. make test-runner-activation
nunca inicia lab; testes usam fixtures/filhos Python em temporários.

Continuidade do diário (ADR0021): continuity.review nunca instancia Journal/Runner,
abre SQLite só no scratch privado e preserva DB/WAL/SHM/lock originais. Exigir lock
preexistente/quiescência, schema v1, identidade, todos os jobs terminais CLEANED e
provas conhecidas completas. WAL conservador exige formato/checksums/salts válidos
e commit final; cauda parcial/antiga bloqueia sem truncar/reparar. Restart histórico
implícito é contado, inclusive falha/retry de cleanup, sem inventar evento novo.
persisted_review.collect recebe engine explícito do banco Linux original, snapshot
READ ONLY/REPEATABLE READ15s, binding antigo exato e predicado ADR0019; nunca usar
Demo/settings como fallback. Decoder exige hash independente/flags/IDs/provas únicas.
journal_probe só /state, bundle stdin até4MiB e resumo sem conteúdo dos jobs; sem
opção de path/comando/rede, import de settings/engine/server ou lifecycle. Invocar
esse probe num volume real exige escopo específico e mount somente leitura/UID/
isolamento comprovados pelo executor futuro. make test-runner-continuity só usa
schema PostgreSQL descartável e SQLite temporário, sem volumes/containers de lab.

Intents da ativação (ADR0022): runner_activation_intents.py só registra ownership,
sem CLI/daemon/lifecycle ou autorização. Root fixo do executor futuro em
.local/pki-activation-intents; locks de outro root não protegem esse projeto.
Catálogo não inclui worker/migrate/controller/Wazuh/volumes. Eventos exclusivos
0600/hashchain/fsync, lock cooperativo e bloqueio de histórico parcial/não encerrado.
Retomada por ID/hash do begin revalida/fsync, sem repetir create/start. Escrita
incerta invalida a sessão e exige retomada; preservar todos os arquivos. Dependência
em remoção/ausente recusa novos dependentes, inclusive após resume; API incerta
retém DB/cache/runner e containers incertos retêm redes. Ausência registrada exige
hash da observação mas não comprova daemon; futuro executor deve conferi-lo, assim
como plano/TTL/autorização antes de novos efeitos. Cleanup próprio precisa continuar
possível após expiração, sem reativar recursos/jobs. Testes em make test-runner-activation.

Reconciliação ownership: runner_activation_ownership.py só observa nomes/owner
composto/ID conhecido e inspect projetado com cinco labels/ID/nome exatos. Usa uma
label ID:papel, sem pressupor AND de filtros repetidos. Name substring pode bloquear
por nome parecido, nunca permitir remoção aproximada. Erro/ambiguidade/renomeação/
drift bloqueiam; repetir listas e reconferir no futuro executor antes do efeito.
Ausência nunca vem de erro no inspect. stopped_or_empty_snapshot não comprova
mounts/isolamento nem autoriza stop/rm. Sem Config.Env/inspect bruto ou lifecycle;
testes locais usam fixtures e não comprovam templates sobre objetos reais do ensaio.

Runtime do probe (ADR0023): runner_activation_probe_runtime compila somente os
papéis journal-before/journal-after, imagem por ID, Python -I/-B/módulo fixo,
stdin para provas, /state read-only/nocopy, UID10001 e network=none. Sem shell,
secrets, ports, pull ou imagem com VOLUME declarado. Revisão antes/depois exige
configuração/mounts/limites/ownership exatos. Env projetado só como key/boolean,
allowlist sem duplicatas e valores fixos; recusar LD_PRELOAD/LD_AUDIT/PYTHONPATH.
LANG/TMPDIR são explícitos na receita; LANG pode faltar só na imagem base.
Campos opcionais Go usam index. Teste opcional só consulta DemoAPI existente,
sem criar objetos nem interpretar o Demo como probe aprovado. Start intent
durável só permite probes observados e nunca repete start após crash/retomada.
probe_result confere bundle/contexto/flags/contagens/hash e compara inventário
lógico completo; isso não prova mounts, origem física, imagem ou autorização.

Cleanup de ativação: runner_activation_cleanup tem driver concreto interno,
sem CLI/Make/API. Não invocá-lo em recursos reais sem o procedimento autorizado;
testes usam daemon fixtures. Revalidar intent durável e ownership nome/labels/ID/
imagem antes de stop SIGTERM/5s ou rm, sem force/volumes. Erro só é reconciliado
por nova consulta, ausência reconferida no final. Falha retém dependências e
impede close/sucesso. Retomada exige begin hash/plano/imagens originais; expiração
não bloqueia cleanup próprio, mas nunca permite novo start. Coordenador completo,
create/start/transport de bundle e ensaio real ainda pendentes. Nenhum volume
Linux original aberto/serviço iniciado decorre destes componentes internos.

Lifecycle interno do probe: runner_activation_probe_lifecycle exige callback
confiável de gates com contexto/receita/bundle/escopo/plano/imagem/DB/volume/
consumidores e validade curta antes de create/start. Não receber esse JSON como
aprovação via API/CLI. O coordenador real ainda precisa computar os gates; fixtures
não autorizam executar driver real. _execute privado suporta stdin4MiB e prazo
até20s, saída somada64KiB, leitura/escrita concorrentes e kill/reap; consultas
somente leitura continuam sem stdin. Callback não dispensa inspeção runtime.
Start intent precede última revisão e RPC, sem retry ambíguo. Cleanup selecionado
não fecha intent pai, não remove outros recursos e respeita dependências. CONFLICT
persiste colisão antes da tentativa de create e recusa adoção/cleanup/replay até
após resume; não editar/excluir histórico para liberar. Sem novo CLI apply/ensaio.

Plano em operação: active_plan.recheck só interno, vinculando ID/SHA ao intent,
PKI/Compose/inventário atuais e TTL também após último IO. Recheck público continua
quiescente. active_metadata exige membros/IDs/imagens/labels/consumidores exatos,
inclui parados/consumidores externos e recusa CONFLICT/remoção/runner/pedido ambíguo.
Dois snapshots e guard durável, prazo absoluto20s desde a entrada até a releitura
final, por query com orçamento restante. inventory sozinho não comprova quiescência
ou autoriza efeito. Schema/SQL/volume físico/rede/proveniência/autorização continuam
gates separados; sem invocação real desses novos componentes por testes/CI.

Leitor PG fixo (ADR0024): persisted_probe só127.0.0.1:5432/aegis/aegis_app/public,
PID1/UID/GID10001/Docker marker e pipe privado. Não aceitar URL/SQL/path livres,
settings fallback ou PG* ambiental; senha só stdin16KiB, fora do contexto público.
Perfil/schema e collect na MESMA conexão RR/READONLY, SQL15s e ACCESS SHARE ONLY/
NOWAIT antes de qualquer SELECT. Role sem elevação/temporários; schema/tipos/
nullability/SELECT/RLS/herança conferidos sem ler alembic_version ou conceder grants.
row_security=off é fail-closed (erro se política filtraria, não bypass); leituras
estritas ONLY não incorporam herança anexada após verificação. APIbinding padrão
não usa only_roots. Bundle até4MiB incluindo newline, emitido só apósdispose;
capturar0600/0700, nunca ecoar/logar. Namespace físico/proveniência/harness reais
ainda separados: import/PID1 não autorizam operação. Transporte mantém consultas
64KiB e só adapter fechado pode selecionar cap4MiB de provas. Sem invocação real.

Estado de implementação em2026-10-28: DBserver lifecycle interno já registra
start antes da RPC, não repete após resume e faz readiness com pg_isready fixo
até15s/oito tentativas; sucesso mantém pai para leitores, falha limpa só ownership
próprio, cleanup incerto não é sucesso. Health não comprova autenticação/SQL.
Nenhuma invocação real desse startup ocorreu; controlador completo/escopo novo
continuam pendentes. Recheck ativo aceita dbcreate/start/running de forma fechada,
sem ampliar fases de outros papéis ou recheck público. Ver ADR0025.

Fonte da nova imagem: make runner-image-source-prepare/verify só exporta blobs
versionados de main limpa em tar privado determinístico, sem Docker/build/pull;
ID/hash e limites conforme ADR0026. Hash local não é assinatura/proveniência.
Imagem antiga do runner75059996 herda três labels Compose; não alterar essa imagem,
relaxar label_count5 ou adotar como imagem aprovada. Preparar imagem limpa com fonte
conferida e base oficial identificada. Build de desenvolvimento não é autorização
para subir Lab, acessar seus volumes, alterar PKI/binding ou executar marcador.

Imagem de preparação efetivamente construída em2026-10-28 e revisada em2026-10-29:
runner imageID b0a4879a0d89b98b3184c579566612d0ddf5837a0508a4a8125a4e1a4a0eaa17,
sourceSHA86c9ec4abe1c087e255e18a03d35fecca84757b4213c7bfec3595d44dcd21adc.
Recibo privado SHA587b1c698adc6207e09fdf362535d621785ebe5c5895d7901ff2a7ca663d3091.
Build offline verificou fonte/versões/imports comoUID10001; não é assinatura nem
permissão de Lab. make runner-image-build-review só inspeciona imagem e publica
recibo privado; não repetir build após intenção. Config digest pode vir do
Descriptor nativo; todas as fontes presentes precisam concordar. Sem artefato
build-completed anterior, build_client_exit_verified permanece false. Não apagar
intents, retaggear imagem histórica ou inferir autorização a partir desses flags.
Diagnóstico futuro deve ter plano próprio, sem renovar candidato PKI para contornar
expiração; startup original exige autorização mesmo se apenas SQL READONLY.

Diagnóstico Linux separado da ativação: ADR0028 e labs/linux/DIAGNOSTIC.md. Plano /3
fixa escopo/commit/source/build e receipt oficial PG por hashes independentes; /1 e
/2 eram preparação e não podem virar autorização implicitamente. Run host-only
exige confirmação explícita do startup original e scopeSHA exato; isso é afirmação
do operador local, não assinatura humana. Não fornecer esses flags em recursos
reais sem nova autorização específica do usuário. `.env` só é lida no run, somente
APP_DB_PASSWORD no perfil gerado, sem interpolation/fallback/reset. Worker/API/
Redis/Wazuh/runner servidor/marcador/migração/grants/PKI/binding não são iniciados.
Startup PG modifica metadados/WAL no volume original RW, consultas são READONLY;
diário sempre RO. Limite300s para novos efeitos, pedido exclusivo por plano e lock
compartilhado, no replay. Cleanup por planSHA/opID/beginSHA aceita prazo expirado,
não exige senha/PKI atual e não remove volumes. Incerteza de leitor retém DB.
Fixtures completas não comprovam ensaio nativo. Em2026-10-29, o usuário aprovou
um diagnóstico único: operação de7aabdff5b04c5da116a86bb2d10496 interrompida antes
do start, container PG criado/removido e operação encerrada, volumes preservados.
Nenhum SQL ou diário foi lido; autorização consumida e plano faea59ae... não pode
ser repetido. Segunda tentativa especificamente aprovada após CI SUCCESS: operação
e6566b9db97d47e88f9e8197a0f85c15, plano ef77bb4c..., PG iniciou com inspeções e
readiness confirmadas; primeiro leitor falhou sem produzir prova validada. Dois
containers próprios removidos, operação fechada, volumes preservados/sem consumidores.
Sem diário/marcador/PKI/binding; essa autorização também está consumida. Não supor
autenticação, consulta SQL ou continuidade verificadas pelo readiness do PG.
Não editar/remover intent ou pedido para liberar replay. Ver evidência
docs/evidence/diagnostic-2026-10-29 e labs/linux/DIAGNOSTIC.md. Metadados oficiais PostgreSQL
já foram consultados por TLS/sem pull; vínculo local não é assinatura nem hash de
todos os layers. Testes: make test-runner-diagnostic; scripts não entram na API.

Rejeição do leitor (ADR0024): envelope fechado até4096bytes/contextSHA exato, sem
mensagens de driver/SQL/segredos. Motivos/etapas em allowlists; flags falsos estritos.
Transporte com failure_decoder é interno ao perfil de payload privado/saída4MiB,
não retorna stdout não zero nem stderr. Driver rejeita envelope também com exit0;
owned_probe só registra código/etapa revisados e sempre tenta cleanup. Não usar
rejeição como provas, causa retroativa da falha anterior ou permissão de retry.
Imagem nova8673e8d9... foi construída/conferida com fonte3e12c0b em2026-10-29;
imagem antiga b0a4879a... permanece preservada e não contém este recurso. Nenhum
diagnóstico original adicional foi executado para validar a nova imagem.

Atualização2026-10-29: em resposta ao escopo único0388cd1e..., usuário instruiu
“continuar”, explicitamente tratado como autorização condicional à CI SUCCESS.
Condição atendida/run40902712786; operação9bb5b0847b8543548cd0db8373128b4d foi
executada/encerrada, PG validado, leitor rejeitou perfil SQL, volumes preservados.
Autorização consumida, não repetir plano. Regressão em PG de testes comprovou
inet::text com /32; a0591af usa pg_catalog.host(inet_server_addr()), mantendo
comparação EXATA com127.0.0.1. Não ampliar endereço/rede, migrar ou mudar grants
para contornar o erro. Imagem8673e8d9 anterior não contém essa correção; precisa
nova imagem selada/conferida e autorização específica antes de outro ensaio.

Imagem da correção inet construída e conferida:6b9033b966eb33b9c2be6d98a3be1d1d8276617e091a39a8e851bac57f4860f0,
build02204960dac2472d9f19da40bddf853b, fonte a15b7f6. Source/imports/versões
conferidos como10001 e cliente terminou0, sem Lab/volumes originais. Último ensaio
original continua sendo9bb5b084... encerrado/rejeitado; imagem nova não foi
executada contra os dados originais. Ver PROGRESS e recibos privados inet-fix-*.

Estado mais recente: usuário autorizou especificamente a confirmação54f5b12d...
após CI SUCCESS40922479654. Operação4c28e0bfdb2a4d5f9d88076e55628b86 executada/
encerrada em2026-10-29: diagnostic_verified_and_closed, uma prova SQL antes/depois,
dois jobs/oito eventos do diário iguais, cinco recursos removidos/volumes preservados.
Hash dos bytes do recibo0be41f1dfedd58c23222a7e96538150bc43fbe851cccccf0553f07b63d343a88.
Essa autorização está consumida; não repetir ou apagar pedido/intent. Não houve
marcador, worker, Wazuh, PKI/binding ou operação normal liberada. A continuidade
comprovada é histórica/escopo exato, não lease permanente para ativação. Preparação
offline pode prosseguir; qualquer intervenção de ativação exige procedimento novo,
gates atuais e autorização própria. Ver evidência diagnostic-2026-10-29.

Rede da rotação (ADR0029): runner_activation_isolated_network só compila receita
fixa e consulta network inspect de ID já OBSERVED; sem CLI/create/lifecycle. Papel
network-isolated, bridge/internal/IPv4/defaultIPAM172.30.88.0/29 e gateway_mode=isolated,
sem membros/opções extras/IPv6/Swarm. Conferir ownership antes/depois e estado do
intent. Metadados não provam tráfego ou acesso ao host. Teste opcional só consulta
Demo existente, não cria/adota rede. Não ampliar active_metadata ou gerar candidato
PKI curto para contornar TTL antes de o executor estar pronto para revisão.

Lifecycle interno de rede (ADR0029) já compila/emite somente create fixo, com request
durável antes da RPC, gates internos frescos e inspeção/ownership após. Sucesso
retém rede vazia; falha/interrupt tenta cleanup selecionado, CONFLICT/endpoint
estrangeiro/dependente pendente impedem sucesso. Sem replay, CLI ou gates concretos
do coordenador nesta unidade. Testes só daemon fixtures; nenhuma rede real criada.
Não interpretar callback sintético ou status de configuração como autorização.

Preflight subnet (ADR0029): runner_activation_subnet_review só ls/inspect Docker
e /usr/bin/ip -json -4 route show table all, dois snapshots/20s, por query<=5s e
stdout+stderr64KiB. Recusa colisão de172.30.88.0/29, plugin/perfil incompleto, drift
ou excesso; não excluir pool por labels próprias. Ignora só default /0, compara
destino/tabela/tipo (não expiry/cache). Saída só counts/hash/subnet fixo, sem outras
redes/rotas/interfaces/gateways. Ausência de ferramenta é erro, sem install/fallback.
Não muda rede/rota nem prova alcance/host/firewall ou autoriza create. Gate concreto
precisa chamar review fresco; JSON salvo não substitui observação atual.

Recheck ativo da rede permite só network-isolated/create REQUESTED/ausente ou
created OBSERVED/vazia. Start/running/roles backend/ingress/runner/API continuam
negados; API/Redis ativos ou endpoint na rede bloqueiam antes de efeito. Metadata
continua sem autorização/isolation proof. Nenhuma ampliação do perfil de diagnóstico
/3: ele ainda aceita só os cinco papéis próprios. Plano de rotação público ainda
não é operacional; gates finais exigem vínculo da versão do executor e escopo atual.

Plano de rotação /2 exige main limpa/tool_commit antes/depois de IO e scopeSHA
que inclui formato/ID/criação/expiração/perfil/snapshot completo. Recheck ativo
exige header.scope_sha256 igual ao plano; snapshots parciais não omitem campos.
Janela15min/flagsfalse mantidas, sem CLI apply. /1 permanece preservado e recusado,
sem conversão ou reuso de aprovação. Ignorar .env para Git não autoriza ler/hashear
segredos. Fixtures agora são repositórios main temporários, nunca a branch real.

Gates internos de rede: NetworkGates vincula confirmação local de scopeSHA/plano/
operação, UTC<=300s e prazo monotônico; não é assinatura humana nem autorização
implícita. Callback create-only recompõe active_plan antes/depois de subnet.review
fresco; receita/intent/metadata imutáveis, worker não admitido. checked_at é início
do IO, gate<=20s limitado por plano/confirmação e idade<=10s no consumidor. Revisão
composta lenta é recusada, leitores mantêm seus próprios timeouts. Sem CLI/create
nativo/PKI/binding; testes só Git/PKI temporários/daemon fixture. Futuro coordenador
deve persistir hashes de evidence e obter novo escopo antes de efeitos reais.

Servidor identity-only (ADR0030): AEGIS_RUNNER_IDENTITY_ONLY=true seleciona app
somente GET /v1/identity, tests=[] e header de modo explícito; demais métodos503,
sem Runner/Workspace/Journal ou diretórios state/work abertos. TLS do entrypoint
continua obrigatório. Cliente operacional recusa allowlist vazia. Default mantém
modo anterior, Compose/Demo não foram alterados/reiniciados. Testes loopback e
boot não provam container/mount/rede reais. Imagem6b9033b9 histórica não contém o
recurso: novo build selado necessário antes do uso nativo; autorização do diagnóstico
segue consumida. Identidade não prova continuidade, binding ou capacidade de jobs.

Compiler identity_runtime só plano /2/header exatos e network-isolated OBSERVED;
create_arguments exige runner REQUESTED novo. IP fixo/ID completo, Python-I/-B,
env identity-only/UUID, três secrets RO e nenhum volume/journal/workspace/porta.
Sem RPC/leitura de chaves; não executar argumentos como atalho de autorização.
Imagem com VOLUME/env herdado e runtime/mounts precisam de revisão futura. Testes
test_runner_activation_identity_runtime não iniciam containers; perfil público
continua não operacional e diagnóstico /3 não recebe papéis/contextos novos.

identity_inspection só inspect de imagem/container por ID; OBSERVED/START_REQUESTED,
ownership antes/depois e receita/plano rechecados após IO. Created/running exigem
env/limits/processo/mounts/endpoints exatos; somente três binds RO e tmpfs opcional,
sem volumes/ports/IPv6/endereços extras. Redigir fontes/env como predicados, nunca
valores. Docker Go template usa index/defaults para campos opcionais. Check de imagem
mantém implementação identity-only/proveniência falsos: perfil básico não prova
bytes novos. Teste CLI real usa daemon Unix falso, não recursos reais. Sem CLI ou
driver start; gate/coordenador nativos ainda pendentes. Ver ADR0030.

Fence identity_start_requested só runner OBSERVED/sem start anterior, modo literal
identity-only, pki/recipe/gates hashes e network-isolated próprio OBSERVED/ID exato;
todos os outros papéis precisam ABSENT. Evento precede futura RPC e marca
START_REQUESTED. identity_runtime_observed fixa hash sem permitir novo start após
sucesso/resume. Hashchain não comprova efeito, mTLS ou autorização; cleanup próprio
continua possível e retém rede até runner ABSENT. Sem driver/CLI novo ou expansão
do diagnóstico;64eventos mantidos. Testes test_runner_identity_intents só temporários.

identity_network é review somente leitura create/start/running: exige rede/runner
próprios e endpoints por ID/nome/IP/prefixo, não apenas contagem. Create vazio;
start vazio ou runner próprio parado; running um membro e fence identity-only.
Outros papéis nãoABSENT bloqueiam. Dois snapshots completos/20s/queries com prazo
restante, plano/receita/intent relidos após IO. Não comprova quiescência global,
tráfego ou mTLS e não inicia nada. _configuration da rede só valida campos sem
membership; validate/review antigos continuam exigindo vazio. Não usar o helper
privado para ignorar endpoints. Ver testes test_runner_activation_identity_network.

Contextos ativos de runner só identity-create/identity-start/identity-running;
create/start/running genéricos ainda negados, outras roles não recebem identity.
Só runner/network-isolated nãoABSENT e zero consumidores de volumes; running exige
start identity-only/runtime duráveis. active_plan confere recipe/PKI/rede do fence
contra plano atual. Não reescrever start incompatível. Diagnóstico /3 ainda recusa
runner/fases identity antes dos inputs. Fato de ownership não prova modo/mounts/
tráfego: combinar inspeções físicas e gates antes de efeito. Sem CLI/start reais.

identity_image exige recibo selado existente/hash revisado e build_client_exit_verified
booltrue antes de reconciliar metadata; não gerar prova ausente. Imagem/commit vêm
do plano, referências de build são apoio. Fonte de pacote/requirements.lock/pyproject
precisa igualar main limpa atual; trocar commit não atualiza imagem antiga. Sem
build/pull/start/SQL/diário. Reusa somente verificadores de inputs do diagnóstico,
não seu lifecycle/autorização. Flags de assinatura/modo runtime/operação são falsos.

CI em três partições Python fixas0/1/2 por hash canônico (mais PINNED revisado) via run_ci_tests.py,
coletando tudo e selecionando cada caso exatamente uma vez. Workflow precisa conter
todos; falha/partição vazia/path externo/PYTEST_ADDOPTS são erros. React em job próprio,
lint/tipos/advisory Python no0, cancelamento redundante/cache preservados; sem paid
features. Nunca omitir partição para obter green ou tratar collect-only como execução.
Localmente rodar shards em sequência por PG/Redis15. Teste test_ci_partitions confere
união/recusas/workflow. Limite18min mantido em cada shard; timeout anterior não é
evidência de testes aprovados. IDs parametrizados precisam ser estáveis para comparar
coletas entre processos. Ver docs/development/testing.md.

ConfirmedPlan fixa operação/beginSHA e expiração <=beginUTC+300s, além de <=300s
desde confirmação. Reconstruir gate não renova orçamento, mesmo com plano15min
válido. Recusar clock anterior à confirmação/último evento e prazo monotônico;
não inferir assinatura/atestado de relógio. NetworkGates usa esse componente,
diagnóstico histórico não muda. Cleanup independente de lease expirada; futuro
resume somente reconciliação/cleanup, sem renovar gate para novos efeitos.

identity_probe /1 é GET-only/TLS1.3 em172.30.88.2:8443, PID1/UID10001/stdin privado,
contexto fechado/hash/identidade/folha DER/CAs fixadas. Sem URL/comando livre,
redirect/compressão/chave antiga/volumes;12s total, caps de input/header/body/certs,
leitura nonblocking/nofollow e sem SSLKEYLOGFILE/overrides. Reset/EOF na omissão de
cliente é INCONCLUSIVE; só alerta TLS explícito comprova requisito. Expiração ou
falha de rede não são rejeição da CA por issuer. Exit0 pode ser revisão inconclusiva,
nunca permissão operacional. Não afirmar cliente autenticado sem transporte do
servidor; identidade com material não o comprova. Normal/activation/marker/volumes/
old-client-rejection flags falsos. Testes loopback não autorizam invocação nativa.

tls_peer captura certificado DER de ssl_object/CERT_REQUIRED para prova privada
ASGI por conexão, nunca de headers do cliente. Só identity-only emite headers de
hash/policy/version para dataclass válida. Wrapper antes de tasks/parser, scope
copiado, extensão reservada sobrescrita e instância não reutilizável; sem contextvars
ou prova de outra conexão. self.app depende de Uvicorn0.54.0 exato: upgrade bloqueia
identity startup até revisão/testes, não relaxar guard para obter green. Modo normal
auto preservado, sem dependências novas. Probe /1 ainda ignora esses headers; não
afirmar consumo/verificação pelo cliente antes da próxima versão explícita.

Probe TLS /2 agora exige headers do adapter e cliente DER esperado, além de janela
UTC<=300s. Peer cliente/política são fatos separados da rejeição negativa: reset
continua inconclusive/negative=false. Janela antes de arquivos/cada conexão e
timeout min(12s, restante); histórico pode ser decodificado expirado sem rede.
decode_result fecha schema/hash/tipos/classificação até4KiB, sem provar origem;
coordenador deve assegurar runtime/imagem próprios. /1 não é convertido por rehash.
Flags de ativação/volumes/marker/old-client-rejection permanecem falsas.

identity_request prepara /2 somente de ConfirmedPlan vivo/main limpa e inventários
públicos fixados, conferidos duas vezes. Não ler .key/ids.env/.env nesse builder;
expiração vem da confirmação original, nunca renova orçamento. Sem Docker/PKI
write. Teste host→probe→decoder usa exclusivamente loopback com SNI/SAN/DER de
candidato temporário preservados, não altera HOST/PORT produtivos ou permite alvo
livre. Não confundir prova pública com keypair/runtime/gate completo.

IdentityGates reutiliza a mesma instância ConfirmedPlan/restrição300s da rede, sem
JSON de gate/confirmação como entrada. Create/start/running fechados; start após
fence é negado. Combina active_plan antes/depois, sealed image current/source,
image profile, membros exatos e mounts físicos; timeout/freshness antes de publicar.
Hashes de evidência só em memória até coordenador persistir. Testes de composição
usam fixture apenas na fronteira do recibo selado, coberta separadamente por
testes reais de arquivos. Não inferir TLS/ativação de gate ou fake daemon.

identity_server é driver interno create/start apenas, não executor autorizado.
ConfirmedPlan/main/fence exatos antes da RPC; lifecycle precisa impedir repetição
START_REQUESTED ambígua e reconciliar ID retornado/cleanup. Sem CLI/exec/restart.
Testes do driver emulam replies; nunca invocam daemon real.

identity_lifecycle só IdentityGates concreto e runner novo (ABSENT também bloqueia
replay). Create intent/gate/ID reconciliado; start gate/fence durável/inspeção
repetida antes da RPC; running físico/evidência durável/gate final. Driver RPC
limitado ao orçamento UTC/monotônico restante, recusa outros papéis ativos. Sucesso
retém servidor/rede sem provar TLS/readiness; falha limpa só runner próprio, mesmo
após expiração/interrupção. Colisão pré-create vira CONFLICT sem delete/adoption.
Rede/volumes/histórico permanecem; cleanup incerto é pendência, nunca sucesso.
Resume de intent não autoriza repetir role. Sem CLI/coordenador nativo autorizado.

Imagem nova identity-only preparada/selada em2026-10-30: build5ccbca482dd649b58f90b89d85c4d885,
image526267ad8a54df12ffe130724874bb79bcdbb6ecb61345afe3a1ddc1d3085be5,
sourceSHA d7c788d66194c5b6d7d227745e8ca794d1ab7834893fb23550a662c381919c6c,
receiptSHA dfa0b726b3c21ab35610bbd2af86c15c03ec45426ce81ca0b12e644f550d8e70.
64arquivos/43runtime/3build/imports/compat guard verificados comoUID10001. Recibos
privados identity-mode-*; imagens históricas preservadas. Build não iniciou Lab,
não renovou candidato nem ativa PKI. Sem CLI/ensaio autorizado; runtime/mTLS nativos
continuam pendentes. Ver docs/evidence/identity-image-2026-10-30.

Role identity-client é dedicada ao probe GET-only, não API/controller genérico.
Request exige runner OBSERVED identity-only/runtime hash e rede OBSERVED/ID do
fence, sem outros papéis ativos. Start fixa request/recipe/gates/IDs de pais;
reply guarda só hashes e preserva fence. Cleanup cliente→runner→rede; cliente
incerto retém pais. Max64 eventos e diagnóstico /3 permanecem fechados. Contextos
ativos antigos continuam recusando cliente presente; runtime/gates próprios ainda
pendentes. Testes de hashes/intents não comprovam TLS ou origem do resultado.

identity_client_runtime só compila role dedicada/servidor identity-only observado,
recipe/manifesto reais e plano/hash/contexto fixados. IP172.30.88.3, pipe sem TTY,
quatro mounts RO (CA servidor/cert e key cliente novos + CA servidor antiga pública),
nenhum volume/key antiga/env livre. _create_arguments compartilhado é privado e
recebe só receitas internas; server mantém stdin fechado/IP.2. Sem RPC/arquivo de
payload/leitura de key. Gates/inspeção física/captura ainda pendentes antes de uso.

identity_client_inspection só created/exited, stdin privado e IPAM.3 exatos, quatro
binds RO/mode/limites/env/ownership/fence/contexto conferidos. Servidor público
continua só created/running, stdin fechado e IP.2. Helper físico privado compartilha
predicados, não cria fase operacional nova. Cliente exited pode ter IP operacional
limpo, conservando IPAM/rede configurados; não inferir ausência/presença de tráfego
disso. Cada query dentro do restante20s, drift/timeout bloqueiam. Saída hashes/
predicados apenas; TLS/result/origem exigem prova separada. Sem driver/start CLI.

identity_client_network só create/start/exited: runner próprio running/IP.2 sempre
presente; cliente próprio parado/IP.3 opcional após create conforme allocation/
release, nunca membro estranho ou ausência do runner. IDs/nomes/IP/prefixo/MAC/
EndpointID únicos, ownership/images/count e bridge exatos, dois snapshots/20s.
Fase exited exige fence/contexto/IDs fixados. Não inferir quiescência global/TLS/
tráfego dessa projeção. Review antigo de runner único permanece fechado ao cliente.

Balanceamento CI: somente identity_lifecycle e diagnostic_coordinator inteiros
fixados no0 após durations reais427º (537s/943s). Restante continua SHAfile%2.
Nenhuma exclusão, nova máquina ou aumento de timeout. Toda mudança de PINNED exige
teste de complementaridade e comparação real dos nodeIDs da coleta completa.
Relatório2726=1379+1347/zerooverlap/zeroomissões é coleta, não execução de testes.

Estado2026-11-03: cliente agora tem contextos dedicados identity-create/start/exited
no active_metadata/active_plan, mantendo contextos runner antigos fechados quando
cliente presente. Exige pai running com fence/runtime e rede própria; projeto,
nomes reservados e consumidores globais dos dois volumes conferidos duas vezes.
active_plan exige request_context_sha256 só nesse papel e confere fence/recipe/
IDs; nenhum outro papel recebe esse parâmetro. Diagnóstico /3 continua recusando
cliente antes de inputs. Isso é revisão de metadata/PKI, não TLS/ativação/CLI.

identity_request.review revalida bytes/hash existentes e public pins contra a
mesma ConfirmedPlan, sem criar contexto/janela novos. Exige created>=confirmed_at,
expiração original e operação/plano/scope/IDs/PEM/DER exatos. Rehash de input
semanticamente diferente não o autoriza. Source/main/material/intent relidos após
IO e decode temporal final; não lê chaves, não grava payload ou conecta à rede.
Outra confirmação não pode adotar request anterior; resume permanece cleanup.

IdentityClientGates combina mesma ConfirmedPlan300s/request existente, active_plan
antes/depois, fonte/imagem selada, perfil físico de parent/client e membership
exato. Só create/start/exited, start com fence anterior negado. Final active_plan
revalida manifesto/material completos; decode final revalida bytes/janela sem
repetir leituras crypto equivalentes. Gate fecha contexto/resourceIDs/checks bool/
freshness e guarda cópia privada/evidência hashes em memória. Não prova TLS/output
ou autorização assinada; lifecycle/captura/coordenador e persistência ainda pendentes.

Transporte privado _execute aceita novo perfil fechado4KiB além dos perfis
64KiB/4MiB existentes. Conta stdout+stderr, retorna só stdout e mantém EOF/
kill/reap/ENV/config Docker saneados. Failure decoder continua exclusivo do4MiB;
nenhum comando/payload livre foi exposto. Reap do CLI não comprova container
encerrado: lifecycle deve reconciliar/limpar por ownership independentemente.

identity_client_driver exige IdentityClientGates e último gate computado recente
com hash igual à evidência; JSON positivo não entra. Start exige fence/gateSHA/
request/IDs exatos, revalida payload público original e congela intent antes da
RPC. Budget menor entre10s create/15s attach e restante UTC/monotônico, output4KiB
e decoder fechado. Admissão em memória consumida até em falha; recheck falho
revoga cache. Lifecycle ainda deve impedir replay durável após resume e limpar
container próprio: kill/reap CLI não o comprova. Sem exec/restart/CLI/API nova.

Estado CI2026-11-03: run435º41641991673 excedeu18min nos dois jobs (annotations
confirmadas), sem aprovação presumida. Agora3shards com max-parallel2/timeout18
inalterados/runners padrão; arquivos inteiros PINNED lifecycle0/coordinator1,
restante SHAfile%3. Todos os casos seguem exatamente uma vez. Coleta2830=1046+
1041+743/zerooverlap/zeroomissões inclui lifecycle ainda no worktree na conferência;
não significa execução aprovada. Sem aumento de concorrência ou recurso pago.

identity_client_lifecycle usa somente IdentityClientGates concreto e role nova
(ABSENT/reopen também bloqueiam replay). Create/ID/gates/fence antes de attach;
inspeção exited/gate/reply hash antes de evento observado. Cleanup só cliente
próprio; colisão não adota/apaga, cleanup incerto retém pais. Reply protocolar
verificado não torna controls_inconclusive em TLS confirmado. Gate records têm
revisões normalizadas em memória; coordenador deve persistir antes de efeitos.
Sem CLI/ensaio autorizado, sem uso de volumes/worker/journal/PKI ativa.

IdentityArtifacts é host-only, intent novo/ConfirmedPlan concreta, diretório de
operação exclusivo0700 e nomes fechados/O_EXCL0600/fsync. Não reabrir writer ou
sobrescrever parciais. Gravar só JSON normalizado público, nunca key/senha/raw
stderr/exceção. Confere anchor/header/inodes/permissões/hash e inventário fechado;
recibo/cleanup após expiração/closure não renovam autorização. Hash não é assinatura.
CI436º41647053065 passou3partições:2807Python+8skip opcionais; React79passou.

RecordedServerGates/RecordedClientGates e before_network_create persistem fatos
normalizados/gate/evidência antes de retornar admissão, sempre mesma confirmação.
Lease/intent/freshness rechecados depois do fsync; falha de persistência/recheck
revoga cache do cliente. Artefato não permite replay. Gates nativos não invocados.

IdentityBudget: efeitos até begin+240s; leituras/cleanup nativos até begin+300s,
monotônico original e UTC mínimo. Sem renovar janela ao reconstruir ou após
rollback. Adaptadores nativos fechados; ownership/cleanup só3roles identity e
mesmos operation/plan. Expiração normal não bloqueia cleanup; corte300s retém
incerteza, nunca force/volume delete. Nenhum native CLI/ensaio autorizado.

Artefatos identity também consomem plano com identity-assay-requested.json
O_EXCL0600/fsync junto a plan.json, fixando requested artifactSHA e anchor. Nova
operação/root não autoriza reutilizar plano consumido. Fence parcial é preservado;
não apagar para retry. Nenhum arquivo PKI original/candidato é alterado por isso.

Identity coordinator interno integra apenas bridge/identity-only runner/client,
mesma NetworkGates e budget240s/300s, persistência antes de RPC e cleanup sempre.
Erro de IO pode deixar recibo incompleto; nunca sucesso artificial. Controles
inconclusivos preservados, cleanup incerto retém pais, interrupção propaga após
cleanup/recibo quando possível. Sem CLI/novo ensaio autorizado. Ver labs/linux/IDENTITY.md.
Novo test_runner_identity_coordinator inteiro PINNED0 (133s local;CI436grupo0=369s
versusgrupo2=924s), demais pins preservados. Coleta2896=1088+1041+767 exata, não testes
aprovados;3shards/max-parallel2/18min continuam. Não excluir casos para otimizar CI.

runner_identity_review é CLI somente leitura: pins independentes op/begin/plano/
scope e digest JSON canônico do CORPO do recibo. Confere envelopes/inventário/
fatos de gates/request/reply/classificação, duas leituras e arquivos privados.
Não abre plano/intents/PKI, não grava/renova lease/consulta Docker; funciona após
expiração. Exit0 é integridade salva, mesmo se ensaio falhou. recorded_* não prova
runtime atual/origem TLS/fence do plano ou autorização de retomada. Nunca executar
componentes por import manual para contornar CLI nativa/escopo ainda pendentes.
PINNED inclui client_lifecycle0 (132s local, ausente do commit CI436º). Coleta
2916=1103+1061+752 exata após leitor, não testes aprovados; política CI inalterada.

runner_activation.load_for_cleanup lê plano histórico /2 com o MESMO hash/schema/
policy, permitindo expiração apenas para cleanup próprio. Não abre PKI/volume/
credenciais/daemon nem concede create/start/lease; load_plan/recheck permanecem
atuais. Não usar leitor histórico em gates/compiladores/ativação.
