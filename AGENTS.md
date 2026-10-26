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
