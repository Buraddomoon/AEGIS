# Troca coordenada da PKI do runner — plano, sem execução autorizada

Este documento descreve uma intervenção futura de ativação completa, ainda não
executada. `runner_pki.py` oferece inspect/prepare/verify e `runner_activation.py`
oferece **plan/recheck somente de metadados**, sem apply de rotação. O diagnóstico
separado de banco/diário foi executado e encerrado em29/10; o ensaio identity-only
tem CLI própria, mas não foi executado. Esses estados não equivalem à ativação.
As autorizações anteriores estão consumidas; um commit/push não concede nova
aprovação. Ver [estado consolidado](../product/roadmap.md).

Para a conferência mTLS inicial, o servidor agora oferece um modo de identidade
sem Runner/Journal/Workspace, sem rotas de jobs e com allowlist vazia. Ainda não
foi implantado nem validado em container próprio. Sua imagem e coordenador já
foram preparados/testados; em05/11, o preflight foi bloqueado por sobreposição de
rede e o usuário determinou preservá-la. Não confundir identidade com prontidão de execução ou
continuidade do volume. Ver [ADR0030](../architecture/decisions/0030-runner-identity-only.md).

## Perfil inicial delimitado

Priorizar o Linux integrado, projeto **aegis-linux-lab**, API loopback18785,
runner192.168.253.2, arquivos Compose root → linux/compose.yml → linux/platform.yml.
Não iniciar simultaneamente standalone/integrado com os mesmos IDs/volume.
Demo18780 e Wazuh ficam fora da intervenção. Primeiro ensaio deve verificar
confiança/identidade/diário **sem criar marcador**, sem nova campanha/start.

Origem pública existente: `.local/linux-lab`. Candidato offline **histórico,
expirado e não utilizável**: `.local/pki-candidates/90204499ca2144aca175fe809538b7e7`;
manifestoSHA256 `24179f34ad0a2c708496e9b0b3798a18d547c4648975c95893330458f0ed8d5f`.
Descritor candidato `d1b616e115fecdf115652472656b4a82e6cd1c65f45b778f0239a2b4afbd566f`.
Esses hashes identificam uma preparação; sua validade não é permanente. Reverificar
material/tempo real imediatamente antes da revisão/uso. Se não houver>=24h nas
folhas, preparar outro candidato quando o executor estiver pronto para revisão e
atualizar o escopo/hash; não reutilizar recibo ou renovar TTL de artefato antigo.

Volumes esperados: `aegis-linux-lab_journal` e
`aegis-linux-lab_postgres-data`, observados presentes sem containers em2026-10-27.
Nomes presentes não comprovam conteúdo/labels/mounts/integridade. A intervenção
deve verificar esses vínculos antes de criar qualquer recurso; volume ausente ou
ambíguo aborta, sem criação substituta. Não transportar o diário para outro runner.

## Troca dos arquivos montados

Todos os arquivos da tabela vêm **do mesmo candidato verificado**. Preservar o
connection.json, IDs, endpoint e nomes dos secrets internos; mudar somente a
origem host revisada em AEGIS_LAB_CONFIG_DIR. Não sobrescrever o diretório antigo,
concatenar raízes ou acrescentar confiança antiga para facilitar a transição.

| Serviço | Secret | Arquivo candidato |
|---|---|---|
| runner | runner_server_key | runner-server.key |
| runner | runner_server_cert | runner-server.crt |
| runner | runner_client_ca | client-ca.crt |
| API/worker/controller | controller_server_ca | server-ca.crt |
| API/worker/controller | controller_client_cert | runner-client.crt |
| API/worker/controller | controller_client_key | runner-client.key |
| API/worker/controller | controller_connection | connection.json |

Chaves das CAs, CSRs, manifests e diretório inteiro não entram nos containers.
Compose monta secrets por arquivo; parar/recriar os consumidores necessários é
parte da troca. `restart` não aplica uma configuração Compose alterada. Uma troca
parcial deve falhar mTLS, sem verify=false ou confiança dupla como fallback.
[Secrets](https://docs.docker.com/compose/how-tos/use-secrets/),
[recriação](https://docs.docker.com/reference/cli/docker/compose/up/),
[limites de restart](https://docs.docker.com/reference/cli/docker/compose/restart/).

Os targets Make de lifecycle ainda selecionam o ids.env original. **Não usar up/smoke
como executor de rotação.** Plan/recheck já fixam hashes/perfil/ambiente e verificam
metadados; falta implementar o executor com gates internos e fechamento no finally.
Não sobrepor lab.env Wazuh com ids.env Linux: os projetos têm PKIs/segredos distintos.

## Ordem e pontos de interrupção

1. Revisar escopo humano, imagens locais por ID, manifesto atual, IDs, labels e
   volumes; material original e histórico permanecem preservados. Registrar
   hashes públicos/configuração e identidade do ambiente; não imprimir segredos.
2. Consultar o banco **próprio do Linux Lab**, sob procedimento autorizado,
   comprovar laboratório revogado e ausência de reservas/pais/filhos pendentes.
   Aplicar a [revisão persistida](linux-binding-review.md) e verificar o diário
   original. Nunca deduzir o estado do Linux a partir do banco Demo.
3. Dispatch/efeito ambíguo interrompe a rotação operacional. Recuperação sob
   descritor alterado ainda não está implementada: manter quarentena, sem start,
   replay, exclusão de intent/journal ou liberação manual de reserva.
4. Com processos de execução parados e pré-condições comprovadas, recriar os
   consumidores mTLS sob o candidato aprovado, preservando volume/identidade.
   API administrativa pode ser necessária para revisão; worker deve permanecer
   parado até encerrar todos os gates. Não chamar migrate/seed/smoke implicitamente.
5. Verificar isolamento real, mounts exatos, UID/limites e integridade/continuidade
   do diário. Provar mTLS/identidade sem preparar/start/marker. Conferir recusa de
   trust/cliente antigos sem atribuir ao trust um erro causado apenas por expiração.
6. Registrar o binding Linux novo explicitamente; confirmar incremento da versão,
   invalidade de preflight/escopos anteriores e laboratório ainda revogado. Novo
   preflight mTLS não autoriza execução. Binding Wazuh só se houver escopo separado.
7. Encerrar os serviços/redes próprios, contas temporárias e quaisquer recursos
   efêmeros; preservar os dois volumes, material original/candidato e evidências.
   Conferir ausência de marcador/start e não declarar operação normal liberada.

Falha em qualquer gate impede avançar. Não retornar ao trust antigo para contornar
um bloqueio; manter o laboratório revogado/parado e os artefatos para investigação.
Sem remoção de volumes, expurgo, replay, upload, alterações de rede/sysctl ou
parada de serviços de terceiros. Recurso criado pelo ensaio futuro precisa de
intent durável, nome/label exatos e cleanup verificável; dúvida no fechamento
retém dependências e impede recibo de sucesso.

## Fora deste ensaio futuro

Não executar novo marcador nem campanha, não iniciar Wazuh, não rotacionar PKI do
Indexer/manager/agente/Filebeat, não migrar host nem trocar credenciais humanas.
Uma campanha posterior exige outro escopo/solicitação/aprovação separada. Prova
de handshake/diário não é evidência de detecção, ingestão SIEM ou retomada segura.

Estado atual: diagnóstico separado dos volumes originais foi **verificado e
encerrado em2026-10-29**, conforme [evidência](../evidence/diagnostic-2026-10-29/README.md).
É uma revisão histórica, não uma licença permanente para ativar PKI. Contratos de
rede/lifecycle/preflight estão implementados, sem create nativo; integração do
executor completo, gates e ensaio de rotação continuam pendentes.

## Harness de metadados executável

`scripts/runner_activation.py plan` inspeciona somente metadados locais e publica
um plano privado. `recheck` compara o plano com o estado atual. Ambos exigem PKI
válida; não abrem banco/diário, não chamam runner/SIEM e não aceitam comandos ou
outros projetos. Não requerem a instalação do Wazuh. Os comandos Docker usam
`/usr/bin/docker`, socket Unix local, config vazia e ambiente mínimo, ignorando
contextos, DOCKER_HOST/proxies/credenciais do usuário. Não leem `.env`.

Revise os quatro IDs completos **já presentes** no Docker: application, runner,
postgres e redis. Tags, abreviações, imagens ausentes ou repetidas são recusadas;
nenhum pull/build ocorre. O plano verifica arquitetura Linux nativa e UID explícito
da API/runner. ID de imagem não prova sua proveniência, conteúdo ou correspondência
ao código atual; isso continua um gate humano/operacional pendente.

```bash
make runner-activation-plan PKI_SOURCE=.local/linux-lab \
  PKI_CANDIDATE=.local/pki-candidates/ID_RETORNADO PKI_SHA256=HASH_DO_MANIFESTO \
  APPLICATION_IMAGE_ID=sha256:HASH_COMPLETO RUNNER_IMAGE_ID=sha256:HASH_COMPLETO \
  POSTGRES_IMAGE_ID=sha256:HASH_COMPLETO REDIS_IMAGE_ID=sha256:HASH_COMPLETO
# Retorna plan_path e plan_sha256; não retorna uma autorização.
make runner-activation-recheck ACTIVATION_PLAN=CAMINHO_RETORNADO \
  ACTIVATION_SHA256=HASH_CANONICO_REVISADO
```

Substitua os placeholders por hashes reais distintos. Alternativa direta:
`.venv/bin/python scripts/runner_activation.py --help`. Plan aceita `--output-root`,
separado da origem/candidato, padrão `.local/pki-activation-plans`; sem exclusões.
Make sem variáveis completas é recusado, sem tentar descobrir/baixar imagens.

O formato `aegis-runner-activation-plan/3` fixa manifesto/descritores/IDs PKI,
hashes dos três Compose, origens esperadas dos secrets individuais, daemon,
imagens e os dois volumes. Exige ausência de containers **inclusive parados**,
redes do projeto/nome reservado e consumidores dos volumes de qualquer projeto.
Volumes precisam existir com labels/local/sem opções externas e data com timezone.
Uma ausência/ocupação bloqueia sem criar substitutos ou parar o consumidor.
Não desmontar recursos de terceiros para fazer a revisão passar.

Também exige Git/main limpa e fixa tool_commit antes/depois dos IO. scope_sha256
vincula formato, ID único, criação/expiração, perfil e snapshot completo (incluindo
commit/PKI/Compose/imagens/daemon/volumes/mounts). Planos iguais com outro ID têm
escopo diferente. Código alterado/commit novo ou escopo diferente no intent bloqueiam
recheck; `.env` ignorada não é lida/hasheada pelo planejamento. Campos faltantes no
snapshot não podem omitir verificações. O formato `/2` anterior só pode ser lido
pelo caminho de cleanup histórico, com integridade/política exatas; nunca compila
efeitos atuais nem é rehashado para `/3`. Pedidos/resultados do probe também são
versão `/3` e recusam o formato `/2` anterior.

Cada consulta tem10s e64KiB somados stdout/stderr; excesso/falha mata e recolhe
somente o filho CLI. Projeções nunca retornam Config.Env, Mountpoint ou inspect
bruto. Config.User ausente em imagem oficial DB/cache equivale ao padrão root;
API/runner continuam exigindo10001:10001. Metadados de volumes não provam conteúdo,
integridade, continuidade dos fences ou mounts futuros.

Plano exclusivo0600/diretório0700, flush/fsync, sem sobrescrever anteriores.
`plan_sha256` é hash do JSON canônico, **não sha256sum plan.json**; precisa de
registro esperado independente confiável e não é assinatura. Recheck exige política
exata, até15min, PKI/Compose/metadados atuais iguais e TTL válido também ao final.
Mudança exige investigação/plano novo, nunca edição do plano ou do histórico.
Falha de publicação pode deixar artefato privado: presença não é recibo de sucesso.

`metadata_plan_revalidated_not_activated` afirma apenas a comparação de metadados.
`pending_gates` explicita autorização própria, proveniência, banco, diário, runtime,
mTLS, registro revogado e encerramento. Todas as flags de autorização/ativação/
verificação interna/operação normal permanecem **false**, assim como
`profile.executor_implemented`. Nenhuma destas consultas impede alterações
concorrentes do host/daemon: um executor futuro deverá recalcular todos os gates.

Testes: `make test-runner-activation`, fixtures Docker e processos Python pequenos
em temporários; sem containers, marcador ou banco. Revisão arquitetural somente
leitura complementa testes e não é pentest nem validação do volume original.

## Componentes de continuidade implementados

`aegis.lab_runner.persisted_review.collect` recebe engine explicitamente do
chamador e identidade/hash do binding antigo fixados pelo plano. Não descobre
credenciais, não usa banco Demo como fallback e não consulta runner/SIEM. Cria
snapshot próprio READ ONLY/REPEATABLE READ15s; exige laboratório revogado/ocioso,
ativo real, vínculo antigo exato e ao menos um dispatch CLEANED conhecido. Reutiliza
ADR0019 e exporta o histórico completo até1000; vazio/incompleto bloqueia. Sem
auditoria de escrita, alteração de binding ou liberação de reserva.

O bundle privado inclui as provas originais e precisa de hash esperado independente
ao ser decodificado. O hash não autentica remetente nem comprova que o banco veio
do volume correto. O executor ainda deverá conferir esse vínculo físico antes de
usar o resultado. Não imprimir o bundle em logs nem expor uma rota pública nova.

`aegis.lab_runner.continuity.review` examina diretório privado do UID do processo,
sem criar arquivo na origem ou instanciar Journal/Runner. Exige instance.lock
existente e exclusivo, arquivos regulares limitados e sem links, nomes conhecidos
e estabilidade antes/depois. Copia DB+WAL para scratch; SHM é reconstruído ali,
nunca na origem. WAL não é ignorado: formato/checksums/salts/commit final são
conferidos antes do SQLite. Perfil conservador recusa caudas antigas de reset,
incompletas ou danificadas; não truncar ou reparar para fazer a revisão passar.

SQLite query_only/read-only/trusted_schema off/authorizer restrito, schema v1
exato, integrity_check/foreign_key_check e orçamento de instruções/tempo. Confere
identidade do protocolo, spec/hash/geração/recibo, todos os jobs terminais CLEANED
e os eventos. Comprovantes conhecidos precisam coincidir integralmente; jobs
standalone adicionais são preservados e revisados. Restart legado sem evento é
explicitamente contado, inclusive quando houve falha/retry de cleanup. Não
reescrever eventos antigos para ocultar essa limitação.

`python -m aegis.lab_runner.journal_probe --expected-sha256 HASH_REVISADO` é o
ponto de entrada para **um probe futuro autorizado**: lê bundle por stdin até4MiB,
somente /state e devolve resumo/hash do inventário, sem specs/markers/recibos ou
paths. Não aceita destino/comando, não conecta serviços nem importa settings/
servidor/engine do runner. Seu uso sobre os volumes reais **não ocorreu**. Antes
de invocá-lo, o executor deve provar volume exato read-only, UID10001, network=none,
imagens por ID/proveniência e cleanup durável. Não montar volume real para testar
esse comando sem escopo específico. Não há target Make que o faça implicitamente.

Os resultados mantêm vínculo físico/ativação/operação normal falsos. O inventário
lógico completo permite comparação antes/depois sem depender do layout de
checkpoint; não autentica exclusão de passado desconhecido nem substitui fences
do backend. Testes: `make test-runner-continuity`, só schema PG e diários temporários.
[Decisão](../architecture/decisions/0021-runner-journal-continuity.md).

## Ownership e encerramento duráveis

`scripts/runner_activation_intents.py` fornece armazenamento interno, sem CLI de
ativação. Registra ID/hash do plano e referência do escopo, recursos de catálogo
fechado e observações de IDs/ausência. Referenciar SHA de escopo não verifica nem
concede autorização. Nenhum evento chama Docker, runner, banco ou rede.

Root padrão .local/pki-activation-intents, privado, com lock cooperativo durante
a operação. O executor futuro deve fixar esse root; escolher outro diretório não
protege contra a operação existente. Eventos exclusivos0600 numerados, encadeados
por hash e fsync antes do retorno. Histórico pendente/parcial/inesperado bloqueia
outra operação. Não apagar lock, pasta vazia ou arquivo truncado para liberar.

IDs completos e nomes/labels são derivados do projeto/nonce/papel. Somente DB,
cache, API, runner, journal-before/journal-after e três redes são recursos próprios.
Volumes, worker, migrate, controller e Wazuh não podem adquirir ownership. Mesmo
quando create falha sem ID, a intenção preserva nome/labels para reconciliação
exata; isso não é autorização para remover por prefixo, nome parecido ou projeto.

Remoção precisa de intenção própria; ausência e fechamento precisam do hash de
observação produzido pelo executor. Enquanto API estiver incerta, preservar DB/
cache/runner; preservar redes enquanto houver containers incertos. Não criar novo
dependente de recurso em remoção ou ausente, inclusive após resume. Observação
tardia de ID não reinicia um recurso cujo pedido de remoção já foi registrado.

Publicação interrompida invalida a sessão; artefatos são preservados. Retomada
explícita por ID/hash do begin revalida histórico, transições e durabilidade,
sem executar/repetir efeitos. Estado em memória divergente é recusado. Resumo
de escrita incerta informa publication_unconfirmed_requires_resume.

absence_recorded_not_runtime_verified mantém autorização/ativação/ausência real/
operação normal false. O armazenamento não prova consultas nem presença/ausência
no daemon, mount, PKI ou journal. O executor ainda deverá confirmar tudo antes
dos efeitos e no encerramento. Plano/TTL/escopo válido é obrigatório para iniciar
novos efeitos; expirou não significa abandonar cleanup de recursos próprios.
[ADR0022](../architecture/decisions/0022-activation-resource-intents.md).

Reconciliação disponível em `runner_activation_ownership.py`, ainda interna e sem
CLI de lifecycle. Cruza nome, owner composto ID:papel e ID histórico; inspect exige
nome/ID/cinco labels exatos. Lista por nome usa substring documentada: nome parecido
é bloqueio conservador, sem limpeza por aproximação. Label única evita ambiguidade
de AND/OR para filtros repetidos. Ausência depende de listas vazias repetidas,
incluindo ID anterior; erro de consulta/inspect nunca vira ausência.

Projeção mostra somente identidade, imagem/estado do container ou contagem de
membros da rede. Rede com membros/container rodando não são stopped_or_empty_snapshot.
Mesmo um snapshot parado/vazio mantém effects_authorized/runtime_mounts_verified/
network_isolation_verified/normal_operation_permitted false. Ainda requer prova de
runtime, autorização e nova conferência antes de cada efeito. Testes usam fixtures;
não houve inspeção real de objetos de ativação nem criação/remoção para validar isso.

## Receita do probe e cleanup interno

`runner_activation_probe_runtime.py` compila só journal-before/journal-after;
não chama create/start. Imagem por ID, entrypoint Python isolado e módulo fixo,
hash em argv/bundle por stdin, UID10001, /state read-only/nocopy, rede none,
root read-only, capabilities removidas e limites192MiB/0,5CPU/16pids. Scratch
tmpfs64MiB noexec/nosuid/nodev e shm1MiB; nenhum secret/socket/porta. Imagem com
VOLUME declarado bloqueia antes do efeito. O executor futuro precisa reconferir
que o volume original existe: --mount de volume nomeado pode criar um ausente,
logo metadados não são uma trava atômica contra outro escritor do daemon.

Revisão projetada compara imagem/referência/argv/UID/mount efetivo+nocopy/opções/
namespaces/limites/estado e ownership antes/depois. Env só nomes/booleans, nunca
valores: allowlist sem duplicatas, PATH/LANG/flags/TMPDIR fixos, recusa overrides
do loader. LANG/TMPDIR explícitos; campos opcionais Go usam index. Projeção
completa foi parseada em DemoAPI **já existente**, somente leitura. Essa consulta
não executou probe nem demonstrou o runtime no journal Linux real.

`probe_start_requested` registra recipe/gates/bundle SHA antes do efeito, somente
para probe observado. Mesmo sem confirmação de start, retomada não pode repeti-lo.
`runner_activation_probe_result.py` decodifica contexto/identidade/flags/contagens
e compara inventários lógicos completos. Hash/saída não substituem proveniência,
mount, banco físico, mTLS ou autorização humana; flags operacionais continuam falsas.

`runner_activation_cleanup.py` implementa cleanup **interno**, sem comando CLI ou
target Make de lifecycle. Seu driver concreto não foi invocado em recursos reais.
Recebe store travado/retomado e imagens originais do plano; revalida bytes duráveis,
nome/cinco labels/ID/imagem antes de cada stop SIGTERM/5s ou rm sem force/volumes.
Erro ambíguo exige consulta nova, nunca ausência inferida do erro. Retém dependências
incertas, repete ausência no final e só então encerra o intent. TTL/PKI expirados
não abandonam cleanup próprio. Consulta final não impede alterações posteriores
por root/daemon; ownership local não é uma assinatura ou trava distribuída.

O componente interno `runner_activation_probe_lifecycle.py` já conecta create/start
restritos ao probe, transporte stdin limitado e gates fornecidos por callback
confiável interno. Não é um comando de ativação nem recebe aprovação JSON pública.
Cada efeito exige contexto/escopo/receita/bundle/identidade/descritor e checks
completos, UTC, idade<=10s e validade<=30s, reconferidos depois da intenção/runtime.
O callback real ainda precisa computar autorização/proveniência/DB/plano/volume.
Fixtures não autorizam invocar o driver real. O transporte privado drena pipes
enquanto envia até4MiB; saída64KiB/prazo20s/kill-reap, sem log dos dados recebidos.

Cleanup selecionado remove só o probe e mantém o intent pai aberto. Colisão
observada antes da tentativa de create fica em CONFLICT durável, sem adoção ou
cleanup posterior, inclusive após resume. Sem desbloqueio automático ou edição
do histórico. Start ambíguo não é repetido, e interrupção mantém cleanup próprio.

Ainda faltam coordenador completo e implementação real dos gates/transporte do
snapshot PostgreSQL,
vínculo físico do banco original, mTLS novo/recusa do trust anterior, registro
revogado e escopo específico de um ensaio. Não executar componentes manualmente
para contornar esses gates. [ADR0023](../architecture/decisions/0023-journal-probe-runtime.md).

Rechecagem durante a operação está disponível somente como componente interno:
`runner_activation_active_plan.recheck` mantém PKI/Compose/inventário fixados e
vincula ID/SHA ao intent. O recheck CLI comum continua recusando projeto ativo.
`active_metadata` exige recursos próprios/IDs/imagens/labels e consumidores exatos,
inclui parados e objetos de outros projetos nos volumes, repete snapshots e confere
estado durável com prazo total20s, incluindo IO final. Não aceita exceções livres
de recursos nem converte metadados em prova física/SQL/autorização. O callback
real ainda precisa combinar esses gates com leitura do banco Linux original.

Leitor fixo já implementado em `aegis.lab_runner.persisted_probe`: senha por stdin,
contexto público fixado, loopback/PostgreSQL17/databaseaegis/useraegis_app/public,
guard de PID1/UID/GID/Docker marker, sem endpoint ou arquivo de configuração livre.
Perfil/schema/coleta compartilham snapshot RR/READONLY e locks antes de SELECT;
recusam role elevada, RLS/temporários/views/herança/tipos/nullability incompatíveis.
Runtime não pode ler alembic_version: nenhum grant ou migration é feito para passar.
Saída contém provas originais e exige captura privada<=4MiB, sem log/TTY.

O leitor não prova sozinho que loopback é o DB Linux original: driver/coordenador
deverá conferir namespace/mounts/imagem/HBA e aprovação antes do start. Esses
controles físicos ainda estão em implementação; não iniciar PG ou montar volume
real para testar o módulo. Startup de PostgreSQL escreve metadados operacionais
no PGDATA mesmo que as consultas sejam read-only, e deve constar no futuro escopo
autorizado. Não confundir SQL read-only com volume fisicamente read-only.
[ADR0024](../architecture/decisions/0024-fixed-postgresql-proof-probe.md).

Componentes do leitor e servidor disponíveis para testes locais (sem novo ensaio):

- `database_runtime` deriva namespace somente do DB próprio observado; sem mount,
  porta, destino livre ou senha em argv/env.
- `database_result` cria request privado e captura reply/contexto em arquivo
  exclusivo0600, fora do hashchain; recibo não contém provas ou credenciais.
- `database_lifecycle` usa intenção durável, gates frescos e finally cleanup; não
  fornece CLI/API de efeito. Resposta válida não dispensa remoção confirmada.
- `database_policy` prepara somente o HBA não secreto da operação,0444 em0700,
  SCRAM fixo e demais acessos rejeitados, sem alterar HBA/senhas/grants originais.
- `database_server` compila receita não root/namespace none/volume original
  RWnocopy/HBA RO. `database_inspection` confere imagem, configuração, mounts e
  ownership; imagem não pode criar volumes implícitos extras. Ver ADR0025.

Runtime do servidor ainda não iniciado no novo perfil. O template foi consultado
somente sobre metadados da imagem local e do DB Demo existente, sem SQL/lifecycle.
Isso não comprova autenticação carregada, proveniência, conteúdo do volume Linux,
exclusividade, limpeza ou autorização. Lifecycle e readiness do servidor já estão implementados/testados com fixtures.
Permanecem pendentes imagem atual/proveniência e coordenador diagnóstico completo. Não
executar os componentes isoladamente como substituto desses gates.

## Checkpoint atual do ensaio de identidade

O diagnóstico dos volumes originais citado nas seções históricas foi verificado
e encerrado em2026-10-29; autorização consumida, conforme
[evidência preservada](../evidence/diagnostic-2026-10-29/README.md). Imagem runner
identity-only selada em2026-10-30, sem equivaler a prova de runtime.

O coordenador interno de identidade integra somente bridge/servidor/cliente,
artefatos e cleanup por ownership, testados com fixtures. Consulte o
[procedimento atual](../../labs/linux/IDENTITY.md). CLI de execução, escopo final
e ensaio nativo continuam pendentes; não iniciar componentes manualmente. A
ativação PKI/binding e imagem atual da aplicação permanecem etapas separadas.
