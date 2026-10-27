# Troca coordenada da PKI do runner — plano, sem execução autorizada

Este documento prepara a revisão de uma intervenção futura. Nenhum comando de
ativação ou ensaio foi executado neste incremento. As autorizações de outubro21/22
continuam consumidas. A ferramenta atual oferece somente inspect/prepare/verify.
Este plano não é um executor e não recebe uma aprovação pelo simples merge/push.
O novo harness `runner_activation.py` acrescenta **plan/recheck somente de
metadados**, descritos abaixo; ainda não oferece apply ou lifecycle.

## Perfil inicial delimitado

Priorizar o Linux integrado, projeto **aegis-linux-lab**, API loopback18785,
runner172.30.88.2, arquivos Compose root → linux/compose.yml → linux/platform.yml.
Não iniciar simultaneamente standalone/integrado com os mesmos IDs/volume.
Demo18780 e Wazuh ficam fora da intervenção. Primeiro ensaio deve verificar
confiança/identidade/diário **sem criar marcador**, sem nova campanha/start.

Origem pública existente: `.local/linux-lab`. Candidato offline atualmente
preparado: `.local/pki-candidates/90204499ca2144aca175fe809538b7e7`;
manifestoSHA256 `24179f34ad0a2c708496e9b0b3798a18d547c4648975c95893330458f0ed8d5f`.
Descritor candidato `d1b616e115fecdf115652472656b4a82e6cd1c65f45b778f0239a2b4afbd566f`.
Esses hashes identificam uma preparação; sua validade não é permanente. Reverificar
material/tempo real imediatamente antes da revisão/uso. Se não houver>=24h nas
folhas, preparar outro candidato e atualizar o escopo/hash; não reutilizar recibo.

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

Estado atual: guardas do backend, harness de planejamento/rechecagem e componentes
de revisão do banco/diário disponíveis. A integração desses componentes ao executor,
a inspeção autorizada dos volumes Linux originais e o ensaio continuam pendentes.

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

O formato `aegis-runner-activation-plan/1` fixa manifesto/descritores/IDs PKI,
hashes dos três Compose, origens esperadas dos secrets individuais, daemon,
imagens e os dois volumes. Exige ausência de containers **inclusive parados**,
redes do projeto/nome reservado e consumidores dos volumes de qualquer projeto.
Volumes precisam existir com labels/local/sem opções externas e data com timezone.
Uma ausência/ocupação bloqueia sem criar substitutos ou parar o consumidor.
Não desmontar recursos de terceiros para fazer a revisão passar.

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
