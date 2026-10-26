# Backup e recuperação do Demo

O banco é a fonte durável; Redis guarda limites e heartbeat. Há uma ferramenta
operacional real para criar backup consistente e verificar restauração num
PostgreSQL efêmero **sem rede, portas, API, workers ou scheduler**. Ela não troca
o banco em uso nem recupera automaticamente uma instalação. Ver [ADR0010](../architecture/decisions/0010-demo-backup-rehearsal.md).

## Preparação

Usar o checkout confiável, `make setup`, Docker local já instalado e o Demo
padrão em funcionamento. Esta versão é deliberadamente restrita ao projeto
`aegis`, banco/usuário administrativo `aegis`, PostgreSQL17 e schema public.
A ferramenta usa o socket Unix do Docker **somente no host**, com configuração
CLI vazia temporária e ambiente saneado para não herdar proxies/credenciais; não é instalada
como endpoint nem recebe socket dentro da aplicação.

A conexão administrativa vem de DATABASE_URL local em `.env`, nunca de um
argumento contendo senha. Ela precisa da porta loopback18782 do override de
desenvolvimento. Se o Demo ainda não a expõe, `make infra` adiciona esse acesso
local ao db/redis do projeto; não publicar essa configuração externamente.
Não efetuar migrações/DDL durante o backup. Nenhum serviço Wazuh é necessário.

O schema atual é `a0d9c7e21b45`, com32tabelas após versionamento do ATT&CK.
Dump de schema antigo pode ser verificado como dados pelo manifesto original;
boot/reconciliação/ciclo da aplicação exigem código/imagem com a mesma revisão.
Não reconstruir a tag atual e esperar que um backup977fd0c42ae8 seja aceito:
preserve imagem por ID, configuração e commit compatíveis. Não remova guardas
de revisão nem migre silenciosamente um clone para contornar essa recusa.
No marco do catálogo, as imagens antigas foram preservadas localmente como
`aegis-catalog-previous:demo-977fd0c42ae8` e
`aegis-catalog-previous:recovery-977fd0c42ae8`; tags não são backup off-host.
O backup anterior e um novo backup32tabelas foram restaurados/verificados como
dados; isso não é outro ensaio completo de ciclo recuperado na revisão nova.

Criar diretórios privados; em instalações antigas, restringir `.local` existente:

```bash
mkdir -p .local/backups
chmod 700 .local .local/backups
make backup-demo
```

A saída informa um ID, hash e caminho privado. `created_not_yet_verified` significa
somente que dump e manifesto foram criados. Nenhuma senha ou conteúdo de linha é
impresso. Arquivos têm0600, diretórios0700 e precisam pertencer ao operador;
symlinks e arquivos públicos são recusados. Dumps são ignorados pelo Git e pelo
scanner staged. Não enviar arquivos privados para issues, commits ou CI.

## Verificar uma restauração

```bash
make verify-backup BACKUP_ID=ID_INFORMADO_PELO_BACKUP
make backup-retention-plan
```

A verificação:

1. Confere ID, formato, permissões e SHA-256 do arquivo local.
2. Usa a mesma imagem PostgreSQL por ID imutável já disponível no host,
   sem pull. Cria apenas `aegis-recovery-<uuid>` com label de ownership.
3. Inicia banco próprio em tmpfs, sem rede/portas/mounts do host/volumes duráveis;
   filesystem read-only, no-new-privileges,1CPU/768MiB/128PIDs. Limite do tmpfs
   de dados1GiB: apropriado ao pequeno Demo, não promessa de escala.
4. Registra intenção privada durável antes da criação; reconcilia nome exato e
   ownership mesmo se o daemon criar e a resposta se perder. Remove somente o schema public vazio desse clone, sem CASCADE, porque o
   dump o recria. Restaura em transação única com exit-on-error e sem ACL/owner.
5. Compara todas as linhas, contagens, revisão Alembic, colunas, constraints,
   tipos/typmods/collations de colunas, índices/flags, triggers habilitadas e
   funções inventariadas. Recalcula hashes
   internos de eventos, versões Sigma, documentos do catálogo ATT&CK e scopes de campanhas/agendamentos. Arquivos e diretórios são
   sincronizados com fsync antes de anunciar publicação.
6. Confere ownership antes de remover o container. Só grava recibo
   `verification-<uuid>.json` após comparação **e cleanup** aprovados.

Snapshot REPEATABLE READ READ ONLY exportado é compartilhado com pg_dump:
inventário e arquivo representam o mesmo snapshot, mesmo com escritas concorrentes.
Identidade do cluster da conexão local precisa corresponder ao db do Compose.
O manifesto contém contagens/hashes, não o conteúdo das linhas. O inventário
é versionado como aegis-pg-inventory/2; o envelope segue aegis-demo-backup/1.
Manifestos experimentais sem essa versão não são restaurados pela CLI atual:
criar novo backup e preservar os antigos, sem reescrever seu histórico. O plano
de retenção mantém esses legados e informa unsupported_inventory_preserved.

PostgreSQL pode reescrever uma conversão varchar[]→text[] durante dump/restore.
A comparação `pg17-literal-array-casts/1` normaliza **somente** essa conversão
quando todos os elementos são literais varchar, preservando valores/aspas.
Não tenta provar equivalência SQL genérica. Outros tipos/NULL/funções/diferenças
continuam estritos. Versão1 recusa sequences, views, RLS/policies, tipos customizados, procedures e
outros recursos não inventariados, em vez de ignorar silenciosamente seu estado.

[Ensaio executado em2026-10-22](../evidence/recovery-2026-10-22/README.md):
30 tabelas/2.884linhas conferidas e clone removido. Isso é uma medição específica,
não RPO/RTO ou benchmark. Arquivos do primeiro ensaio ainda não verificado foram
preservados, sem reescrever o manifesto para fazê-lo passar.

## Falhas e retenção

Erro não é sucesso: dump parcial pode permanecer privado, sem manifesto completo;
comparação/restore/cleanup com erro não cria recibo verificado. Erros PostgreSQL
podem conter valores sensíveis e ficam em `.local/recovery-errors`,0600; a saída
apresenta apenas identificador do diagnóstico. Falha de cleanup exige inspeção.
Ctrl+C passa pelo finally; SIGKILL, queda do daemon ou desligamento podem deixar
um clone. Intenções/resultado de cleanup permanecem privados em
`.local/recovery-intents`; `observed_absent` registra só o estado visto, não uma
garantia sobre um daemon indisponível/operação pendente. Consultar somente os recursos próprios:

```bash
docker --host unix:///var/run/docker.sock ps -a --filter label=io.aegis.recovery
```

Antes de remover manualmente um clone, conferir nome exato, label ownership,
network=none e ausência de mounts persistentes. Não usar prune, down -v ou
limpeza de todos os containers. Backups, volumes e journals dos laboratórios
Linux/Wazuh continuam fora dessa limpeza.

`backup-retention-plan` é **somente leitura**, verifica manifestos/arquivos e
sugere revisão dos backups com mais de30dias, preservando os sete mais recentes
e todos com até30dias. `review_only` não é autorização ou execução de exclusão.
Não há limpeza automática de backups, eventos, auditoria ou evidências. Backups
antigos exigem revisão de retenção legal e necessidade de recuperação antes de
exclusão manual específica. Backups não verificados não substituem cópias boas.

## Boot da API recuperada em quarentena

```bash
make recovery-app-build
make verify-recovered-app BACKUP_ID=ID_INFORMADO_PELO_BACKUP
```

O build cria somente a tag local `aegis-recovery-local:0.2`; não reinicia ou
substitui a imagem do Demo em uso. O ensaio fixa o ID imutável dessa imagem,
requer o mesmo backup confiável/privado e não aceita destino, comando ou endereço
de rede arbitrário. Não é uma interface de upload/restauração web.

Após restaurar e verificar o inventário, a ferramenta cria no clone um usuário
somente SELECT, sem ownership, memberships, DDL/DML/TEMP ou EXECUTE de funções
da aplicação e de large objects. Acesso TCP exige senha efêmera SCRAM para esse
usuário; conexões administrativas TCP são recusadas. Somente o operador, via
docker exec no banco descartável, conserva administração por socket local.
Esses grants e revogações nunca são aplicados ao banco em uso.

A API compartilha exclusivamente o namespace de rede do clone network=none,
ouvindo 127.0.0.1 **dentro** dele. Não publica portas nem recebe mounts do host,
socket Docker, configuração/credenciais SIEM, runner ou Redis. API com usuário
10001, filesystem read-only, cap-drop ALL,384MiB/1CPU/64PIDs e tmpfs64MiB;
PostgreSQL mantém os limites do ensaio de dados. A soma dos limites é1,125GiB,
sem incluir overhead do Docker/host; não é medição de consumo.

`OPERATING_MODE=recovery` é decidido no boot, sem endpoint de reativação. Apenas
GET health/live, health/ready e recovery/review existem. Readiness/review exigem
token novo independente das sessões do backup; token e senha só duram no
container descartável e no arquivo env temporário0600 durante create. Nenhum
segredo é incluído em intenção/recibo ou argumentos do processo Docker.

A revisão agregada `aegis-recovery-review/1` mostra contagens de sessões,
filas/estados, reservas, autorizações, agendamentos e dispatches históricos.
Não retorna senhas, nomes, tokens, comandos, scopes ou evidências brutas. Confere
privilégios e revisão Alembic da imagem; incompatibilidade mantém503. Contagens
zero não liberam operação: `normal_operation_permitted=false` e
`reconciliation_applied=false` permanecem explícitos nesse comando. Auditorias
de reconciliações anteriores são contadas como histórico; não comprovam uma nova
aplicação nem autorizam retomada.

Probes exigem recusa de login/sessão histórica, rotas normais, escrita/DDL/TEMP e
large objects mesmo após SET TRANSACTION READ WRITE, além de autenticação TCP
administrativa. Worker, scheduler, seed/grants e migrações abortam em recovery.
O inventário deve continuar igual após a API. Intenções de ambos são duráveis;
cleanup remove API antes do banco, conferindo ownership mesmo após create
ambíguo. Só depois de tudo aprovado grava `application-verification-*.json`.
Se cleanup da API não for confirmado, o banco fica preservado e a intenção
registra `retained_api_cleanup_unconfirmed`; revisar os dois nomes/labels,
encerrar/remover primeiro a API e depois seu banco, sem comandos globais.
Falhas não publicam sucesso e exigem a mesma revisão de clones/intents descrita
acima. Recibos anteriores permanecem preservados.

Esse ensaio valida **boot restrito e leitura**, sem abrir o dashboard operacional,
fazer login normal, reconciliar dados ou retomar tarefas. Não inicia labs Linux/
Wazuh, workers ou scheduler operacionais. Ver [ADR0011](../architecture/decisions/0011-recovery-quarantine.md).

[Ensaio executado em2026-10-23](../evidence/recovery-2026-10-23/README.md):
API em quarentena leu o backup de 30 tabelas/2.884 linhas;9 rotas,4 tentativas SQL,
5 entrypoints e TCP administrativo bloqueados; inventário igual/clones removidos.

## Reconciliação Demo no clone descartável

```bash
make recovery-app-build
make reconcile-demo-backup BACKUP_ID=ID_INFORMADO_PELO_BACKUP
```

Esse comando restaura **outro clone novo**, confere o inventário original e
aplica um plano fixo somente nesse clone. Não aceita endereço, SQL ou container
do operador e não modifica o banco em uso, o dump ou seu manifesto. Não existe
endpoint de reconciliação na API. Não ligar Linux/Wazuh para satisfazer checks.

Antes de enviar SQL, confere nome/label próprios, network=none e ausência de
mounts/binds/portas. Plano privado contém contagens, bloqueadores e hash SHA256
de todas as tabelas/estrutura, sem linhas ou credenciais. Recusa tabelas extras,
revisão incompatível, jobs reais pendentes, dispatch de runner em run pendente,
testes/ativos mistos, reservas órfãs ou estados/filhos inconsistentes. Um único
bloqueador impede toda a aplicação; o plano fica preservado para revisão manual.

A aplicação usa administração por socket **somente do DB descartável**, locks
em ordem fixa/NOWAIT e uma transação. Refaz o hash sob lock, recusando drift.
Apaga sessões, desativa usuários, revoga laboratórios e incrementa a versão dos
que estavam autorizados. Revoga grants recorrentes, encerra agendamentos
retomáveis e cancela runs/filhos pendentes comprovadamente Demo, registrando as
transições válidas por run e simulação. Preserva ended_at já existente e não
alega cleanup externo ou modifica classificações defensivas.

Aprovações/scopes antigos ficam intactos para auditoria, vinculados às runs
agora terminais; não são reutilizados. Resultados, eventos, regras, comprovantes
e histórico anterior são protegidos por comparação no SQL e inventário posterior.
Um erro, inclusive no último INSERT de auditoria, faz rollback de todas as
mudanças. Repetição do mesmo ID/hash retorna o registro anterior sem novo efeito;
mesmo ID com outro plano é recusado. O CLI cria outro clone em cada invocação.

Antes de remover os clones, inicia somente a API em recovery com role SELECT.
O boot recebe o par esperado RECOVERY_RECONCILIATION_ID/HASH: review exige
exatamente esse recibo e fences atuais (sessões, usuários ativos, pais/filhos
pendentes, reservas, labs, agendamentos e grants). Um registro antigo sozinho
não muda o veredicto. A API continua sem login, mutações, worker ou Redis e
normal_operation_permitted=false. Novo drift faz review/readiness retornarem503.

Recibo `demo-reconciliation-verification-*.json` só é gravado após aplicação,
preservação do histórico, boot/probes, inventário novamente igual após leitura
e cleanup API antes de DB. Distingue snapshot_rows das linhas após auditoria.
Intenções/planos/aplicação privados não substituem esse recibo final. Cleanup
incerto da API retém o DB e impede sucesso, como no ensaio anterior.

Não é retomada normal nem cutover: todas as contas e labs restaurados ficam
desativados. Novo administrador/credenciais, autorização Demo e aprovação nova
para um ciclo sintético ainda precisam ser validados em destino separado.
[ADR0012](../architecture/decisions/0012-demo-recovery-reconciliation.md).
[Ensaio real e recibo](../evidence/reconciliation-2026-10-23/README.md): inventário
original2.884linhas,1auditoria nova, vínculo ID/hash confirmado e clones removidos.

## Primeiro ciclo Demo no destino recuperado

```bash
make recovery-app-build
make verify-recovered-cycle BACKUP_ID=ID_INFORMADO_PELO_BACKUP
```

Extensão opt-in: os comandos anteriores continuam sem iniciar Redis/worker.
Esse ensaio faz restore, comparação, reconciliação e probes da API em recovery;
remove aquela API e somente então prepara um ciclo novo no mesmo DB descartável.
Não reinicia o Demo em uso nem restaura diretamente sobre um destino existente.

Exige imagens locais da aplicação e redis:8-alpine, fixadas por ID antes dos
efeitos, sem pull no ensaio. Provisiona aegis_app com os mesmos privilégios
runtime revisados da implantação normal, sem administração/ownership ou acesso
ao schema privado de integridade. HBA permite somente esse papel por SCRAM no
loopback; TCP administrativo segue rejeitado. Credenciais SQL/Redis e senha da
conta são novas/aleatórias, em env temporário0600 ou stdin, nunca argv/recibo.

Conta administrativa, laboratório Demo revogado e ativo sintético são novos.
O catálogo precisa coincidir com os quatro testes Demo revisados. Hashes das
linhas reconciliadas ficam em schema privado no DB tmpfs, inacessível ao runtime.
API e worker normais e Redis novo compartilham somente o namespace network=none
do DB, sem portas, mounts persistentes, socket Docker ou configuração runner/SIEM.
Redis bind127.0.0.1, autenticado, sem save/AOF. Não recupera o Redis antigo.

A probe local autentica a conta nova e autoriza explicitamente só o lab novo;
cria campanha/run, verifica recusa de início sem aprovação, aprova o hash novo e
inicia uma única run. O worker real processa os quatro testes sintéticos. Confere
eventos/evidências/hashes, DETECTED/OBSERVED_NOT_ALERTED/NO_TELEMETRY/INCONCLUSIVE,
indicadores com delta1run/4testes/3válidos e relatórios HTML/JSON identificados como
sintéticos. Nenhum resultado comprova proteção Windows, Linux real ou ATT&CK real.

Depois revoga o lab novo, encerra a sessão e remove o worker antes da verificação
final. Desativa a conta nova; exige aprovação própria consumida, quatro resultados
sintéticos, zero pendências/autorizações/sessões e todas as linhas anteriores
idênticas. Alteração do histórico ou estrutura bloqueia recibo. Não cria agendamento.

Intenções duráveis para cada create, inclusive falhas ambíguas. Cleanup em ordem
worker→API→Redis→DB, com nomes/labels exatos. Falha em um filho retém dependências,
registra retained_cycle_cleanup_unconfirmed no DB e não emite sucesso; revisar
as intenções antes de remover manualmente somente esses recursos próprios.
SIGKILL/daemon indisponível continua exigindo revisão manual, sem prune global.

Recibo final demo-cycle-verification-*.json só aparece após todas as fases e
cleanup. Distingue a revisão em quarentena do ciclo normal limitado ao clone.
Não é cutover, failover, recuperação de efeitos externos ou RPO/RTO garantido.
[ADR0013](../architecture/decisions/0013-recovered-demo-cycle.md).
[Ensaio real](../evidence/recovered-demo-2026-10-23/README.md):1run/4testes
sintéticos,2.885linhas anteriores intactas, relatórios e cleanup confirmados.

## Recuperação operacional completa permanece manual

Dumps contêm hashes de senha, sessões, scopes e evidências. Guardar criptografados,
fora do host e com acesso restrito;0600 não é criptografia. Hashes detectam mudança
acidental e não são assinatura: alterar dump e manifesto juntos pode enganar a
comparação. **Restaurar SQL somente de origem confiável**; o PostgreSQL pode
executar código contido num dump. Não há importação web de arquivos de backup.

Este backup não contém roles globais, ACLs, secrets/.env, certificados, Redis,
artefatos externos ou journals do runner. Guardar configuração/PKI separadamente,
com controle de acesso e sem colocá-las no repositório. A imagem identificada
precisa permanecer disponível; recuperação em outro host/versão não foi validada.

Para recuperação efetiva: provisionar destino vazio separado, restaurar arquivo
confiável, revisar roles/privilégios runtime e migrações necessárias. Antes de
iniciar qualquer worker, invalidar sessões/credenciais conforme o incidente e
reconciliar jobs, aprovações, reservas e agendamentos do snapshot. Não reativar
trabalhos automaticamente nem repetir efeitos externos ambíguos. Fazer um ciclo
Demo controlado no novo destino antes de um cutover autorizado. `verify-backup`
verifica fidelidade; `verify-recovered-app` acrescenta somente o boot em quarentena.
Nenhum dos dois demonstra failover, reativação normal ou recuperação de efeitos
reais. RPO/RTO e
política de retenção destrutiva não estão estabelecidos.

Fontes: [pg_dump17](https://www.postgresql.org/docs/17/app-pgdump.html),
[pg_restore17](https://www.postgresql.org/docs/17/app-pgrestore.html),
[snapshots exportados](https://www.postgresql.org/docs/17/functions-admin.html#FUNCTIONS-SNAPSHOT-SYNCHRONIZATION).

## Cópias cifradas

A extensão host-only age/X25519 acrescenta `backup-keygen`, `seal-backup`,
`verify-sealed-backup` e `backup-vault-plan`. A cópia cifrada pode ser decriptada
e restaurada no mesmo clone offline sem acessar banco/dump fonte. Originais,
chaves, imagens e evidências não são removidos; retenção permanece só plano.
[Procedimento, custódia e limites](encrypted-backups.md). Transporte externo,
guarda independente de chaves e cutover continuam pendentes.
