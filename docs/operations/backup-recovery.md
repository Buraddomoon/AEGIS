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
   internos de eventos, versões Sigma e scopes de campanhas/agendamentos. Arquivos e diretórios são
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
`reconciliation_applied=false` permanecem explícitos.

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
API em quarentena leu o backup de30tabelas/2.884linhas;9 rotas,4 tentativas SQL,
5 entrypoints e TCP administrativo bloqueados; inventário igual/clones removidos.

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
