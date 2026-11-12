# Compatibilidade do banco Linux na ativação

Estado atual: o original foi migrado explicitamente d446→b7 sob aprovação da #5
em12/11/2026. [Relatório e encerramento](../../labs/linux/CAMPAIGN-2026-11-12.md):
33tabelas, histórico/senhas preservados; catálogo versionado ainda vazio, sem
seed/bootstrap e sem campanha nova. O restante desta seção preserva a evidência
da #48, conferida em11/11/2026. O PostgreSQL original foi copiado a frio
em mount read-only/nocopy, sem iniciar servidor sobre ele nessa etapa de backup. Restore e upgrade
foram executados somente nos clones; os resultados reais constam abaixo.
Os testes automatizados continuam usando histórico sintético descartável.

## Versões e estratégia

| Perfil | Schema | Uso permitido |
|---|---|---|
| Lab original verificado | `d4465b7aca2a`,27tabelas com Alembic | Helpers administrativos fechados v3; sem API/worker atuais |
| Backup intermediário previsto anteriormente | `a0d9c7e21b45`,32tabelas com Alembic | Perfil anterior e testes; não é a revisão atual do original |
| Rotação administrativa v3 | `d4465b7aca2a` | Cinco helpers fechados de continuidade/binding/preflight; sem API normal ou worker |
| Aplicação atual | `b7f3c2d91a06`,33tabelas com Alembic | API administrativa somente após upgrade explícito e revisão dos grants |

`b7` acrescenta `scheduled_reports`, índices, checks e trigger/função de
imutabilidade. Não transforma tabelas antigas. A aplicação atual consulta essa
tabela; trocar a imagem não migra o banco nem concede seus privilégios.

Estratégia escolhida: backup e restore em clone isolado, upgrade d446→b7
no clone e revisão de inventário/grants. Para a rotação, usar a imagem revisada
somente nos cinco entrypoints administrativos compatíveis com d446; não migrar o
original. Testes de lifecycle rodam sobre schema d446 descartável, e o perfil
recusa a0/b7. Isso não torna API normal/worker atuais compatíveis com d446.
Não executar o serviço Compose `migrate`: ele também faz seed e muda
o segredo do papel runtime. Aplicar Alembic com credencial owner apenas durante
a intervenção aprovada; grants com o segredo existente, sem rotação implícita.
Sem seed, bootstrap, worker, scheduler ou campanha.

Inventário local somente de metadados em11/11:

- `aegis-before-scheduled-reports:20261109` / imagem
  `sha256:9e3fe0c86a8361520f882aaaad5928c72d3fa3633eec55bbb82c7f780c108add`
  existe como retenção anterior à feature de snapshots. Ausência de label de
  commit impede afirmar por metadados que seu conteúdo corresponde a uma fonte
  revisada; ainda precisa de conferência antes de uso.
- `aegis-scheduled-reports-validated:20261109` / imagem
  `sha256:b8abe5e44af4bad90d2e302a045f38fb9cf268932be5ea0493fc72f078657a23`
  existe e continua sendo a imagem do Demo. Isso não prova compatibilidade de
  runtime/mounts/PKI do Lab. Não reutilizar sua tag para build.
- A imagem runner revisada na #3 não é imagem da API nem prova schema b7.

Rollback: manter imagem antiga por tag, backup d446, volumes originais e fences.
Restaurar backup apenas em clone distinto, validar e revisar a escolha do volume
explicitamente. Nunca sobrescrever original com restore ou executar downgrade
como recuperação: remover `scheduled_reports` perderia novos snapshots. Imagem
antiga sobre banco b7 não é rollback validado. Um recibo de binding novo também
não permite desfazer a versão do ambiente, grants ou aprovações históricas.

## Procedimento de clone autorizado nesta conversa

Fixar IDs das imagens, fonte, projeto, dois volumes e candidato PKI; revalidar
ausência de consumidores. Backup PostgreSQL17 completo deve incluir ACLs,
schema/dados/versão e inventário lógico independente. Guardar dump privado0600,
manifesto/hash e imagem existente; não imprimir dados ou senhas. O diário não
foi montado nesta etapa; sua revisão WAL-aware pertence ao ensaio nativo.
Não reutilizar backup Demo.

Restaurar em volume/DB clone identificado por nonce, sem API/worker/rede externa.
Comparar todas as linhas/tabelas antigas, IDs, scopes, approvals, receipts,
cleanups, reservas, constraints e grants antes/depois. Confirmar27→33tabelas,
novas tabelas vazias e provas SQL íntegras. Aplicar grants mínimos
de `aegis.operations.runtime_grants` somente nesse banco, preservando senha.
Runtime não lê Alembic e não altera/apaga recibos/cleanups/auditoria; UPDATE dos
snapshots fica limitado às colunas de processamento. Encerrar recursos próprios
sem remover originais/backup/PKI. Qualquer diferença não prevista bloqueia.

Resultado real: cópia fria de51.434.896bytes/1.439entradas; inventários da fonte
read-only, cold-backup e working-copy idênticos, SHA256
`3e35cf6195d79e45a328822a4198c6a6fc5979117c795a85cc886d2b02189f48`.
O inventário real corrigiu a hipótese a0: fonte d446/27tabelas. Dump custom PG17
397.998bytes, SHA256
`4ef1bc67cdb7013198c76890685eab8f59785683226aa32b001900379ef5e969`.

Restore em volume novo confirmou todas as linhas/colunas, contas e verificadores
de senha. ACL do dono explícita versus implícita foi normalizada apenas quando
semanticamente igual; nenhum privilégio runtime foi ignorado. A primeira
inicialização do clone usava um superusuário temporário que o PostgreSQL fixa no
catálogo; esse clone foi preservado e substituído por outro clone novo com o
mesmo nome de bootstrap da fonte, sem reset ou alteração da fonte.

Upgrade explícito d446→b7 passou `alembic check` na imagem Demo retida, após
conferir todos os arquivos de migração contra a fonte. Comparação das26tabelas
de dados antigas usa suas colunas originais: as quatro colunas ATT&CK adicionadas
por a0 não representam perda/reescrita dos valores anteriores. Seis tabelas novas
vazias, contas/ACLs antigas preservadas. Grants mínimos aplicados apenas no clone:
recibos/cleanups/auditoria sem UPDATE/DELETE, snapshots com UPDATE por coluna e
Alembic inacessível ao runtime. Senhas não foram rotacionadas.

Recibo final privado: `.local/linux-schema-clones/1947140a2cd4411d81b9e686ff21358c`;
evidência canônica SHA256
`f6ded75cdfe08dbdc3d24d439681babd749869d0dda44d0d1209bbd11da2635a`.
Dump/globals privados no diretório bce29bd182564212ad88173d4b9fe61f. Houve falhas
de preparação/validação intermediárias, registradas nos ledgers; nenhuma gerou
nova cópia do original. Todos os containers próprios foram removidos e fences
fechados após conferir ausência. Volumes intermediários, backup, journal, PKI,
qasrc e imagens históricos preservados. A evidência não autoriza migração original.

Para consumo pelo pacote, foi derivada evidência canônica
`03fcbe5979e75a719300318ce2e6c735142a96ebfa8722320e0ea3585d12f935`: somente o
hash dos metadados do volume normaliza options null→{}, como o inventário
`runner_activation_metadata.inventory`. A evidência original e um recibo separado
dessa normalização permanecem preservados; nenhum dado/backup foi alterado.
O [ensaio nativo posterior](../../labs/linux/ROTATION-2026-11-12.md) abriu PostgreSQL
no original exclusivamente para conta temporária, binding/preflight e verificação;
o schema original continuou d446, sem grants ou senhas existentes alterados.

## Verificação executável sem Lab

`.venv/bin/pytest tests/test_linux_schema_compatibility.py -q`:

- Histórico Linux sintético, incluindo CLEANUP_FAILED com confirmação CLEANED;
  a0→b7 preserva todas as linhas e ACLs antigas e passa `alembic check`.
- Histórico d446→b7: compara todas as colunas originais de cada tabela,
  aceita somente as adições explícitas e mantém as novas tabelas vazias.
- Dump custom/restore transacional com ferramentas PG17 do container de
  desenvolvimento já existente, restrito ao schema aleatório da fixture;
  comparação integral antes/depois e novo upgrade. Sem esse container o caso
  é explicitamente skip; o teste aditivo continua obrigatório na CI.
- Papel NOLOGIN descartável recebe os grants reais no schema da fixture;
  recibos imutáveis, Alembic inacessível e updates de snapshots limitados.

Não executar simultaneamente com outras suítes PG/Redis15. A restauração de
fixture não comprova backup/restore do volume original ou implantação Linux.
