# Compatibilidade do banco Linux na ativação

Preparação da #48, conferida em11/11/2026. Nenhum banco/volume Linux original
foi aberto, copiado ou migrado nesta sessão. O ensaio de upgrade/restore abaixo
usa histórico sintético em schema PostgreSQL descartável, não um backup do Lab.

## Versões e estratégia

| Perfil | Schema | Uso permitido |
|---|---|---|
| Lab histórico | `a0d9c7e21b45`,32tabelas com Alembic | Leitor diagnóstico limitado às tabelas antigas; sem API/worker atuais |
| Rotação administrativa v2 | `a0d9c7e21b45` | Cinco helpers fechados de continuidade/binding/preflight; sem API normal ou worker |
| Aplicação atual | `b7f3c2d91a06`,33tabelas com Alembic | API administrativa somente após upgrade explícito e revisão dos grants |

`b7` acrescenta `scheduled_reports`, índices, checks e trigger/função de
imutabilidade. Não transforma tabelas antigas. A aplicação atual consulta essa
tabela; trocar a imagem não migra o banco nem concede seus privilégios.

Estratégia escolhida: backup e restore em clone isolado, upgrade aditivo a0→b7
no clone e revisão de inventário/grants. Para a rotação, usar a imagem revisada
somente nos cinco entrypoints administrativos compatíveis com a0; não migrar o
original. Testes de lifecycle rodam sobre schema a0 descartável, e o perfil
recusa b7. Isso não torna API normal/worker atuais compatíveis com a0.
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

Rollback: manter imagem antiga por tag, backup a0, volumes originais e fences.
Restaurar backup apenas em clone distinto, validar e revisar a escolha do volume
explicitamente. Nunca sobrescrever original com restore ou executar downgrade
como recuperação: remover `scheduled_reports` perderia novos snapshots. Imagem
antiga sobre banco b7 não é rollback validado. Um recibo de binding novo também
não permite desfazer a versão do ambiente, grants ou aprovações históricas.

## Procedimento a autorizar para o original

Fixar IDs das imagens, fonte, projeto, dois volumes e candidato PKI; revalidar
ausência de consumidores. Backup PostgreSQL17 completo deve incluir ACLs,
schema/dados/versão e inventário lógico independente. Guardar dump privado0600,
manifesto/hash e imagem existente; não imprimir dados ou senhas. Copiar diário
sem abrir writer, preservando WAL/locks/fences. Não reutilizar backup Demo.

Restaurar em volume/DB clone identificado por nonce, sem API/worker/rede externa.
Comparar todas as linhas/tabelas antigas, IDs, scopes, approvals, receipts,
cleanups, reservas, constraints e grants antes/depois. Confirmar32→33tabelas,
nova tabela vazia, revisão persistida e diário íntegros. Aplicar grants mínimos
de `aegis.operations.runtime_grants` somente nesse banco, preservando senha.
Runtime não lê Alembic e não altera/apaga recibos/cleanups/auditoria; UPDATE dos
snapshots fica limitado às colunas de processamento. Encerrar recursos próprios
sem remover originais/backup/PKI. Qualquer diferença não prevista bloqueia.

Nenhum backup atual do volume original ou restauração dele foi demonstrado aqui.
Esse gate continua pendente e impede ativação nativa; os testes não o substituem.

## Verificação executável sem Lab

`.venv/bin/pytest tests/test_linux_schema_compatibility.py -q`:

- Histórico Linux sintético, incluindo CLEANUP_FAILED com confirmação CLEANED;
  a0→b7 preserva todas as linhas e ACLs antigas e passa `alembic check`.
- Dump custom/restore transacional com ferramentas PG17 do container de
  desenvolvimento já existente, restrito ao schema aleatório da fixture;
  comparação integral antes/depois e novo upgrade. Sem esse container o caso
  é explicitamente skip; o teste aditivo continua obrigatório na CI.
- Papel NOLOGIN descartável recebe os grants reais no schema da fixture;
  recibos imutáveis, Alembic inacessível e updates de snapshots limitados.

Não executar simultaneamente com outras suítes PG/Redis15. A restauração de
fixture não comprova backup/restore do volume original ou implantação Linux.
