# ADR 0021 — Revisão do diário original antes de inicializar o runner

Data: 2026-10-27. Status: bibliotecas implementadas; não autoriza abrir volumes reais.

O construtor do runner inicializa o schema e marca jobs RUNNING como INTERRUPTED.
Portanto, iniciar o servidor para descobrir se o diário é o correto já modifica o
estado que queremos verificar. O gate anterior à inicialização deve ser separado
de Journal/Runner e nunca executar migração, cleanup, prepare ou start.

Implementar uma biblioteca de revisão offline. Exigir diretório privado do UID
atual, instance.lock preexistente bloqueado exclusivamente sem criar/truncar e
somente os nomes conhecidos SQLite. Ler arquivos regulares com limites, sem links,
comparar identidade/tamanho/mtime/ctime/conteúdo antes e depois. Um runner ativo,
arquivo ausente ou origem alterada bloqueia. O lock é cooperativo; não substitui
ausência de consumidores verificada pelo executor no daemon.

Copiar DB e WAL para scratch privado; nunca abrir SQLite diretamente na origem.
Reconstruir o índice SHM apenas no scratch. WAL contém transações confirmadas que
podem ainda não estar no DB: não usar immutable=1 ou copiar somente o DB para
concluir continuidade. Arquivo SHM da origem é inventariado, não interpretado.
Recusar rollback journals/arquivos desconhecidos e WAL sem DB coerente. O scratch
é removido ao terminar; falha no fechamento impede publicar resultado de sucesso.
O perfil conservador verifica o formato/checksums/salts do WAL e exige terminar
num commit completo; caudas incompletas, antigas após reset ou corrompidas bloqueiam,
sem truncar/recuperar automaticamente. Checksums de formato não autenticam origem.

SQLite somente leitura/query_only, trusted_schema desabilitado, limites de
tamanho/linhas/instruções/tempo, sem extensões, SQL fornecido ou funções de usuário.
Exigir schema v1 exato, integrity_check e foreign_key_check, identidade completa
do protocolo atual e hash canônico. Validar todos os jobs, gerações, spec e recibos,
com estado terminal e cleanup CLEANED; histórico começa em PREPARED e termina em
CLEANED com transições do runner permitidas. Não resolver estados ambíguos.

Receber pelo menos um comprovante CLEANED conhecido, obtido do banco Linux sob
o gate persistido independente. Cada comprovante esperado deve coincidir com o
job completo no diário. Jobs standalone adicionais são preservados e revisados,
nunca descartados por não constarem no banco integrado. Inventário lógico completo
de metadata/jobs/events produz hash para comparar antes/depois da troca.

O resultado comprova coerência do snapshot e dos comprovantes fornecidos; não
autentica histórico anterior desconhecido, imagem, volume ou origem dos dados.
O executor ainda precisa conferir mount read-only/volume exato, isolamento,
vínculo do banco e ausência de outros consumidores. Nenhuma flag autoriza ativação,
marcador, detecção ou operação normal. Nenhum endpoint ou CLI de leitura arbitrária
de volumes é exposto neste incremento.

`persisted_review.collect` recebe engine explicitamente, sem descobrir credenciais
ou usar settings/Demo como fallback. Sessão própria REPEATABLE READ READ ONLY,
statement_timeout15s. Exigir laboratório/ativo Linux reais, revogação/ociosidade,
runner e hash do binding antigo idênticos ao plano e ao menos um dispatch conhecido.
Reutilizar predicado ADR0019 e exportar todas as provas CLEANED até seu limite1000;
histórico vazio/incompleto/diferente bloqueia. O chamador ainda precisa comprovar
que o engine corresponde ao volume PostgreSQL Linux original; SQL sozinho não
atesta esse vínculo físico. O bundle e seu hash não são assinatura nem autorização.

`expected_proofs` decodifica apenas bundle com hash esperado independente, contexto,
limites/flags/IDs coerentes e jobs únicos. Encaminha identidade/provas à revisão do
diário. Os dois gates podem ser combinados e testados com PostgreSQL/SQLite reais
temporários, sem runner, daemon, SIEM ou efeitos. Não acrescentar rota pública de
exportação, leitura de volume ou ativação para expor esses componentes internos.

`journal_probe` é o ponto de entrada restrito /state; stdin até4MiB/hash independente,
resumo sem conteúdo de jobs, sem argumento de path/comando. Decoder importável sem
models/settings; imports SQL só dentro de collect. Um processo novo verifica essa
fronteira. O probe não inicia runner nem comprova seu próprio mount/volume/rede.
Invocação real depende do executor/scope futuros e nunca integra make up/test.

O coletor agora adquire ACCESS SHARE ONLY/NOWAIT nas sete relações, em ordem fixa
e antes do primeiro SELECT/snapshot. Hook interno de verificação recebe a mesma
conexão/sessão READ ONLY/RR da coleta; não validar schema numa transação anterior.
Locks protegem substituição de tabela, alteração de RLS/tipos e fazem DDL ocupado
falhar, sem exigir grants adicionais. Não congelam todo DDL: leituras estritas
usam ONLY em cada relação e subconsulta para não incorporar herança anexada depois.
Modo de raízes é interno; revisão da API mantém comportamento padrão sem esse flag.

SET LOCAL row_security=off não ignora políticas: PostgreSQL falha se uma política
filtraria linhas. Perfil do probe recusa superuser/BYPASSRLS e tabela com RLS;
o guard evita conclusão por histórico oculto, sem alterar segurança global.

Fontes oficiais consultadas:

- [SQLite WAL e leitura somente leitura](https://www.sqlite.org/wal.html).
- [SQLite pragmas](https://www.sqlite.org/pragma.html).
- [Formato SQLite/WAL](https://www.sqlite.org/fileformat2.html#wal_file_format).
- [Authorizer SQLite](https://www.sqlite.org/c3ref/set_authorizer.html).
- [Python 3.13 sqlite3](https://docs.python.org/3.13/library/sqlite3.html).
- [PostgreSQL17 LOCK e ordem do snapshot](https://www.postgresql.org/docs/17/sql-lock.html).
- [PostgreSQL17 row_security e falha em vez de filtragem](https://www.postgresql.org/docs/17/runtime-config-client.html).

Complementa [ADR0019](0019-runner-binding-review.md) e
[ADR0020](0020-runner-activation-plan.md). Testes usam somente diários temporários.
