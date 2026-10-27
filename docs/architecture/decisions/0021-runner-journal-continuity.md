# ADR 0021 — Revisão do diário original antes de inicializar o runner

Data: 2026-10-27. Status: implementação incremental; não autoriza abrir volumes reais.

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

Fontes oficiais consultadas:

- [SQLite WAL e leitura somente leitura](https://www.sqlite.org/wal.html).
- [SQLite pragmas](https://www.sqlite.org/pragma.html).
- [Authorizer SQLite](https://www.sqlite.org/c3ref/set_authorizer.html).
- [Python 3.13 sqlite3](https://docs.python.org/3.13/library/sqlite3.html).

Complementa [ADR0019](0019-runner-binding-review.md) e
[ADR0020](0020-runner-activation-plan.md). Testes usam somente diários temporários.
