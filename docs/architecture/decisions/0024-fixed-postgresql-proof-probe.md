# ADR 0024 — Leitor PostgreSQL fixo para provas persistidas

Data: 2026-10-27. Status: leitor e testes locais implementados; runtime/namespace
Linux original e transporte do bundle pelo host ainda não ensaiados/autorizados.

O banco Linux original é separado do Demo. Não descobrir um DATABASE_URL nem
aceitar endereço/SQL/path arbitrários para a revisão. O novo persisted_probe é
entrypoint interno destinado a PID1/UID/GID10001 em container Docker inspecionado,
compartilhando namespace de rede do DB próprio. Guard local recusa host acidental;
só o executor externo pode comprovar qual namespace/volume esse processo usa.

Senha somente em stdin privado limitado16KiB, junto de identidade/descritor exatos.
Hash do contexto público exclui a senha; não publicar hash de credencial nem colocar
segredo em argv/env/recibos. Import/help não conectam ou leem .env. Saída de sucesso
contém provas originais e deve ser capturada privadamente, nunca ecoada em logs/TTY.

URL construída pelo SQLAlchemy com componentes fixos: PostgreSQL17,127.0.0.1:5432,
databaseaegis/useraegis_app/public; hostaddr fixo, connect_timeout5s, poolNull,
hide_parameters, sem password file. Qualquer PG* ambiental recusa em vez de
herdar service/host/options ou carregar arquivos. Não é conector de rede genérico
nem prova de autenticação/TLS ou vínculo físico do volume.

Perfil exige servidor/banco/usuário/schema/search_path/read-only/RR exatos, ausência
de schema temporário e papel sem superuser/createrole/createdb/replication/bypassrls.
Como runtime não lê alembic_version, não conceder acesso nem migrar para revisar.
Validar capacidades exatas das sete tabelas/colunas necessárias: relações ordinárias,
SELECT, tipos pg_catalog/nullability compatíveis e sem RLS/herança no snapshot.
Recusar views/tabelas estrangeiras/colunas faltantes ou schema alterado.

Verificação e collect compartilham sessão READ ONLY/REPEATABLE READ, SQL15s e locks
ACCESS SHARE ONLY/NOWAIT antes de SELECT. Só consultas ONLY às raízes validadas
no modo estrito, inclusive subqueries; não ampliar por herança anexada depois.
row_security=off falha se política ocultaria linhas, não concede bypass. Locks
mantidos até fechar snapshot, sem alterar registros, grants ou config global.

Serializar/validar bundle completo e limitar4MiB incluindo newline; publicar somente
após dispose. Falha de SQL/driver/input/fechamento emite código estático/flags falsas,
sem diagnóstico contendo segredo nem saída parcial de provas. Hash não é assinatura.

Testes usam catálogos/DDL revertido/histórico em schema PG descartável e fixtures
do perfil de conexão. Validação positiva do namespace/role de produção permanece
fora do aceite até o ensaio específico; não reutilizar autorização antiga.
Continuam pendentes driver host/runtime físico/proveniência/captura privada e
coordenador que combine os gates antes de apresentar novo escopo de autorização.

Fontes oficiais:

- [SQLAlchemy2.1 Engine/URL e parâmetros](https://docs.sqlalchemy.org/en/21/core/engines.html).
- [SQLAlchemy2.1 NullPool](https://docs.sqlalchemy.org/en/21/core/pooling.html).
- [PostgreSQL17 libpq e parâmetros de conexão](https://www.postgresql.org/docs/17/libpq-connect.html).
- [PostgreSQL17 LOCK](https://www.postgresql.org/docs/17/sql-lock.html).
- [PostgreSQL17 row_security](https://www.postgresql.org/docs/17/runtime-config-client.html).

Complementa [ADR0021](0021-runner-journal-continuity.md) e
[ADR0023](0023-journal-probe-runtime.md).
