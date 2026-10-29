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

### Perfil físico do leitor (compilador e inspeção)

`runner_activation_database_runtime` é interno, sem CLI/lifecycle. Deriva o ID do
DB exclusivamente do intent bloqueado, exigindo OBSERVED. Receita só para os dois
papéis de leitura; entrypoint/módulo/contexto fixos, UID/GID10001, sem init, rootRO,
capdropALL/PNP,256MiB/0,5CPU/16PIDs, tmpfs16MiB, sem mounts persistentes/ports/logs.
`network=container:<ID completo do DB próprio>` compartilha somente o namespace
revisado; Config.ExposedPorts também deve estar vazio, inclusive na imagem.
Inspeção exige runtime exato e ownership DB/leitor antes e depois, DB running,
mesmo estado durável e nenhuma rede própria. Verificação do DB físico/isolamento,
HBA/SQL, proveniência e autorização continuam gates independentes falsos.
Fixtures/imports não comprovam templates de daemon nem autorizam operação real.

Fonte: [Docker networking: container networks](https://docs.docker.com/engine/network/)
e [Docker container run: limites, read-only e tmpfs](https://docs.docker.com/reference/cli/docker/container/run/),
consultadas em2026-10-28. `container:` tem restrições a publicação/exposição de
portas e DNS próprios; não usar imagem da API que herda EXPOSE8080 para esse papel.

### Captura privada no host

`runner_activation_database_result` compila request16KiB e valida reply4MiB sem
ampliar o parser de metadados64KiB. Contexto público exclui senha; decoder confere
identidade/descritor originais independentemente do hash calculado da resposta.
Recusa JSON duplicado/profundo, flags falsas alteradas e provas inconsistentes.

Captura requer START_REQUESTED do papel/contexto esperado (ou estado posterior
preservando esse start), escreve uma vez em diretório por operação0700 fora do
hashchain de intents, arquivo0600/O_EXCL/O_NOFOLLOW, fsync e releitura segura.
Falha conserva resíduos e não emite sucesso nem sobrescreve em retry. Reload
exige SHA canônico de origem independente e recusa symlink/hardlink/modo inseguro.
Recibo contém somente contexto/hashes/contagens, nunca proofs/marker/senha.
Hash local não é assinatura; root/daemon/usuário local continuam fronteiras de
confiança. Captura válida não comprova runtime, volume, autorização ou cleanup.

### Lifecycle interno do leitor

`database_lifecycle.execute_reader` combina receita, transporte privado e captura;
não expõe CLI/API nem aceita aprovação JSON externa. Usa o mecanismo interno
`owned_probe` também utilizado pelo diário para intenção antes de create/start,
reconciliação, CONFLICT sem adoção, proteção contra replay e finally cleanup.
Comandos são somente receita fixa e start attach/interativo do ID próprio, com
stdin16KiB/saída4MiB/prazo20s, nenhum segredo em argv/env/logs.

Callback confiável antes de cada efeito precisa comprovar autorização específica,
plano vigente, proveniência, volume DB original, runtime isolado, política de
autenticação, consumidor exclusivo e worker parado. Contexto inclui DBid e hash
da receita/identidade/descritor/request/escopo/plano, validade<=30s/idade<=10s,
conferidos novamente antes da RPC. Não exigir história persistida antes de ler o
banco: esse resultado só pode vir depois da consulta. SQL não se autorreferenda.

Antes e depois do start exigir runtime/ownership exatos. Capturar somente após
exit0/configuração conferida; falha na captura ainda limpa o leitor. Cleanup
incerto mantém DB e impede status de sucesso mesmo que o arquivo tenha sido
capturado. Interrupt limpa e propaga; pai não é fechado. Não iniciar esse driver
manualmente: runtime físico do DB/proveniência/coordenador completo e novo escopo
humano continuam pendentes. Testes do transporte completo usam fixture do engine/
SQL e entrypoint real de serialização; não comprovam PostgreSQL original.

### Campo opcional ExposedPorts em imagem limpa

Inspeção real somente de metadados da imagem nova em2026-10-29 encontrou falha de
template quando ExposedPorts está ausente. Projeções de imagem/container agora
usam index .Config "ExposedPorts"; ausência normaliza para null e o guard continua
recusando portas declaradas. Não aceitar uma porta real para contornar o template.
Teste nativo opcional AEGIS_TEST_RUNNER_IMAGE_ID exige ID explícito e só consulta
imageinspect. Usa intent/DBid sintéticos em temporários apenas para compilar receita;
não registra ownership real nem cria/inicia/inspeciona o DB fictício. Não comprova
Lab/SQL/proveniência. Rodada runtime+lifecycle95passou incluindo essa consulta real.

## Rejeição contextual sem mensagens do driver — 2026-10-29

A segunda tentativa autorizada confirmou startup/isolamento do PostgreSQL, mas
falhou no leitor sem bundle validado. Seu erro genérico não identifica a causa
exata. Não atribuir retrospectivamente senha, schema ou transporte como causa;
não conceder grants, migrar ou resetar o banco original para fazer o teste passar.
Ver [evidência](../../evidence/diagnostic-2026-10-29/README.md).

Novo envelope aegis-persisted-probe-rejection/1 mantém status=rejected e todos os
flags de prova/ativação falsos. Traz somente context_sha256, failure_phase de um
vocabulário fechado e failure_reason revisado. Erros ContinuityError só preservam
argumento exato em allowlist; DBAPIError só mapeia SQLSTATE conhecido para categoria
estática. SQLSTATE desconhecido vira database_driver_rejected; demais exceções,
unexpected_error. Nunca str(error), statement, parameters, URL, senha ou traceback.
Rejeição de input/processo não importa o stack de banco apenas para classificar.

Decoder limita4096bytes, recusa duplicatas/campos extras, contexto diferente,
motivos/etapas desconhecidos e flags inteiros ou verdadeiros. Contexto não é
assinatura; o fluxo continua dependendo de imagem fixada e isolamento/ownership.
Formato antigo ou resposta arbitrária não é reinterpretado como diagnóstico novo.

Transporte privado mantém timeout/cap integral e stderr descartado. Somente no
perfil de payload privado/saída4MiB um callback interno confiável pode examinar
stdout de uma saída não zero e levantar rejeição estática. Não retorna bytes de
falha, ignora env/proxy/config Docker externos e sempre reap. Consulta de metadados
e callback não chamável não podem selecionar esse caminho. O driver também rejeita
envelope válido se o cliente retornar0: status rejected nunca vira prova.

Lifecycle registra failure_phase do host e somente failure_code/reported_failure_phase
validados. Cleanup e quarentena continuam independentes; não há retry de start,
novo endpoint, comando livre ou enfraquecimento das inspeções. Sucesso ainda exige
runtime correto, bundle válido, comparação e ausência/fechamento confirmados.
Regressões usam erros sentinela, DB/schema descartável e filhos Python locais;
não demonstram correção da causa desconhecida no laboratório original.
