# ADR 0025 — PostgreSQL original em namespace isolado para diagnóstico

Data: 2026-10-28. Status: política de autenticação local implementada/testada;
receita, inspeção, lifecycle e ensaio do servidor ainda em implementação.

O leitor fixo do [ADR0024](0024-fixed-postgresql-proof-probe.md) exige um servidor
PostgreSQL17 próprio, volume original inequivocamente identificado, namespace sem
rota externa e autenticação sem confiança implícita no loopback. Não usar Demo,
restaurar clones como se fossem o original, executar initdb/migrations/seed,
redefinir senhas ou alterar grants para satisfazer os requisitos.

A receita planejada invoca o binário postgres diretamente como UID/GID70 no
perfil alpine revisado, sem entrypoint de inicialização/chown. Montará somente o
volume PostgreSQL original existente e um arquivo HBA fixo da operação. Network
none e listen loopback permitem acesso apenas ao leitor no mesmo namespace do
DB próprio; sem porta publicada, worker, Redis, API, Wazuh ou marcador. Revisão
do runtime e proveniência continuam obrigatórias antes de qualquer efeito.
Não desabilitar TLS, controles ou extensões da fonte para contornar falhas.

SQL READ ONLY não torna PGDATA somente leitura: iniciar/encerrar o servidor pode
escrever PID, WAL e metadados operacionais. Essas escritas precisam constar do
novo escopo humano, assim como o encerramento dos containers próprios preservando
volume/journal. Não alegar hash físico do PGDATA inalterado nem autorizar um ensaio
por meio desta decisão. Não iniciar o DB para testar um executor incompleto.

## Política local implementada

`runner_activation_database_policy` prepara exclusivamente um arquivo não secreto
fora do hashchain dos intents, no diretório privado por operação. Escrita O_EXCL/
O_NOFOLLOW, fsync, modo0444 sob pais0700, permitindo single-file bind RO para UID70
sem montar o diretório de segredos ou copiar/editar o HBA original. Repetição/falha
não sobrescreve nem remove arquivos; verificação exige bytes exatos, owner/modo/
link único, operação aberta e estado durável inalterado. Preparação não usa Docker,
não lê o volume e não modifica credenciais.

A única regra de acesso é SCRAM-SHA-256 para databaseaegis/useraegis_app/127.0.0.1/32.
Unix sockets, demais destinos/usuários/bancos e replication são rejeitados; nenhum
include, trust, peer, md5 ou lookup DNS. O futuro coordenador deve comprovar o
mount exato e a autenticação real. Ler esse arquivo ou passar fixtures não prova
que um servidor o carregou. Os recibos mantêm runtime/auth/autorização falsos.

Fontes oficiais consultadas em2026-10-28:

- [PostgreSQL17 postgres e parâmetros](https://www.postgresql.org/docs/17/app-postgres.html).
- [PostgreSQL17 pg_hba.conf](https://www.postgresql.org/docs/17/auth-pg-hba-conf.html).
- [PostgreSQL17 conexões e autenticação](https://www.postgresql.org/docs/17/runtime-config-connection.html).
- [Docker execução de containers](https://docs.docker.com/engine/containers/run/).

## Receita do servidor implementada (compilação apenas)

`runner_activation_database_server` fixa binário postgres, UID/GID70, rootRO,
networknone/loopback5432, capsALL removidas/PNP,384MiB/1CPU/64PIDs, tmpfs64MiB e
shm64MiB. Sem stdin/init/healthcheck/publicação/logDocker. Apenas volume original
PGDATA RW/nocopy e HBA da operação RO/rprivate; recusa delimitadores CSV no path
antes de compilar mount. Verifica novamente a política e estado durável; comando
create só pode ser compilado depois de dbREQUESTED, sem ID observado.

Parâmetros fixam data_directory/HBA/loopback/sockettmp/read-only/timeouts e limites
de memória/conexões. Não sobrescrevem TLS, autovacuum, preload ou logging da fonte
para fazer passar. Nenhum chown/initdb/migrate/seed, shell ou imagem por tag/pull.
Se dados/UID/versão/configuração forem incompatíveis, falhar fechado; não reparar.

Compilar uma receita não verifica imagem, volume existente, mounts efetivos ou
proveniência; inspeção real e lifecycle/coordenador ainda pendentes. Imagem PG pode
declarar VOLUME: o futuro guard deve exigir somente PGDATA e impedir outros volumes
anônimos antes de create. Em hosts SELinux, não desabilitar labels para fazer bind
funcionar; verificar política do arquivo próprio antes do ensaio autorizado.

## Inspeção projetada implementada

`database_inspection` só faz image/containerinspect, por ID local e templates
fechados. Imagem deve declarar apenas VOLUME PGDATA/EXPOSE5432, sem ONBUILD ou
labels herdadas; User ausente normaliza root somente na imagem, sobrescrito70:70
na receita. Go template usa index/with em campos opcionais, sem Config.Env bruto.

Ambiente projetado só como chave/booleano: PATH/LANG/PG_MAJOR17/PGDATA fixos e quatro
metadados oficiais PG_VERSION/PG_SHA256/GOSU_VERSION/DOCKER_PG_LLVM_DEPS. Estes dois
últimos pertencem ao build/entrypoint upstream, que o perfil não executa; não
aceitar PGOPTIONS/LD_PRELOAD ou prefixos genéricos. A leitura do Dockerfile upstream
não é proveniência da imagem local. Guard de versão SQL continua independente.
[Dockerfile oficial PostgreSQL17 Alpine](https://github.com/docker-library/postgres/blob/master/17/alpine3.23/Dockerfile).

Runtime exige configuração/host/estado exatos em created/running, imagem por ID,
DB observado próprio e ownership antes/depois. Montagens precisam ser exatamente
PGDATA RW/nocopy e bind HBA RO/rprivate com origem igual ao arquivo da operação;
um tmpfs/tmp efetivo é opcional na projeção. Nomes de volumes são preservados;
caminhos físicos do daemon e origem de binds não saem do template, somente
booleano de igualdade para o HBA. Ordem de mounts não importa, duplicatas/extras
falham. Política é relida antes/depois; estado durável deve permanecer igual.

Namespace none e ausência de publicação de5432 são distintos de EXPOSE5432 na
imagem. Guard não afirma conteúdo do volume, autenticação carregada, proveniência
ou autorização. Consumidores/inventário do volume continuam gates externos do
coordenador; inspeção isolada não confirma exclusividade.

Teste opcional só consulta metadados do DB Demo já existente e de sua imagem para
cobrir templates reais; não executa SQL, não inicia objetos e não aceita Demo como
servidor aprovado. Ausência de Docker/Demo significa skip. O servidor do Lab ainda
não foi iniciado nem inspecionado neste novo perfil.

## Intenção de inicialização do servidor

Eventos separados `database_start_requested` e `database_runtime_observed`
permitem registrar start antes da RPC e depois retornar a OBSERVED com evidência
hash da inspeção. Recipe/gates/policy hashes são obrigatórios. O registro original
de start permanece: observar runtime não permite repetir inicialização, inclusive
após resume. Dependentes abertos impedem start; leitores só podem ser solicitados
quando DB está OBSERVED, nunca no start ambíguo. Cleanup continua aceitando DB em
START_REQUESTED, preservando suas dependências e volume. Inspeção pode conferir
created/running durante esse estado, sem reexecutar start ou alterar o intent.

O evento de runtime não é readiness, login válido ou autorização; o driver futuro
deve obter os hashes de observações reais e verificar os demais gates. Histórico
local não permite fabricar verdade do daemon. Nenhum startup foi executado.

## Lifecycle interno do servidor implementado, sem ensaio real

`database_server_lifecycle.start_server` exige callback interno confiável antes de
create, start e de cada readiness; não recebe aprovação JSON por API/CLI. Gates
fixam escopo/plano/operação/receita/HBA/volume e ID conhecido (null só no create),
validade<=30s/idade<=10s. Callback precisa comprovar autorização específica, plano,
proveniência, volume original, política local, consumidor exclusivo, journal
quiescente e worker parado. Drivers de fixtures não autorizam efeitos reais.

Imagem é revisada antes do intent/create. Intenção precede efeito e start é único;
ID retornado, ownership e runtime são conferidos antes/depois. Ambiguidade/falha/
interrupção limpa somente o DB próprio com o mecanismo compartilhado dos probes,
sem remover volume ou fechar operação pai. Colisão pré-create vira CONFLICT sem
adoção/exclusão. Retomada não permite repetir start. Cleanup incerto não é sucesso.

Após running/evidência durável, única operação exec permitida é pg_isready direto,
UID70,quiet,127.0.0.1:5432/aegis/aegis_app/timeout1s. Sem shell, senha, endpoint ou
comando livre. CLI Docker até2s por consulta, oito tentativas no máximo e prazo
absoluto15s incluindo gates/inspeções/revisão final; só readiness pode repetir.
Não há retry de criação ou inicialização do servidor. Sucesso mantém DB running
para os leitores; coordenador deve sempre encerrar depois, mesmo se outro estágio
falhar. Registro pai e start original continuam duráveis.

[pg_isready17](https://www.postgresql.org/docs/17/app-pg-isready.html) comprova apenas
que o servidor aceita conexões. Não exige senha válida e pode gerar logs de tentativa
de conexão; isso deverá constar do escopo do ensaio. Não declarar autenticação,
identidade SQL ou conteúdo do volume com esse sinal. Provas vêm do leitor separado.
Recibos mantêm esses flags falsos, assim como autorização/proveniência/ativação.
PGDATA permanece RW e pode receber escritas operacionais; nenhum runtime foi iniciado
para validar esta implementação. Coordenador e imagem atual continuam pendentes.
