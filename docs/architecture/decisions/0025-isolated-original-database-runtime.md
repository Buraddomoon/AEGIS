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
