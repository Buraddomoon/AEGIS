# Retomada de uma campanha Linux — issues #5/#52/#53/#54

Preparação de12/11/2026. Este documento é uma proposta revisável, **não uma
autorização**. A #4 terminou com binding atual revogado, sem worker/campanha.
Autorizações anteriores foram consumidas. Não reutilizar seus pacotes/fences.

## Configuração preparada (#52)

O overlay `campaign.yml`, aplicado depois de `platform.yml`, fixa as quatro
imagens por ID e substitui o antigo `migrate` por uma transação
READ ONLY/REPEATABLE READ. Ela exige schema **b7f3c2d91a06**, grants mínimos,
nenhuma reserva/execução/cleanup pendente e nenhum agendamento ativo ou relatório
automático pendente. API/worker dependem desse gate. Não há seed, bootstrap,
upgrade ou alteração de senha/grants nesse startup. Não iniciar os serviços
base sem o overlay. O original conhecido continua **d4465b7aca2a/27tabelas**;
portanto ainda não pode receber a API/worker atuais.

`make linux-platform-config` somente renderiza e revisa o Compose. Rejeita tags
mutáveis, build implícito, portas extras, host networking/mounts de dados,
integração Wazuh, comando antigo e volumes/faixa inesperados. Não consulta dados
do Lab nem inicia Docker. O build anterior que reutilizava tags foi retirado;
construir a aplicação somente em tag nova exclusiva e registrar seu ID.

Entradas locais, ignoradas no Git:

- `LINUX_IDS_ENV`: `ids.env` do candidato atual
  `81826566e88e4c9ebc8b9aa09c8a8d02`; nunca regenerar IDs ou usar a PKI antiga.
- `LINUX_CAMPAIGN_ENV`: arquivo privado com `LINUX_APPLICATION_IMAGE`,
  `LINUX_RUNNER_IMAGE`, `LINUX_POSTGRES_IMAGE`, `LINUX_REDIS_IMAGE`, todos IDs
  `sha256:` completos. O pacote local registra também hashes da fonte/config.
- Credenciais existentes: só por arquivo privado/env/stdin, nunca argv/issue.
  Reconciliar com a configuração original antes de conectar, sem resetar senha.

Recursos fixos: projeto `aegis-linux-lab`; volumes existentes
`aegis-linux-lab_postgres-data` e `aegis-linux-lab_journal`; rede runner interna
isolated `192.168.253.0/29`, gateway `.1`, runner `.2`, API `.4`, worker `.5`.
API somente `127.0.0.1:18785`, origem browser `http://localhost:18785`.
Backend/ingress exclusivos desse projeto. Sem Docker socket, shell remoto,
CA privada montada, Wazuh ou conexão às redes de terceiros/qasrc.

Runner revisado: `sha256:a893bdaee96551dd569f85d0fe2d49af147e6793441efed18a665b88a84277ab`.
PostgreSQL: `sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24`.
Redis: `sha256:3811787313eba226a2ef38658c6ccb91cd5e110edc89c37767de373120a0e5a0`.
O ID da aplicação, manifesto e prazo concretos ficam no pacote da #53 após
build em tag nova. Imagem do Demo e todas as tags históricas são preservadas.

## Pacote a aprovar (#53)

A proposta inclui **somente uma tentativa**, neste host e nesses volumes/IDs:

1. Antes de abrir o original, reconferir imagens, consumidores ausentes, espaço,
   redes, PKI/TTL, configuração/hash e autorização vigente. Qualquer drift ou
   prazo vencido bloqueia; não renovar automaticamente o pacote/certificados.
2. Fazer backup frio novo do PostgreSQL original em RO/nocopy, sem rede, pois o
   backup da #48 precede a mudança do binding. Abrir apenas cópia isolada para
   inventário/dump/restore e upgrade d446→b7. Comparar todas as colunas/linhas
   antigas, contas/verificadores, ACLs efetivas e provas de execução/cleanup.
   Backups/clones e ledgers ficam privados e são preservados.
3. **Somente sob aprovação explícita dessa intervenção**, aplicar Alembic
   d446→b7 no original e grants mínimos com os segredos existentes, sem
   seed/bootstrap/reset. Comparar novamente o histórico e as adições previstas;
   uma divergência bloqueia a campanha. Não fazer downgrade/restore no original.
   Esse passo não foi autorizado ou realizado pela #4.
4. Iniciar a configuração revisada, conferir runtime/isolation e continuidade
   SQL/diário sob a PKI atual. O binding existente deve corresponder ao deployment;
   o script não recadastra o lab nem incrementa sua versão para contornar drift.
5. Criar **duas contas novas temporárias**: administrador e operador, senhas
   aleatórias só em memória/stdin. Manter contas históricas inativas e intactas.
   Preflight mTLS novo (vigência5min), autorização do lab, solicitação pelo
   operador e aprovação por administrador distinto, scope hash exato, duração
   máxima da run60s. Nenhuma aprovação histórica é reutilizada.
6. Worker executa apenas `linux-file-marker/v1` (`linux-file-marker-v1` no
   catálogo): um `proof.marker` de43bytes e `receipt.json`, em pasta UUID do
   tmpfs `/work` de1MiB. Filho≤5s, lease2s, supervisor mata/reap em timeout,
   cancelamento ou perda do controlador. Runner UID10001, rootfs RO, ALL caps
   removidas, no-new-privileges,192MiB/1CPU/64PIDs; API512MiB, worker256MiB,
   DB384MiB, Redis128MiB. Não é teste ATT&CK nem defensivo.
7. Conferir uma run rastreável na API/UI, recibo imutável, hash/43bytes, cleanup
   CLEANED e workspace vazio, relatórios JSON/HTML/PDF proporcionais e histórico
   preservado. Sem SIEM: `synthetic=false`, **INCONCLUSIVE**, zero eventos/alertas
   defensivos. Captura por leitura do mesmo UUID; nunca repetir efeito.
8. Revogar lab e desativar as duas contas, remover suas sessões e confirmar no
   banco. Encerrar somente containers/redes próprios, sem `down -v`, mantendo
   volumes, diário, fences, PKI, imagens, backup e recibos. Conferir ausência de
   consumidores. Registrar falhas e não confundir revogação com cleanup físico.

O operador desta sessão supervisiona o ciclo com limite global de15min. Em falha,
não há nova campanha/UUID: consultar a tentativa original, parar dispatch e usar
cleanup restrito, conservando reserva/quarentena se a confirmação for ambígua.
O comando de efeito exige `--attempt-id` fixado no pacote: um registro exclusivo
0600/fsync é consumido antes da primeira mutação; repetir o comando é recusado.
O run ID/scope hash é persistido antes do start. O finally tenta revogação e
remoção das sessões independentemente de erros; falhas de cleanup são explícitas.
Isso não substitui supervisão externa em SIGKILL/perda do host.

## Ordem e aceite

#52: configuração, imagens, render e testes sem startup. #53: pacote fixado e
aprovação humana **pendente**. #54: ensaio real somente depois da #53, com cleanup
confirmado e evidência. Pai #5 aberto até o aceite dos três filhos.

Testes pertinentes: `tests/test_linux_campaign_preparation.py`,
`tests/test_linux_campaigns.py`, `make test-runner` e
`tests/test_linux_schema_compatibility.py`, sequenciais para PG/Redis15.
Fixtures/tempdir/loopback não demonstram o ensaio nativo, migração original,
implantação ou detecção. Contagens/commits efetivos são registrados nas issues.
