# Ensaio de renovação TLS Wazuh — #6/#57

**Encerrado em12/11/2026: VERIFIED_AFTER_RECONCILIATION/CLEANED.**
[Relatório final, horários, hashes e limites](../../docs/evidence/wazuh-tls-2026-11-12/VERIFIED.md).
As duas tentativas autorizadas foram consumidas; laboratório parado, nove volumes
e configuração antiga preservados. Não há autorização de nova execução.

## Entrega e histórico

#55 entrega [inventário/candidato offline](../../docs/operations/wazuh-pki.md),
#56 entrega [troca/rollback coordenados](../../docs/operations/wazuh-pki-rotation.md).
A dependência #149 e suas subissues foram incluídas sob autorização somente
offline: ADR0034 fixa execução192.168.253.8/29 e telemetria192.168.253.16/29,
transição explícita de rede/SAN e recusa de baseline incorreto.

A primeira tentativa5175cd2f, autorizada posteriormente, terminou
[INCONCLUSIVE/CLEANED](../../docs/evidence/wazuh-tls-2026-11-12/README.md):
Indexer/Filebeat verificados, agente Active, condição complementar inconclusiva,
leitor não iniciado. O resultado histórico permanece intacto.

O usuário autorizou separadamente o pacote16e48a04 após CI/preflight aprovados.
O segundo ensaio comprovou nova folha/CA/SNI/IP, Filebeat TLSv1.3/full,
agente001/aegis-marker Active/connected, API de gestão somente em loopback e
leitor com principal/ACL de leitura reais. Um label de build `migrate` herdado
causou classificação conservadora incorreta no coletor de runtime. A
reconciliação verificou imagem/comando/mounts/limites/identidade e recuperou a
saída do leitor original encerrado, sem replay, completando o cleanup. Outcome
original e reconciliação adicional preservados separadamente.

## Escopo executado e limites

Um ensaio por autorização, até15min, projeto `aegis-wazuh-lab`: Indexer,
manager/Filebeat, agente001 e leitor na telemetria isolada, sem portas publicadas.
Imagens oficiais4.14.9/amd64 fixadas e leitor local por ID; sem pull/build.
Memória mínima8GiB e demais gates reconferidos imediatamente antes dos efeitos.
A liberação anterior de RAM ocorreu encerrando apenas Firefox/Slack, sob ordem
do usuário; nenhum projeto de terceiros foi parado.

`scripts/wazuh_tls_scope.py` projeta só os três serviços, rede e seis volumes
**external=true**, remove depends_on do agente e vincula os recursos ao ensaio.
`scripts/wazuh_tls_probe.py` usa CA/SNI/IP/fingerprint exatos antes de enviar
credenciais por stdin; somente principal `aegis_reader` e cinco GETs fixos.
Verifica role/principal, leitura de alertas com `size=0`, falta de acesso à API
Security e negativa403 de leitura do índice de segurança. Não imprime documentos
ou credenciais. `write_acl_verified=false`: não testa proibição de escrita.

`scripts/wazuh_tls_readiness.py` separa manager, estado local do agente e
listeners de gestão. API ausente não equivale a API funcionando; listener LAN é
recusado. Neste ensaio a API estava efetivamente em loopback. A identidade do
leitor usa nome/projeto/ensaio/imagem/entrypoint/comando explícitos; label herdado
é informativo e não dispensa conferir mounts, limites e hashes.

Sem marcador, regra nova, alerta fictício, runner, observador, API/worker da
plataforma, banco/migração, binding ou campanha. O agente usa seu canal seguro;
não afirmar handshake X.509 do agente. Não há alegação DETECTED/ATT&CK/eficácia.
O startup pode atualizar estado/logs normais dos volumes e reprocessar backlog;
volumes preservados não significa dados byte a byte idênticos.

## Operação futura

Nenhum comando/issue/relatório concede startup. Pacotes consumidos, candidatos,
PKI, journals, outcomes e intents/fences devem permanecer preservados. Não
recriar arquivos/identidades ou iniciar novamente para obter outro resultado.
Para operação futura, revisar escopo concreto, imagens/IDs/mounts/volumes,
TTL de certificados e plano, CI, recursos/redes e obter autorização específica.
Não reutilizar a autorização histórica de22/10 ou as de12/11.

Usar o procedimento coordenado, com INTENT durável antes de cada efeito e
observações depois. Não usar `make wazuh-lab-up` para um ensaio TLS limitado,
pois inicia mais serviços. Erro/timeout retém evidências e exige cleanup e
reconciliação; não autoriza repetição automática. Cleanup preserva volumes,
credenciais, configuração antiga e metadados históricos. Rollback seleciona
caminhos originais com serviços parados, sem operar com certificados expirados.

`make test-wazuh-tls-review`:114aprovações finais, fixtures/Compose e TLS real
de loopback, sem startup nativo. Distinguir esses testes do ensaio real no
relatório final e da CI de cada commit. O
[checkpoint](../../docs/development/wazuh-pki-checkpoint.md) conserva a sequência
de bloqueios, preparação, primeira tentativa e aceite final.
