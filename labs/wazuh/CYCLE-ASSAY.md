# Retomada integrada Linux/Wazuh — revisão #58 da entrega #7

**Preparação offline, sem autorização de execução.** Revisão em13/11/2026 na
fonte7751185, com mudança posterior de preparação do runner descrita abaixo.
Ordem obrigatória: #58 (pré-requisitos/pacote) → #59 (uma campanha real) → #60
(leitura do resultado/UI/exports). As dependências#5/#6 estão fechadas; suas
autorizações foram consumidas. A #58 permanece aberta enquanto os gates abaixo
não estiverem atendidos. Não fechar #59/#60 nem o pai com fixtures ou história.

## Perfil fixado e diferenças frente ao histórico

O único efeito proposto é `linux-file-marker/v1`: arquivo benigno43bytes,
filho até5s, uma campanha/execução/teste, sem retry do marcador. O recibo do
executor comprova execução; o observador lê o arquivo independentemente e o
Wazuh gera o alerta defensivo. Não copiar recibo para log nem fabricar alerta.
Regra própria100200/nível3/decoderJSON; zero técnicas ATT&CK avaliadas.

Manter Wazuh4.14.9, linux/amd64, sem atualização de versão ou download. Digests
de referência de [images.json](images.json), encontrados no daemon local:

| Componente | Digest fixado e ID observado localmente |
|---|---|
| Indexer | `sha256:9c43f316f0a4a15951b8667c0a0f97fc945a9e1ac55035b1be22c95d2b9a04e3` |
| Manager/Filebeat | `sha256:3561b33f8d1edf3d3b05e1819fa9a47fd28d6536787793d1840bfdf1172359ff` |
| Agente | `sha256:538ce3efc9bb097fad25e7b189d02e7e831f71faa750e2733b6011ea2070de08` |
| PostgreSQL17 Alpine existente | `sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24` |
| Redis8 Alpine existente | `sha256:3811787313eba226a2ef38658c6ccb91cd5e110edc89c37767de373120a0e5a0` |

Os três manifests oficiais coincidiram com os IDs observados neste daemon;
essa coincidência não é pressuposta para outros registries/hosts. A inspeção
consultou somente ID/arquitetura/RepoDigests; não executou imagens. Não usar tags
mutáveis como prova de identidade de um futuro pacote.

Aplicação/runner Wazuh históricos retidos, sem label de revisão de fonte:
`aegis-wazuh-platform:local` corresponde a
`sha256:afec185e570d54652f0917de8adf4034fc97869d0ebb1a4bbb1fff39c0cd8a08`;
`aegis-wazuh-runner:local` a
`sha256:d8a2479a6d970909ac88d95ea0576172cc26449ed3007a8d0263b8017d227d88`.
Existência não demonstra compatibilidade com código/schema atuais. Antes de
build futuro, retê-las em tags dedicadas e conferir IDs. Fixar imagens novas por
ID e revisar conteúdo/fonte; nenhum build/pull foi realizado nesta preparação.

Em22/10 o pipeline foi COMPLETED/DETECTED/CLEANED em redes172.30.89/90.
Em12/11 a #6 verificou TLS/leitura/identidade em rede nova, sem runner, observador,
banco ou marcador. Não equivale a uma campanha integrada renovada.
Hoje ADR0034 fixa execução192.168.253.8/29, runner192.168.253.10, e
telemetria192.168.253.16/29, Indexer192.168.253.18 com SNI`wazuh.indexer`.
Manter qasrc e aplicar [network.yml](network.yml) antes dos overlays de PKI.

## Constatações por leitura e bloqueios

1. Recursos:16CPUs, MemAvailable4.924.940.288bytes (~4,59GiB), Docker livre
   414.373.498.880bytes, vm.max_map_count1048576. O preflight **recusou** por RAM:
   exige8GiB, sem contar swap. Não parar terceiros nem reduzir o limite para passar.
   O teto configurado integrado continua7.200MiB (~7,03GiB), incluindo migração
   transitória; limites não constituem reserva física.
2. Redes:20redes Docker/61rotas, nenhuma sobreposição IPv4 observada nas duas
   faixas novas. Snapshot SHA256
   `68dc96084c342fbbe2c515d66a80c2ddc324538cf65a43c43090904f33a7e4d5`.
   Isso não reserva redes nem comprova conectividade. Revalidar antes de efeitos.
3. Zero containers do projeto `aegis-wazuh-lab`. Os nove volumes próprios existem:
   postgres-data, journal, workspace, observations, indexer-data, manager-etc,
   manager-logs, manager-queue e agent-queue. Somente metadados foram consultados;
   estado de conteúdo, schema e continuidade do journal permanecem pendentes.
   Conferir também consumidores de volumes sem o label do projeto antes de abrir.
4. A origem histórica está no checkout antigo, em
   `/home/IVPTER/codes/aegis/.local/wazuh-lab`; não existe `.local/wazuh-lab` neste
   checkout. Não executar `wazuh-lab-prepare` para preencher essa ausência:
   isso criaria outras identidades/senhas para os mesmos volumes.
5. Inventários públicos, sem ler chaves antigas: serviços
   `eb3e7008f8bc0fffcf56c7f126409c0b9d99dd6b4cc933f8a0be491550a9f85b`;
   runner`981036ea265c1cbc09e1a25f6823419195a2f70ec3656fe606f04779197e5357`.
   CAs antigas expiraram28/10; folhas23/10. A origem conserva SANs/URL antigos.
   Candidatos da #6 e suas autorizações continuam históricos/consumidos.
6. A política original confere lab`cbf6e0ec-962c-450e-861e-ba7a313c2a5a`,
   ativo`40ba5412-0034-4096-b88f-78a2ccdb789a`, agente`001`, regra`100200`,
   `aegis-json/1`, prefixo`data.aegis`, timestamp`timestamp`, índice de alertas
   `wazuh-alerts-4.x-*`, sem archives. Janela/espera60s, poll2s, timeout3s,
   clock skew5s. Runner ID`3fa6fd77-e493-4d3d-b85d-aff08cb0e356` preservado.
7. Intent original existe, SHA256 dos bytes
   `283c2a14f31d5503c2c17b7e653c2c81211655baf5ac46b3b50fec5ac3f778b4`.
   Execução histórica`987bd48f-fafc-4a34-bf2a-2d310e7ca794` permanece COMPLETED,
   synthetic=false. **O harness antigo não é reutilizável**: exige banco sem
   execuções e intent ausente, usa origem fixa do checkout e texto de revisão
   com constatações antigas. Preparar ID/intenção novos vinculados ao histórico,
   sem apagar intent, zerar banco ou trocar IDs para contornar replay.
8. Schema Wazuh original não foi aberto/inferido a partir do Linux. A aplicação
   atual exige b7/33tabelas; a migração autorizada na #5 foi somente do Linux.
   Backup frio, restore isolado, inventário/grants/compatibilidade e eventual
   upgrade Wazuh precisam de escopo próprio. O serviço Compose `migrate` também
   executa seed/atualiza senha runtime; não usar startup genérico como migração.
   **Atualização após diagnóstico especificamente autorizado:** a cópia física
   isolada confirmou4b72/29tabelas, dump/restore verificados após reconciliação;
   [recibos e limites](../../docs/evidence/wazuh-database-2026-11-13/README.md).
   O original não foi iniciado/migrado; nenhum clone recebeu upgrade. Essa etapa
   de diagnóstico foi utilizada e não autoriza migração ou marcador.
9. No inventário inicial faltava autorização para diagnóstico/backup, startup
   e efeito único. A etapa específica de diagnóstico foi posteriormente
   autorizada e encerrada conforme o relatório. Outras intervenções continuam
   pendentes; essa autorização não abrange migração, startup integrado ou marcador.

## Preparação do runner entregue sem ativação

`runner_pki.py prepare --migrate-wazuh-network` gera candidato separado com as
mesmas três identidades, URL/SAN192.168.253.10 e chaves novas. Manifesto `/3`,
distinto da renovação `/1` e da transição Linux `/2`. `verify` exige o perfil
correspondente, validade, cadeia/EKU/pares e ausência de drift. Nenhum alvo livre,
leitura de chaves antigas, alteração de origem, abertura do journal ou lifecycle.
As duas flags de transição são mutuamente exclusivas, também na função Python.

Após liberar os gates de recursos e revisar a origem pública, a ferramenta pode
gerar o candidato Wazuh separado com `make runner-pki-wazuh-transition`, fornecendo
PKI_SOURCE do runner histórico e seu hash público. Serviços Wazuh têm ferramenta
separada: `wazuh_pki.py prepare --migrate-wazuh-network`, seguida do plano
`wazuh_pki_rotation.py`. Os overlays futuros precisam montar apenas arquivos
individuais dos dois candidatos e preservar client.keys/credenciais/política/IDs.
Gerar candidato não autoriza montá-lo. Não gerar material expirável nesta etapa
enquanto o gate de RAM impedir uma proposta operacional pronta.

## Etapas que ainda exigem pacote e aprovação

A primeira etapa operacional proposta é somente diagnóstico e backup do banco
Wazuh: confirmar zero consumidores de cada volume, copiar postgres-data a frio
por mount RO/nocopy para backup protegido, iniciar PostgreSQL17 fixado apenas
na cópia de trabalho isolada (384MiB, sem porta publicada, API/worker/runner ou
Wazuh) e inventariar schema/contas/grants/histórico. Dump e validação de restore
somente em clones próprios; originais/backup preservados. Registrar imagens,
volumes/IDs, hashes, nome novo do clone e intent durável antes de cada efeito;
interromper em divergência. Encerrar recursos próprios, retendo backup/recibos.
Nenhuma migração original, seed, rotação de senha ou marcador pertence a essa
aprovação. [Procedimento de compatibilidade](../../docs/operations/linux-schema-compatibility.md)
fornece referência técnica; sua autorização Linux não se transfere ao Wazuh.

Depois desse diagnóstico, resolver a compatibilidade demonstrada, fixar fonte/
imagens/overlays/candidatos atuais e revisar um pacote final integrado. Conferir
regra no engine em sandbox, conflito100200, agente001/aegis-marker Active e estado
local connected, Filebeat TLS/full, CA/SNI/IP/fingerprint do Indexer, ACL real
`aegis_reader` limitada a leitura/search/scroll de alertas. A #6 não verificou
proibição de escrita; não afirmar que verificou. Não usar principal admin/ingest
na aplicação nem ampliar ACL para passar o ensaio. Observador sem rede, workspace
RO e log dedicado limitado/durável; retomar preservando linhas anteriores.

Só com #58 atendida e autorização específica do pacote final executar #59:
operador solicita, outro administrador ativo aprova escopo/hash por até120s,
intent/dispatch durável antes do único start/RPC e uma tentativa sem retry.
Capturar `_index`/`_id`/`_source` originais, observação e hashes, mesmo em falha.
DETECTED exige execução e alerta completamente correlacionados por lab/ativo/
execution/marker/comportamento/regra/tempo. Negativo incompleto é INCONCLUSIVE;
sem archives não inferir ausência de telemetria ou falha geral de controle.
Resposta ambígua retém recuperação; cancelamento/revogação não dispensa cleanup.

Para #60, apenas ler a tentativa original por browser autenticado e parsers
JSON/HTML/PDF; conferir synthetic=false, regra própria, denominador explícito
de um teste/zero técnicas, comparação condicionada a contexto conhecido e sem
inferência causal. Um par incompatível deve mostrar limitação, sem reescrever
histórico ou criar campanha de comparação. Screenshots não autorizam replay.
Revogar lab, confirmar cleanup físico, desativar contas/zerar sessões próprias,
encerrar containers/redes próprios e preservar nove volumes/PKI/journal/fences.
Retomar #59/#60 somente após os pré-requisitos anteriores; permanecem pendentes.

## Verificações offline

Executar `make test-wazuh`, `make test-wazuh-preparation` em sequência com as
credenciais do PostgreSQL/Redis de desenvolvimento já existentes. Fixtures usam
schemas descartáveis/Redis15; não trocar contas/grants do serviço compartilhado.
O segundo target inclui regressão da transição do runner Wazuh. Os testes de PKI
usam arquivos temporários e OpenSSL, sem Wazuh real. Conferir lint/staged/release
antes do commit e os quatro jobs Python mais React na CI antes de chamá-la verde.
Comandos/resultados efetivos e sincronização constam no comentário de#58/#7.

Diagnóstico/backup autorizado concluído em13/11:
[VERIFIED_AFTER_RECONCILIATION/CLEANED](../../docs/evidence/wazuh-database-2026-11-13/README.md).
Continuidade/schema foram examinados somente no banco copiado, sem abrir journal.
Após cleanup, RAM~6,57GiB; integrado ainda bloqueado. Antes do pacote integrado,
propor e aprovar ensaio de upgrade4b72→b7 em clone, sem migração original implícita.

## Próxima proposta: upgrade apenas em clone

Aprovação ainda pendente. Usar backup frio retido
`aegis-wazuh-diagnostic-6fd466f0fc3d-cold-backup`, inventário
`f93cd36d483a25d30b2df11bce97dd331aaba1fb6bf8fb2ae33ce9d128a05085`,
montado RO/nocopy para uma cópia de trabalho **nova**. Manter backup, working-copy
e restore do diagnóstico intactos; nenhum volume original montado nesta etapa.

PostgreSQL17 por ID já fixado acima,384MiB, network=none, sem TCP/portas; helper
de migração isolado384MiB, somente socket Unix em volume próprio novo. Imagem de
aplicação existente fixada em
`sha256:b8abe5e44af4bad90d2e302a045f38fb9cf268932be5ea0493fc72f078657a23`.
É helper owner fechado de Alembic, sem iniciar API/worker. Verificar os hashes
de todos os arquivos de migração dessa imagem contra a fonte revisada **antes de
SQL**; recusar divergência. Usar somente4b72→ec302→977fd→a0→b7, passando de29para33
tabelas e `alembic check`. Sem serviço Compose genérico de migração ou seed.

Comparar todas as colunas antigas de todas as tabelas, IDs/scopes/approvals/
receipts/cleanups/contas/verificadores e ACLs antes/depois do upgrade. Esperar as
quatro tabelas novas vazias e somente os acréscimos de colunas previstos no a0.
Aplicar/revisar grants mínimos atuais **somente nesse clone**, mantendo senha e
privilégios de outros papéis. Conferir imutabilidade e permissões por coluna.
Sem publicação/adopção de catálogo, binding, PKI, Wazuh, API/worker, runner ou
marcador. Encerrar containers próprios, reter volumes/backup/recibos e comparar
metadados/consumidores originais sem abri-los. Falha retém artefatos e bloqueia
qualquer intervenção original. O limite do ensaio integrado de8GiB continua
independente da etapa de clone com até768MiB configurados simultaneamente.
