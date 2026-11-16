# Campanha Wazuh real atual —16/11/2026, #59

**COMPLETED / DETECTED / CLEANED**, `synthetic=false`. Uma campanha nova,
uma execução/teste, um único marcador benigno43bytes e alerta original100200
correlacionado. Nenhuma técnica ATT&CK avaliada; resultado limitado a esse pipeline.

## Autorização e preparação

Usuário respondeu **“autorizo”** à [proposta concreta](../../../labs/wazuh/CYCLE-SINGLE-REQUEST.md),
revisão `9f60b4c8d7154babaca1e6271b110683`, SHA256
`bfe8a3df1ad60feed480abdf299304af3f9a2fe0928026a1b7e3bcd585e1f498`.
Compose/PKI `5ae34818255f7f9f1af408ca61419a29a61cae19748d8b6c30123e2d345dd32b`.
Autorização/intent duráveis registrados antes dos efeitos; pacote consumido.
Não repetir marcador, remover fences ou trocar UUID para reutilizá-lo.

Uma checagem inicial20:15:43UTC encontrou MemAvailable3.579.957.248bytes,
abaixo do perfil+reserva, e encerrou **antes de qualquer startup/backup/SQL**.
Esse resultado/intent foi preservado. Após a oscilação, continuação do mesmo
pacote, sem campanha anterior solicitada, passou com4.185.264.128bytes.
Não houve redução de gate, parada de terceiros ou novo pedido de aprovação.
Piso exigido4.060.086.272bytes; perfil3360MiB/heap512MiB e reserva512MiB.
Mínimo observado durante a operação2.118.246.400bytes; sem OOM/restart observado.

Operação20:17:33–20:19:42UTC,417eventos de comandos. Backup frio novo antes do
banco:69.286.747bytes/1478entradas, origemRO/nocopy, helper128MiB/sem rede.
Inventários fonte antes/depois e cópia idênticos, SHA256
`2e92839e1578b680c884c1680dacb02220e3f74f13678d21556d3336a79c2ee2`.
Volume retido `aegis-wazuh-campaign-9f60b4c8d715-cold-backup`; anteriores mantidos.

DB256MiB e helper256MiB, antes dos outros serviços: revisão independente SQL/
journal duas vezes, um comprovante histórico examinado, inventário journal
`32dad29069b8f5837a9b2765263dc5ead7379050f04be0e93bcb9c6895e0ec2b`.
`activation_review.collect` produziu revisão em processo; `register` repetiu
`require_current` sob lock antes do commit. Binding do runner renovado, IDs e
histórico preservados. Duas contas novas exclusivas (administrador/operador),
distintas; nenhuma conta antiga reativada ou senha antiga alterada.

Ambiente3→4 na renovação runner;4→5 na revisão do binding Wazuh **atual**,
necessária pela CA/rede aprovadas. Binding ID, política/agente001/regra100200
preservados; nenhum scope histórico atualizado. Nova configuração Wazuh SHA256
`668e78c89bf82cc68d85c0e9ba7ec6b94aae2aadf8e384fce210f09cfb63aab9`.
Ambiente5→6 na revogação final. Sem migração, seed, DDL, alteração de grants,
build/pull ou instalação. Imagens/API/worker9e3488c4 e runner/observer77dec541
e demais IDs são os fixados em [ORIGINAL](ORIGINAL.md).

Nove serviços passaram nos182checks físicos do perfil. CA/SNI/IP/fingerprint,
TLS1.3, Filebeat/full, ACL efetiva somente leitura, agente Active/connected,
regra100200/nível3/JSON em sandbox e mTLS confirmados novamente. Probes na API,
sem outro IP na `/29`. Regra de sandbox não foi gravada no log defensivo.

## Execução e alerta original

- Campanha: `28b18502-f99c-4e82-9648-daee01171e00`.
- Run: `b338665e-2086-48a4-8601-db7f147dd087`.
- Job/teste: `2f858fc9-e59c-46d0-ab9a-5d1b45bb0e1c`.
- Scope SHA256: `e395cf7ae4213f9c1144f01b9eebe496cbd27cf5376eeca1ff30265bc332e040`.
- Operador solicitou, administrador ativo diferente aprovou scope novo por2min,
  duração120s. Intent antes do único start20:18:54.574UTC e dispatch antes da RPC.
- Marcador `aegis-17392bfa-18e8-4de3-a2f0-a2051725e2bc`,43bytes,
  artefato SHA256 `8869f73f98558f9ddcaff3771a89052b00030fece7eec1f096bffbade3dc9c29`.
- Alerta `_index=wazuh-alerts-4.x-2026.11.16`, `_id=jWQD5qEBm7izxmUqYd4q`,
  timestamp20:18:57.553UTC, agente001 e regra100200/nível3/decoderJSON.
- Uma observação nova lida independentemente do arquivo; `full_log` original do
  alerta é semanticamente idêntico a essa linha. Não é cópia do recibo.
- Seis consultas; alerts_available=true, complete=true, telemetry_available=false,
  window_satisfied=false. Positivo correlacionado dispensa concluir a janela;
  isso não permite uma conclusão negativa completa. Archives desabilitados.

Arquivos revisados, somente dados do próprio laboratório:
[alert.json](alert.json) conserva `_index/_id/_source`;
[observer.jsonl](observer.jsonl) é só a linha nova original;
[result.json](result.json) é resumo selecionado, não export integral;
[sha256.json](sha256.json) distingue hashes de bytes e serialização canônica.
Alerta canônico `1181e2d800bd99e3117b22b760f30223ff88c1243e0462328f2137889c2276c5`;
recibo `3608f1614699755ce2c2ed2c2a94fe19db5446f260ff8eaa2ae85d4452e6132b`;
cleanup `0a353efe967645e003b2ed5788ff9e2ef22c17f717d658aa398a8403da5369e7`.

Após a captura, normalização/correlação foram recalculadas localmente sobre o
alerta preservado; marcador/execution_id incorretos foram rejeitados. Hashes,
43bytes, `full_log`, observação e prova de cleanup conferidos separadamente.
Isso é verificação dos artefatos da tentativa, não uma segunda execução nativa.

## Encerramento e integridade

Journal passou de1para2jobs, um novo PREPARED→RUNNING→SUCCEEDED→CLEANED,
apenas um RUNNING novo. Job/eventos anteriores idênticos; workspace vazio.
Log466bytes anterior preservado integralmente como prefixo; agora duas linhas.
Run histórica987bd48f teve o mesmo detalhe/hash antes/depois, sem reescrita.

Snapshot SQL final b7,32tabelas de modelo/33com Alembic: todas as linhas antigas
das29tabelas fora dos três registros atuais de lab/bindings preservadas por
PK/hash, incluindo verificadores dos dois usuários históricos e duas sessões
históricas. Novos registros são adições explícitas; somente os bindings/lab
atuais sofreram as mudanças aprovadas. Duas contas próprias desativadas,
zero sessões novas restantes; lab revogado, ambiente6, sem reserva.

Containers/redes próprios encerrados, zero consumidores dos nove volumes
originais, metadados desses volumes e configuração fonte preservados. Nenhuma
administração de qasrc ou encerramento de aplicativos de terceiros. Backups,
PKI/IDs/imagens, originais, journals/intents/fences e artefatos privados retidos.
`normal_operation_permitted=false`; esta autorização foi consumida.

Recibo conjunto host-only em `.local/wazuh-single-campaign/9f60b4c8d7154babaca1e6271b110683/native-state-operational`,
SHA256 `0ed4ddc74dedf1636949c5686b7dfd251ec1f9103933d7af8e1a2a6f84c7a30b`.
Detalhe integral SHA256 `77a461b086f16b0cf435fac1a74320c2ab5f067be6309b8fc424b8a5b6a269ff`.
Hashes não são assinaturas. Não extrapolar detecção deste teste para eficácia
geral de SIEM/EDR, cobertura empresarial ou técnicas ATT&CK.

Base operacional34c8093, aplicação/imagens9493c0e;217495e alterava somente docs.
CI integral43943713532 já SUCCESS:3429Python/9skips opcionais e91React;
52testes do ciclo/62runtime-perfil sobrepostos e lint completo passaram na
preparação. Nesta etapa: compilação/lint dos operadores privados, gates nativos,
parser/correlação dos artefatos e revisão staged/release. Não houve novo teste
de marcador para validar a documentação. A#60 registra leitura/UI/exports da mesma run.
