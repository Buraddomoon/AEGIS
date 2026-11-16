# Prontidão Wazuh com memória limitada —16/11/2026

**READINESS_VERIFIED/CLEANED.** O pedido explícito do usuário para tentar com
a memória disponível substituiu o piso recomendado de8GiB somente nesta
tentativa. Nenhum programa de terceiros foi encerrado e nenhum sysctl alterado.
Isso comprova inicialização/prontidão limitada, sem campanha ou detecção atual.

Fonte das ferramentas `34c80938024f0ccbd70b3b85a9ce64086db6e8ca`.
Imagens da aplicação/runner corrigidas e demais sete IDs permanecem os do
[relatório original](ORIGINAL.md); sem build/pull, migração, seed ou contas novas.
O perfil fechado `bounded-3360m/1` limita os nove serviços a3360MiB, heap Java
512MiB e swap adicional zero por container. O gate excepcional exige outros
512MiB disponíveis, mantendo CPU/disco/map_count. O padrão de8GiB permanece.

## Primeira tentativa e continuação

Pacote privado `65e77cf9d5484ad095834385810988aa`, SHA256
`fefbdbc1b4e8f698c7b40ab7d9773dae02379e421fcc97123810459f330a902e`.
Iniciado19:54:18UTC, encerrado19:55:27UTC. Nove serviços passaram nas182
verificações de runtime; agente Active/connected e Filebeat TLS/full confirmados.
O probe auxiliar não iniciou por falta de IP livre na rede de telemetria `/29`:
seus cinco endpoints já estavam ocupados pelos serviços. Não foi falha de RAM.
Resultado preservado **INCONCLUSIVE/CLEANED**,235eventos de comandos; recibo
SHA256 `fd8f350e2f1c7cdd207b2ec02643f1807c3d7711d3eed22ddb5b1f830e6b5636`.

Após confirmar encerramento completo, a continuação usou pacote/intent novos
`eaaf4d833cbe473daec0b4e198bf52ef`, SHA256
`7f3fa61d6ea50cfe9717912ee039b11d20b3d67ac864ace159a58a14ce358b98`.
O mesmo probe somente leitura executou dentro da API existente, sem consumir
outro IP/container, com senha exclusivamente no stdin. Nenhum marcador em
qualquer fase, nem replay de campanha.19:57:31–19:59:15UTC,311eventos de comandos.
Resultado **READINESS_VERIFIED/CLEANED**, recibo SHA256
`877cc548322a33ae65d2ab994418346f0e91d1fa6263f39a2e99499913150b22`.

## Observações reais

- Antes da continuação: MemAvailable4.537.585.664bytes; piso4.060.086.272bytes.
  Mínimo observado durante ela3.275.452.416bytes (~3,05GiB), acima da reserva.
  Supervisor não observou OOM/restart/saída inesperada. Na primeira tentativa,
  snapshot de consumo Docker dos nove serviços somou aproximadamente1,6GiB.
  Limites não são reservas; isso não estabelece capacidade sob carga contínua.
-182verificações de runtime aprovadas antes/depois de30s de estabilidade:
  IDs de imagens, perfil, memória/swap, heap/comandos, mounts, usuários,
  capacidades, redes/endereços/membros e porta API somente127.0.0.1:18786.
- Indexer apresentou o certificado novo esperado; probe da API confirmou
  CA/SNI/IP/fingerprint e TLS1.3. Certificado DER SHA256
  `c03e316afcabe10977e2e60378b629e41e24508cc2a20ed345d3b4329fd90c34`.
- Filebeat test output confirmou verificação de cadeia/full e TLS; agente
  `001/aegis-marker` Active no manager e connected no próprio agente.
  API de gestão55000 observada somente em loopback na continuação.
- Principal efetivo `aegis_reader`, leitura de alertas sem shards falhos e
  acesso negado à API de segurança/índice de segurança. GETs administrativos
  somente leitura conferiram o papel/mapeamento/grupo efetivamente persistidos:
  índices `wazuh-alerts-4.x-*`, ações read, cluster monitor/main e scroll; grupo
  read contém apenas leitura, fields/get e resolve/index. Sem grants de escrita.
  **Nenhuma requisição de escrita foi feita para testar um403**; o probe mantém
  `write_acl_verified=false`, distinto da inspeção dos grants efetivos.
- Preflight mTLS real da API ao runner preservou os três IDs originais,
  concorrência1, efeito até5s e somente `linux-file-marker/v1`.
- Regra100200/nível3/decoderJSON passou em `wazuh-logtest` com entrada sintética
  de sandbox, sem gravá-la no log do observador nem apresentá-la como alerta.
  O engine não emitiu aviso de duplicação100200; emitiu avisos de outras regras
  ignoradas/listas audit/IOC ausentes. Essas regras não foram avaliadas nem
  corrigidas nesta entrega; o resultado se limita à regra própria100200.
- Observador permaneceu sem rede/workspaceRO. Log anterior idêntico:
  466bytes/uma linha, SHA256
  `630a404522ebc8a1b1b1669da3dd8265f0e4f4ba5fe5d811ccb92a3cd2e9a094`.

PKI separada: runner `b37eb9409da24aa9a6a2d4332fd265b4`, manifesto
`05e8ac4c84cd9b1989b29bd756e1222c3f27d382d388086902f42ed0728586a1`;
serviços `00b37f26bb0147bda60160755374f200`, manifesto
`58050d69e2fd9d9ae26a1100603ece61843e8d943a1cc9cdb1683b12ac900767`.
Origem/PKI antigos, IDs, intents e candidatos anteriores preservados.

## Encerramento e limite

Nas duas fases, containers/redes próprios removidos, zero consumidores dos nove
volumes originais, metadados desses volumes e snapshot completo da configuração
fonte idênticos. Volumes/PKI/recibos/backups mantidos no host. Não houve mudança
de binding, autorização do lab, conta, senha, schema, catálogo ou campanha.
Os serviços existentes fizeram as escritas normais de inicialização em seus
volumes; isso não é declaração de igualdade física de bancos após startup.

Preparação técnica da#58 atendida com esta evidência e os relatórios de
continuidade/catálogo anteriores. Para#59 falta autorização específica do efeito
único, incluindo renovação do binding e contas temporárias, sob gates rechecados.
#60 depende da leitura da mesma execução futura. Não inferir DETECTED deste ensaio.

`make test-wazuh-cycle`:52passaram; runtime/perfil:62passaram, conjuntos
sobrepostos. `make lint` completo passou. CI de34c8093
[43943713532](https://github.com/Buraddomoon/AEGIS/actions/runs/43943713532)
**SUCCESS:3429Python/9skips opcionais e91React**. Quatro partições conferidas:
858/2skips,813/2,918/1,840/4; React91. Source-review43943713821 também SUCCESS.
Checks staged/release devem ser conferidos no commit documental.
Artefatos privados em `.local/wazuh-bounded-native`, fora do Git; hashes não
são assinaturas e não autorizam repetir os pacotes já consumidos.
