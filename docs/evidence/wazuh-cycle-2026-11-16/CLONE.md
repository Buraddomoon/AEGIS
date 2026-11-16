# Continuidade e catálogo em clone — 16/11/2026

**CLONE_CONTINUITY_AND_CATALOG_VERIFIED / CLEANED.** O usuário respondeu
**“Autorizar essa etapa em clone”** ao escopo específico de cópia fria, leituras
RO de journal/log e adoção do catálogo somente no clone. Operação executada
16:44:53–16:45:36 UTC,143 eventos duráveis; autorização utilizada neste escopo.

## Resultado nativo

- Os nove volumes originais conservaram metadados, com zero consumidores antes
  e depois. PostgreSQL original não iniciado; nenhuma escrita SQL original.
- Cópia fria do original b7/33 para backup e working novos, por mountRO/nocopy.
  Original e backup conferidos novamente ao final:68.391.491bytes/1.475entradas,
  mesmo inventário físico
  `2c19f3edf9ea9c176ed21dc75f78f23b52969b737ff9e0c449c6bb90d1704522`.
- Somente o working iniciou PostgreSQL17,384MiB, networknone/loopback interno,
  sem porta publicada; helpers até256MiB compartilham apenas seu namespace.
  Original copiado confirmou **b7f3c2d91a06/33tabelas**, inventário lógico
  `b04c7c04f4717b842b175a605d1388f27e81b33f0576ccd1be9ed21fe82ce33a`,
  igual ao estado final da manutenção de13/11. Imagem da aplicação verificada
  internamente:73arquivos/45versões, sem build/pull.
- Leitor PostgreSQL com `aegis_app`, transação read-only/repeatable-read,
  produziu provas independentes do binding/dispatch/cleanup. Probes reais do
  journal original usaram mountRO/nocopy,192MiB, UID10001, rootFSRO, sem rede,
  entrypoint fechado. Metadados antes/depois foram validados, incluindo labels
  de procedência da imagem. **Um job/quatro eventos/uma prova**, zero jobs
  adicionais; inventários lógicos iguais antes/depois.
- Log original lido RO em helper128MiB, sem iniciar observador/agente. Uma
  observação/466bytes, igual ao registro histórico revisado, SHA256
  `630a404522ebc8a1b1b1669da3dd8265f0e4f4ba5fe5d811ccb92a3cd2e9a094`.
  Conteúdo e metadados estáveis; nada foi acrescentado ou reescrito.
- Catálogo foi planejado read-only e adotado **somente no working**: uma
  release, um estado e uma auditoria. Todas as demais linhas, verificadores,
  grants e definições de schema preservados. Sem seed, migração, nova técnica,
  conta, senha ou alteração de binding. Release
  `b572391494ef2b9ec7b68095bef5ba16c7190da123497c1b814b9c5c0ce6b3e2`;
  inventário final do clone
  `a0c5d1e37404e787b016c5d3b4d2791ab03da4707a2b3cdedd3d3fbf6c7ad54c`.
- Containers próprios encerrados/removidos. Conferência independente confirmou
  zero consumidores dos originais e dos dois novos volumes retidos:
  `aegis-wazuh-cycle-643ee4e311a1-cold-backup` e
  `aegis-wazuh-cycle-643ee4e311a1-working`. Backups/clones anteriores preservados.

O comparador lógico mantém seus flags de runtime/ativação/autorização falsos:
ele só compara inventários. As inspeções físicas do driver são artefatos
separados; nenhum JSON foi reescrito para promover esses flags. Não representa
ativação PKI, ingestão Wazuh ou uma nova campanha defensiva. Pico configurado
PG384MiB+helper256MiB, probes sequenciais; não é medição de pico global do host.

## Integridade e custódia

Artefatos privados em
`.local/wazuh-cycle-native/643ee4e311a14f9cb86f861c65384f1f`; operador/helper,
intents, SQL/provas/inspeções e recibos não foram publicados. Hashes canônicos:

| Artefato | SHA256 |
|---|---|
| Autorização delimitada | `8049d74abd14c633528d31a30015dcb79aee2a5077919fef01de5bfdd07c4713` |
| Plano/escopo executado | `aae131c95b65f550c84c1f5a86e5e277298f5f03ab320e159a0c9067a68b1cd0` |
| Provas persistidas | `cfaa635e4608b6ed7ca18d0d983a16e18bfaee646eddb60a7012917a9359c8a7` |
| Inventário lógico do journal | `32dad29069b8f5837a9b2765263dc5ead7379050f04be0e93bcb9c6895e0ec2b` |
| Proposta de adoção do catálogo obtida no clone | `b3f12e604b450b4fe4032677897095f71bb2d39f50bbce58d0ca069882a5e26a` |
| Recibo final | `62d634014454c0e70aabed77e3e67092c58869c0fd0f2e730b0e5eae8b874e41` |

Hashes verificam alterações, não são assinaturas ou aprovação recorrente.

## Correções de compatibilidade e testes

Inspeção da imagem real revelou três labels de procedência herdados; a receita
passou a admitir e conferir somente essas chaves/valores estruturados, recusando
labels adicionais. Regressão acrescentada;11testes de continuidade passaram.

A CI da fonte b81f7bd encontrou uma falha real no grupo0: Compose v2 omite
`create_host_path:false` no JSON renderizado, enquanto o CLI local o preserva.
Correção6fb319e faz o pacote compilado escrever `false` explicitamente e segue
recusando `true`; não remove teste ou controle. Regressões de omissão e tentativa
de criação implícita acrescentadas. Escopo/pacote/continuidade:34passaram.
Rodada anterior completa:46novos e regressões60/114/96, com sobreposição.
CI anterior permanece com falha; CI da correção é distinta e deve ser conferida
nos quatro jobs Python e React antes de declará-la verde. Links/contagens finais
nos comentários de#58/#7. Código preparado/testes/ensaio nativo são distintos.

## O que permanece pendente

Original ainda tem catálogo versionado vazio; a autorização usada foi somente
para clone. Está pronta a [proposta separada de adoção original](../../../labs/wazuh/CYCLE-PREPARATION.md),
ID`4b058e1a6f194fb1a76d37117fbb7520`, SHA256 canônico
`e52f0d0e5d1fcf588c4c46b47d3c38a3957000e7b40b54b416c44f5833fb727a`.
Ela exige backup/original com hash exato e o mesmo plano de catálogo demonstrado;
PG384MiB+helper256MiB, somente os três acréscimos, sem migração/grants/contas/
binding/PKI/Wazuh/marcador. Operador preparado, sem execução ou autorização.

Após cleanup, preflight integrado novamente recusado:4.881.993.728bytes
(~4,55GiB) disponíveis, mínimo8GiB. Não desligar terceiros nem reduzir o gate.
PKI vigente/pacote de runtime/ACL/regra/agente/observador e autorização do ensaio
único ainda faltam. #58/#59/#60 e pai#7 permanecem abertos; não houve campanha
atual, DETECTED novo, UI/exports ou implantação do stack.
