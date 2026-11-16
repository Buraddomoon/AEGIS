# Catálogo original e imagens corrigidas — 16/11/2026

**ORIGINAL_CATALOG_ADOPTION_VERIFIED / CLEANED.** Após a resposta específica
**“Autorizar catálogo no original”**, o plano demonstrado no clone foi aplicado
uma vez ao PostgreSQL original entre16:55:59 e16:56:10UTC,77eventos duráveis.
Essa autorização foi utilizada; não concede replay ou operação do laboratório.

## Catálogo original

Antes do startup, original e backup frio novo mantinham inventário físico
`2c19f3edf9ea9c176ed21dc75f78f23b52969b737ff9e0c449c6bb90d1704522`.
O banco confirmou o inventário lógico b04c7c04 completo do
[ensaio em clone](CLONE.md), schema **b7f3c2d91a06/33tabelas**.

PostgreSQL384MiB, rede none/loopback interno, sem porta publicada; helper256MiB
no namespace privado. O plano do catálogo foi revalidado sob locks antes de
escrever. Resultado: **uma release, um estado e uma auditoria de bootstrap**.
Linhas antigas, verificadores de senha, schema e grants preservados, incluindo
as linhas anteriores da auditoria. Sem seed, migração, novas contas, alteração
de binding, PKI, Wazuh, runner/observador ou marcador. Banco/helper encerrados;
conferência independente confirmou metadados e zero consumidores dos nove
volumes originais e do backup retido.

| Artefato | SHA256 canônico |
|---|---|
| Proposta aprovada | `e52f0d0e5d1fcf588c4c46b47d3c38a3957000e7b40b54b416c44f5833fb727a` |
| Plano/escopo executado | `9b6313c852201bc6337409572cf7628afd41a3cbdcbfb20e573919f42af7f6d7` |
| Inventário lógico anterior | `b04c7c04f4717b842b175a605d1388f27e81b33f0576ccd1be9ed21fe82ce33a` |
| Inventário lógico posterior | `f2eb67a757579f0efe50f29e0b2abd895826a31d3d120c2a6cd01d2520dc36e2` |
| Recibo final | `595976d45f00d03bdcd8e91e501613f985c2d61bcc3f9eb61ea8a94ef3bbf0d7` |

Release inicializada:
`b572391494ef2b9ec7b68095bef5ba16c7190da123497c1b814b9c5c0ce6b3e2`.
Os novos registros têm IDs/horários próprios da aplicação original; não foram
copiados do clone para produzir igualdade artificial do inventário final.

O conteúdo físico original mudou legitimamente:68.965.095bytes/1.476entradas,
inventário `fc78c93f63c91d2b7570bda8c779d281f60e690b5d7cb6258a77865bcab0ffd4`.
O backup frio b7 pré-catálogo continua68.391.491bytes/1.475entradas e mesmo
hash2c19f3ed. Working com catálogo e backups/clones anteriores também retidos.
Não apresentar o original como byte a byte intacto após essa escrita autorizada.

Operador/helper/autorizações/SQL/recibos permanecem protegidos host-only em
`.local/wazuh-original-catalog/4b058e1a6f194fb1a76d37117fbb7520`. O helper
relata preservação SQL; o driver separado vincula o alvo físico original.
Hash não é assinatura ou autorização recorrente. Nenhum segredo foi publicado.

## Imagens locais com o patch da dependência

A [correção de OpenTelemetry](../../security/review-wazuh-cycle-dependencies-2026-11-16.md)
atualizou os dois locks para1.45.2, com hash oficial do wheel. Foram preparadas
imagens derivadas das bases locais anteriores, preservadas em tags dedicadas.
Sem atualização de outros pacotes, pull de Wazuh, montagem de volumes ou startup
da plataforma. Build steps e verificadores usam rede none. Em cada imagem,
73arquivos Python e45versões runtime foram conferidos durante build e em
processo separado RO/sem rede/128MiB. Somente opentelemetry-api mudou de versão.

| Uso futuro | Tag dedicada | ID local |
|---|---|---|
| API/worker | aegis-wazuh-platform:otel-patch-657ced1c7f4a | `sha256:9e3488c42adecf3c6a3ffb5588752bc75bae5e31f72e215d9777e950de7dd527` |
| Runner/observador | aegis-wazuh-runner:otel-patch-657ced1c7f4a | `sha256:77dec5415d0f8acb9ad523d56e086c9face00edff9004ab9bf19ae1e58bb26c9` |

Manifestos novos referenciam a fonte9493c0e e o lock corrigido. Bases e tags
históricas de13/11, Demo:0.1 e Wazuh:local mantêm os IDs anteriores. A presença
dos IDs/tags e a ausência dos verificadores foram conferidas independentemente.
Recibo canônico do build/conferência:
`8e3c2736aea09590179976375425cbeb92daff9ada685445b0c12f96bcbc6221`,
host-only em `.local/wazuh-dependency-patch/657ced1c7f4a4c87af09eed4703bc92e`.

Falhas intermediárias foram preservadas: primeiro, template de campos opcionais
de imagem recusado antes de qualquer mutação; depois, BuildKit interpretou
`FROM sha256:ID` como nome de repositório e recusou a resolução de metadados,
antes de executar estágios do build. Não houve camada baixada nesse erro.
Continuação usou tag local dedicada, conferida contra o ID imutável antes/depois,
e verificou a linhagem de camadas. Logs/intents/recibo de falha não foram apagados
ou substituídos pelo recibo final. Nenhuma imagem foi publicada ou implantada.

## Validação da fonte e limites restantes

[CI integral43913368799 SUCCESS](https://github.com/Buraddomoon/AEGIS/actions/runs/43913368799),
fonte `9493c0e41a5a2929a84e6aa34cbf3d86f5b9da43`, cinco jobs conferidos:

| Job | Passaram | Skips |
|---|---:|---:|
| Python0 | 858 | 2 |
| Python1 | 813 | 2 |
| Python2 | 918 | 1 |
| Python3 | 837 | 4 |
| Total Python | **3426** | **9** |
| React | **91** | 0 |

O [source-review9493c0e](https://github.com/Buraddomoon/AEGIS/actions/runs/43913368816)
também passou. Skips opcionais continuam explícitos; nenhuma exclusão foi
adicionada. Testes, lint/tipos/build e auditorias passaram; diskcache revisado
continua visível. As runs anteriores com falhas de Compose/auditoria mantêm
seus resultados. Validação local atual:49casos de retomada e119da correção da
dependência; regressões anteriores60/114/96. Conjuntos sobrepostos, sem soma
artificial. CI de fonte não equivale a implantação ou campanha defensiva.

Depois do build, preflight novamente recusado:5.058.166.784bytes (~4,71GiB)
disponíveis, mínimo8GiB. Não parar terceiros ou reduzir o gate. Continuidade e
catálogo foram resolvidos nas etapas autorizadas e encerradas. Ainda faltam
PKI vigente, pacote/revisão do runtime integrado e autorização específica do
ensaio único quando houver recursos. Nenhuma tentativa atual, alerta novo,
DETECTED, UI/exports ou cobertura ATT&CK foi fabricado; #58/#59/#60 e pai abertos.
