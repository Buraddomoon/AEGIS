# Consulta Sigma nativa verificada — #17 / #87 / #88 / #89

**SIGMA_NATIVE_QUERY_VERIFIED / CLEANED**,23/11/2026,
14:17:25.538264–14:17:59.511858UTC. Uma consulta positiva e uma negativa geradas
pelo conversor oficial consultaram o índice real autorizado. Sem novo marcador,
campanha, veredicto ou implantação de regra. Fonte executável
`13ff3d8f1c6b2dbd42aeb7506b2a5a1a884afb81`.

## Autorização e tentativas preservadas

Após a preparação local, o usuário autorizou o ensaio: “autorizo, pode fazer”.
As [tentativas de18/11](NATIVE-ATTEMPTS.md) terminaram INCONCLUSIVE/CLEANED; a
última comprovou HTTP403 ao ler mapping, sem executar queries Sigma.
Em23/11 foi apresentada a [manutenção mínima e reversão](../../operations/sigma-metadata-acl-proposal.md).
O usuário escolheu explicitamente **“Autorizar ajuste mínimo e reversão”**,
incluindo PKI temporária válida e preservação dos originais.

A primeira tentativa com essa manutenção, pacote
`092f932522da458b84f36f6b0afbf7f3`,14:11:39.915599–14:12:05.124438UTC,
obteve snapshot da role, mas o PATCH com operação `test` recebeu400. A role
original foi conferida/restaurada antes do cleanup; zero queries Sigma. Resultado
INCONCLUSIVE/CLEANED, sem OOM ou reinício, mínimo5.192.675.328bytes disponíveis.
Escopo `adf3412d10d1f0a49bcdbbd1aa3af529bd4611abfa867ac6a6b8d0b75982037f`,
operador `9a3a21eb13b9aaf017c040c2ccb1f1bbccbc833cb0f331d1fbb2b0011f651bd1`.

O [código oficial Security2.19](https://github.com/opensearch-project/security/blob/2.19.0.0/src/main/java/org/opensearch/security/dlic/rest/api/AbstractApiAction.java)
aceita somente add/replace/remove. A correção usou essas operações sem ampliar a
lista de privilégios, com conferência exata por GET antes/depois e um único
escritor administrativo em rede isolada, comprovado pelo operador. **Não há
compare-and-swap no servidor**; o hash da prova vincula observações do coordenador
confiável, não é assinatura/autorização independente. Drift continua bloqueando
alterações/reversão cegas. Não se apagou ou repetiu pacote anterior.

## Pacote final e identidade

Pacote novo `eae8345c8c2544938d1f71345759b706`:

- Escopo canônico: `9a3afe68c540671702843271279ccf85f40fe66dc918b0b7c0e1b71b3b895d27`.
- Operador host-only: `911e11f508ac188de2a3404b6b074148c7c744f9dd98424cc2d527909d6bb467`.
- Probe JSON privado, hash dos bytes: `9329568af7a5bc497b56e495dc47f17f9d6288bfa148714d693a340f980c0c82`.
- Metadata coletada, digest canônico: `815097b88c1edcbb1f7691c5c4d02e801a4b0ae239f6cffb02f1a79b6269aacf`.

Escopo registrado [antes dos efeitos](https://github.com/Buraddomoon/AEGIS/issues/89#issuecomment-7103765618),
após [autorização adicional específica](https://github.com/Buraddomoon/AEGIS/issues/89#issuecomment-7103614386).
180eventos de intent/observação, sequência/hashchain e150inputs reconferidos.
Artefatos operacionais e respostas integrais permanecem host-only; nenhum segredo,
dump, log ou chave foi adicionado ao Git. Hashes verificam integridade, não autoria.

Indexer oficial local4.14.9, fixado por imagem:
`sha256:9c43f316f0a4a15951b8667c0a0f97fc945a9e1ac55035b1be22c95d2b9a04e3`.
Helpers pela imagem local retida da #16:
`sha256:8787f04a88472296e175f67cdd0153ac34dbea69459a1e27eb3e73bcae188956`,
com fonte/probes atuais montadosRO e conversor isolado já instalado por lock.
Sem build/pull ou sobrescrever tags/imagens. A versão raiz anunciada7.10.2 é a
compatibilidade da API, não a versão da distribuição Wazuh.

PKI de ensaio nova e separada, sem modificar certificados/chaves/CA antigos.
TLS1.3, CA/SNI/hostname/IP e fingerprint verificados antes de transmitir credenciais.
Certificado DER: `efb8fb20ca87f07ca46ed33c6810da8558139be77aab93fd9fcd822586dfaf8a`.
Somente o Indexer recebeu seu par; helpers receberam só CA pública. A CA privada
nova não foi montada. Seleção restrita aos containers temporários, não à operação normal.

## #87 — metadata física e ACL

Índice concreto: **`wazuh-alerts-4.x-2026.11.16`**. Foram coletados e revisados
mapping/settings/aliases reais; template e `_source` não foram usados como
substitutos. O gate verificou novamente os mesmos hashes antes/depois de cada
consulta; nenhuma alteração de mapping ou settings foi realizada.

| Campo físico usado | Tipo observado |
| --- | --- |
| `data.aegis.schema` | keyword, sem normalizer/truncamento declarado |
| `data.aegis.observation` | keyword, sem normalizer/truncamento declarado |
| `agent.id` | keyword |
| `timestamp` | date, `date_optional_time\|\|epoch_millis` |

Sem aliases do índice. Sem nested/disabled/runtime/source filtrado nos caminhos
usados. Comprovação limitada a esses quatro campos e à revisão deste perfil:

- Mapping: `14bd3a55b73526f114c59ade805c957c0ab4104169f902372148d3c1c6a457c2`.
- Settings completos: `17bcbe245ff9fcca2f4df474737e6519e86a5cf55cc82cf464479684a84ec385`.
- Perfil `aegis-marker-keyword/1`: `c8253c4aa9c8e5f9f73dfae1c4d4711a417dc789a99f90cce375cc8ad2d122e7`.

O administrador existente leu apenas a role escolhida, preservou snapshot durável
antes do INTENT e acrescentou três ações somente nesse índice: mappings/get,
monitor/settings/get e aliases/get. As consultas foram feitas exclusivamente como
`aegis_reader`, com role esperada e negativas de acesso à API Security e ao índice
de segurança mantidas. Nenhuma escrita de documentos foi tentada para testar ACL;
`write_acl_verified=false`, sem inferir proibição por um teste não realizado.

Role canônica antes e após reversão:
`29707c731e9a1cd5da0c1fc2f99455dd6d617a14aa436912ff8b87e4ea1600f9`.
Role temporária:
`969e8610d62e2aa876984985589ed07ef75caf8c0c6d647978d71d19cff073c9`.
O rollback removeu exclusivamente a entrada acrescentada e confirmou a política
original por GET antes do encerramento. Arquivos YAML originais não foram alterados.
A manutenção escreveu Security no volume Indexer; não se alega operação fisicamente
read-only nem apagamento de registros administrativos.

## #88/#89 — queries, origem e completude

Versões efetivamente salvas/exportadas por API em PostgreSQL/schema descartável,
com seus snapshots/hashes preservados. Schema removido; o Demo e o banco original
de Lab não foram usados para importar ou reescrever versões. Regra do snapshot:
`3a70b42a-23e7-4557-8a95-34afe1d55dd5`.

| Verificação | Positiva | Negativa |
| --- | --- | --- |
| Versão salva | `4756083d-a44c-4124-aa7e-ac70c99d05cc` | `0f841544-8bf0-4079-9b0c-ce9b3a197667` |
| Período de consulta em23/11UTC | 14:17:51.068260–14:17:51.508501 | 14:17:53.570536–14:17:53.644114 |
| Total exato / retornados | 1 / 1 | 0 / 0 |
| Páginas | 2, final vazia | 1 vazia |
| Completude / mapping antes/depois | true / true | true / true |
| Cleanup do cursor | succeeded=true, num_freed=2 | succeeded=true, num_freed=2 |

Ambas usaram agente001, índice exato e janela de evento
20:18:52.553–20:19:02.553UTC de16/11. Os shards iniciais foram3total/3successful/
0failed (um skipped pelo Indexer), sem timeout; total eq estável e cursor corrente.
21requisições auditadas nas duas validações, incluindo metadata antes/depois,
Search/Scroll e dois DELETEs, todos HTTP200. Chamadas de prontidão, coleta inicial
e manutenção administrativa são etapas separadas, não incluídas nesse denominador.

Positiva gerada do exemplo autoral `fixtures/sigma/aegis-marker-candidate.yml`;
negativa muda somente `marker_file_read` para `sigma_validation_negative_no_event`.
Queries reais produzidas por pySigma1.5.1/OpenSearch2.0.3/Elasticsearch2.1.1 no
processo isolado, com lock/pipeline/implementação e hash conferidos novamente.
O parser2.0.1 da aplicação e o artefato offline original não foram alterados para
marcar a verificação física; o novo recibo de validação tem identidade própria.

| Artefato | Positiva | Negativa |
| --- | --- | --- |
| Query SHA-256 | `924cbb0bf9deba5db7916e43d4a2c01bf3af2747295eb1d0167f78371cebfa4a` | `0f1b1825318f1181099b8bf7cc34f720ae121580f3d1cce8f4d1e5298c1a2e39` |
| Escopo SHA-256 | `28ce20e84fef61d155be312d709d9b88d02d0875ffe98dbf11aec7696d108400` | `e9e8b5e2f889e818f99c0b1fb802a7e978c4343528db2672deb4b19f7b08a4cd` |
| Documento de resultado SHA-256 | `ecf6524a0f58a49734414efbdd8250ae57df8016cfbc2c27e4191191678f9314` | `58d5ed8f0c107211944e5b9e9f17853859eb7d9ff05003aadf65abb5ddd7a00a` |

O positivo preservou `_id=jWQD5qEBm7izxmUqYd4q`, índice, `_source` completo e
timestamp original `2026-11-16T20:18:57.553+0000` da #59. Digest canônico do hit:
`1181e2d800bd99e3117b22b760f30223ff88c1243e0462328f2137889c2276c5`,
idêntico ao [alerta original](../wazuh-cycle-2026-11-16/alert.json).
Hashes de resultado/escopo foram reconferidos independentemente após cleanup.

## Recursos e encerramento

Rede própria interna/isolada192.168.253.16/29; Indexer.18, query reader.19,
metadata.20 e helpers administrativos sequenciais.21/.22. Sem portas publicadas,
devices, privilégios, Docker socket ou fonte gravável nos helpers. Indexer1536MiB/
heap512MiB e cinco helpers256MiB cada, swap adicional zero; gate3328MiB incluindo
512MiB de reserva. Helpers só iniciados em sequência; piso da stack completa8GiB
preservado. Preflight imediato:5.718.757.376bytes disponíveis,16CPUs,
408.959.541.248bytes livres e map_count1048576. Mínimo4.801.495.040bytes disponíveis;
sem OOM/restart/falha de supervisor.

Encerramento confirmado: role original restaurada, zero containers/redes próprios,
nove volumes preservados/zero consumidores, metadata dos volumes e150inputs fonte/
configuração/PKI idênticos. Somente Indexer-data foi montadoRW/external/nocopy;
startup e manutenção podem alterar estado/logs/registro administrativo. Não se
afirma igualdade física do volume. Intents, backups, pacotes antigos e PKI retidos.
Sem manager/agente/runner/observador/banco/API/worker de Lab, novas contas ou
bindings, migração, ingestão, sysctl, mudança em qasrc, build/pull ou operação normal.

## Testes, fonte e limites

207testes locais pertinentes passaram em31,92s após a correção do PATCH, usando
PostgreSQL/schema descartável e Redis15 em sequência. Incluem os11arquivos de
validação/conversão/coleta/ACL; as rodadas anteriores de47/207testes se sobrepõem.
Lint completo aprovado (Ruff,369Python formatados, mypy, TypeScript/Prettier).
Checks staged/segredos, diff-check e release-check aprovados antes dos commits.
O207não inclui nova contagem de detecções reais nem substitui a CI integral.

CI final13ff3d8:
[45192506887](https://github.com/Buraddomoon/AEGIS/actions/runs/45192506887),
**SUCCESS**, quatro grupos Python e React conferidos individualmente:
3857Python/9skips existentes,115React/17arquivos. Nenhum filtro/partição/timeout
foi alterado para obter aprovação.

| Grupo | Passed | Skipped | Tempo pytest |
| --- | ---: | ---: | ---: |
| Python0 | 962 | 2 | 131,66s |
| Python1 | 931 | 2 | 232,38s |
| Python2 | 1040 | 1 | 262,64s |
| Python3 | 924 | 4 | 253,45s |

3866casos coletados por partições complementares, sem omissão/overlap. A CI
d2771a2 foi cancelada pela atualização de fonte, não é workflow verde.
CI04e9c01 anterior passou, mas não substitui a fonte final. Commits posteriores
do fechamento são documentais, com inputs executáveis idênticos à fonte13ff3d8.

Implementação/testes locais, serviço de validação consultando o Indexer real e
implantação são distintos: o ensaio chamou o serviço de integração na imagem
temporária; RBAC/CSRF e banco/API foram testados localmente. Não houve implantação
da nova API no Demo: API/worker continuam na imagem
`sha256:b8abe5e44af4bad90d2e302a045f38fb9cf268932be5ea0493fc72f078657a23`.

Prova limitada aos quatro campos, duas versões/queries, um alerta existente e um
índice. Não avalia recall geral, archives, eficácia SIEM/EDR, implantação Wazuh,
novas técnicas ATT&CK ou ausência de telemetria. Pacote, manutenção e PKI de ensaio
não autorizam reativação ou operação contínua. [Aceite conjunto da #17](ACCEPTANCE-17.md)
conferido sem repetir efeitos. **Entrega encerrada; não repetir o ensaio.**
