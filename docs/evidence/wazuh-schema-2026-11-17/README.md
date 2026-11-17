# Perfil Wazuh consultado nativamente — #63/#8

**NATIVE_PROFILE_QUERY_VERIFIED / CLEANED**,17/11/2026,
`13:30:35.033354–13:30:55.354029UTC`. Consulta do alerta original da #59
preservado no Indexer real4.14.9; zero novos marcadores, campanhas ou vereditos.
Não é nova evidência de detecção nem implantação permanente.

## Autorização e fonte

Após o bloqueio inicial, o usuário pediu explicitamente concluir a #63:
“ue, pq nao fez a 63? pode fazer mano”. O
[escopo concreto](../../../labs/wazuh/SCHEMA-QUERY-ASSAY.md) foi registrado na
issue antes dos efeitos. Cada tentativa teve pacote/intent novos; resultados
anteriores e autorizações históricas consumidas foram preservados.

Pacote final `f3297fc7b401419ebbcecb3c8a7d0451`, escopo canônico SHA256
`5602d974b9cb67cd766843153ed9748f30d8e134cf624c935eba6aa22e230e4b`.
Fonte executável `3a758a6ab793cdda5321596cdc8354c5125d73cd`.
Operador host-only SHA256 dos bytes
`757142ddadb35bd74ece7b16d163ea334603c6d28a6d977aa3d91f8eeaae8dda`.
Hashes identificam artefatos; não são assinaturas ou autorizações reutilizáveis.

Indexer pela imagem local oficial fixada4.14.9:
`sha256:9c43f316f0a4a15951b8667c0a0f97fc945a9e1ac55035b1be22c95d2b9a04e3`.
Leitor pela imagem local existente
`sha256:9e3488c42adecf3c6a3ffb5588752bc75bae5e31f72e215d9777e950de7dd527`,
com pacote Python atual/probes montadosRO e hashes reconferidos antes/depois.
Isso executou a fonte atual no leitor sem rebuild ou atualização do Demo.
A resposta raiz de compatibilidade não foi usada para inferir versão do Wazuh.

## Resultado observado

Perfil **`wazuh-4.14.9/1`**, `timestamp`, agente001/regra100200; política canônica
SHA256 `a62500cb1448c21630e52414e7c9128fb30d9e3f80a352ed07cf36484f791c8e`.
Intervalo delimitado ao redor do evento histórico, não um recibo substituto.

| Verificação | Observação real |
| --- | --- |
| TLS | TLS1.3, CA/hostname/SNI/IP e fingerprint exatos antes das credenciais |
| Certificado DER | `c03e316afcabe10977e2e60378b629e41e24508cc2a20ed345d3b4329fd90c34` |
| Prontidão | GET raiz sem credenciais passou de503para401; depois vieram as consultas autenticadas |
| Principal/ACL | `aegis_reader`/role esperada; acesso à API Security e leitura do índice de segurança negados |
| Alerta original | `_index=wazuh-alerts-4.x-2026.11.16`, `_id=jWQD5qEBm7izxmUqYd4q`, uma correspondência exata |
| Origem integral | `_id/_index/_source` canônicos SHA256 `1181e2d800bd99e3117b22b760f30223ff88c1243e0462328f2137889c2276c5`, igual ao [alerta preservado](../wazuh-cycle-2026-11-16/alert.json) |
| Tempo | `2026-11-16T20:18:57.553+0000` original preservado; offset normalizado UTC equivalente |
| Correlação da consulta | Lab/ativo/job/marcador/comportamento exatos da #59; somente agente externo001 traduzido ao ativo aprovado |
| Negativa de filtro | Marcador com sufixo diferente: zero hits, total exato0, consulta completa; não é uma conclusão sobre detecção |
| Paginação | Total exato1→1 nas páginas positivas, página final vazia; nove shards iniciais bem-sucedidos, dois na continuação, zero falhos/timeouts |
| Cursores | Três DELETEs do cursor corrente, todos `succeeded=true`/`num_freed=2`; tokens não publicados |
| Archives opcional | **HTTP404**, `telemetry_available=false`, coleta incompleta com motivo específico; alertas continuaram disponíveis e com mesmo hash |

São14requisições do probe autenticado, incluindo Search/Scroll/DELETE e a
negativa de ACL, além dos dois GETs de prontidão sem credenciais. O alerta foi
consultado novamente ao combinar alertas/archives, preservando o conteúdo.
O404 não comprova archives desativados nem distingue sozinho índice ausente de
uma resposta condicionada pela segurança. Nenhum archive foi ativado ou ingerido;
normalização de eventos de archives e perfil `@timestamp` continuam só contratuais.
`write_acl_verified=false`: não se enviou escrita para testar sua proibição.

## Recursos e encerramento

Somente Indexer1536MiB/heap512MiB e leitor192MiB, swap adicional zero por container;
rede própria interna/isolada ADR0034 `.16/29`, IPs`.18/.19`, nenhuma porta publicada.
Gate exigiu2.348.810.240bytes (tetos+512MiB de reserva); imediatamente antes dos
efeitos foram observados3.618.193.408bytes,16CPUs,414.285.307.904bytes livres no
filesystem Docker e map_count1048576. Mínimo observado2.356.551.680bytes; sem
OOM/restart/falha do supervisor. O piso8GiB da stack completa permanece.

Runtime conferiu IDs, usuário, memória/swap/CPU/PIDs, capacidades, mounts RO,
ausência de portas/devices/privilégios, rede exclusiva/IP do Indexer e readonly
do leitor; endereço fixo do leitor conferido na configuração. Só o volume
original do Indexer foi montadoRW/external/nocopy; sua inicialização pode escrever
estado/logs normais. Não se afirma igualdade física dos dados após startup.

Containers e rede próprios removidos; **zero consumidores dos nove volumes**,
metadados desses volumes e todos os arquivos fonte/configuração/PKI examinados
idênticos.71eventos no registro de intents, sequência/hashchain verificados após
cleanup. Sem banco/API/worker da plataforma, manager/agente, runner/observador,
binding/approval/conta, migração, build/pull, sysctl ou operações em qasrc.
Backups, imagens/PKI/IDs/journals/fences antigos preservados. Outra cópia com
alterações locais não foi editada. `normal_operation_permitted=false`.

## Falhas e diagnósticos preservados

| Tentativa | Resultado e causa |
| --- | --- |
| `771a1c21`13:10:36–13:10:39 | INCONCLUSIVE/CLEANED; opção `create --no-deps` não suportada pelo cliente. Nenhum container/startup. Campo mínimo de RAM ainda era sentinel, não usado como métrica. |
| `bfed33a9`13:12:22–13:14:59 | INCONCLUSIVE/CLEANED; `docker inspect` excedeu5s e supervisor encerrou. Saída do leitor não capturada. Mínimo1.627.672.576bytes. |
| `08424ea4`13:20:12–13:20:32 | INCONCLUSIVE/CLEANED; leitor exit1, attach sem diagnóstico. Mínimo2.160.795.648bytes. |
| `39029779`13:26:38–13:26:55 | INCONCLUSIVE/CLEANED; logs recuperados do ID original: alerta/negativa passaram, suposição incorreta de403 em archives impediu o aceite. Mínimo2.685.145.088bytes. |
| `f3297fc7`13:30:35–13:30:55 | NATIVE_PROFILE_QUERY_VERIFIED/CLEANED; estado404 efetivo de archives documentado, sem alterar grants/dados para obter um resultado esperado. |

Diagnóstico separado `transport-205297e2bbd94d51bd27e5b7fd0cde57`: container64MiB,
sem rede/volumes, entrada fictícia17bytes/newline, exit0; attach sem stdout e
`docker logs` com JSON correto, depois removido. Não é ensaio de SIEM. Corrigidos
stdin sem EOF (`StdinOnce=false`), recuperação de logs, prontidão HTTP e suposição
indevida sobre archives; nenhuma falha/outcome antigo foi reescrito.
Preparação4a4b2a3d sem efeitos também permanece no host; não reutilizar.

## Artefatos privados e verificações

Artefatos completos em `.local/wazuh-schema-native/f3297fc7b401419ebbcecb3c8a7d0451/native-state`,
sem upload de credenciais, chaves, logs brutos ou configuração privada.

| Arquivo | SHA256 dos bytes |
| --- | --- |
| `authorization.json` | `8c76843a9154a884e9ef0e29dd616af83b557926265bc2b4acc29de0e2043a15` |
| `probe.json` | `aee36679e8943f2868200c882fad5754aef1438784ebd71f318d12caa80e0f96` |
| `outcome.json` | `d512707f41b5c640185d2a5c7717f029baebce2f342970fe7b482cdcf4900dd7` |
| `intents.jsonl` | `3e745a1928b2904bee7e6c6d971f4c3e1787bda152361b63e20ccbd34dd5946c` |
| `volumes-before.json` e `volumes-after.json` | `c6100e901cb055ef0cabdefadca518b44a6e19909c59defe45080101cce030be` |

`make test-wazuh-schema`: **84passed/1,37s**, fixtures locais; não somar rodadas
intermediárias sobrepostas. Inclui contratos, stdin sem EOF, limites/duplicatas,
TLS/prontidão, recusas de conteúdo alterado/paginação/cleanup e disponibilidade
de archives403/404/200. `make lint` completo aprovado, assim como verificadores
staged/release antes de cada commit. Aviso upstream Starlette/httpx preservado.

CI da fonte do conector fbe192d:
[44086844300](https://github.com/Buraddomoon/AEGIS/actions/runs/44086844300)
SUCCESS, quatro grupos Python e React conferidos. CI da fonte final do probe
3a758a6:[44093362930](https://github.com/Buraddomoon/AEGIS/actions/runs/44093362930)
ainda pendente no registro; source-review44093363209 aprovado separadamente.
Estado final da CI/commits/sincronização nos comentários de#63/#8.
O aceite nativo encerra a #63 e permite aceite conjunto da #8, limitado à matriz.
Esta autorização foi consumida. Parar, sem reiniciar o ensaio ou outra entrega.
