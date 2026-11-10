# Identidade nova observada, registros íntegros e cleanup — 2026-11-10

Tentativa final da issue #3/subissue #47, após corrigir parsing repetido e
enumeração Btrfs. O usuário aprovou especificamente este pacote:
“Autorizo a tentativa final e o cleanup”. Houve uma invocação da CLI para esse
plano, sem retry/start manual; as duas tentativas anteriores permanecem preservadas.

**Cliente e servidor autenticaram com os certificados novos em TLS1.3, com IDs e
DER conferidos, e a verificação positiva foi repetida ao final.** O inventário
dos14 registros foi confirmado e a revisão histórica integral retornou exit0.
Os dois containers e a bridge foram removidos, conforme solicitado.

O resultado geral é **`identity_assay_inconclusive_and_closed`**, exit1, error=null.
O controle sem certificado cliente fechou a conexão sem motivo TLS verificável;
isso permanece inconclusivo. Não declarar todos os controles TLS verificados,
rejeição comprovada sem cliente, ativação do laboratório ou DETECTED.

| Conexão fixa | Resultado observado |
| --- | --- |
| Material candidato | Identidade e TLS1.3 confirmados; certificados dos dois peers conferidos. |
| Sem certificado cliente | EOF sem alerta TLS verificável; inconclusivo. |
| Somente CA servidor anterior pública | Confiança recusada, segundo a classificação fechada do probe. |
| Material candidato novamente | Identidade e certificados novos conferidos novamente. |

## Pins retidos e integridade

| Referência | Valor |
| --- | --- |
| Código executado | `fd729fda23315ff9edd768d477ac7587cd00e74c` |
| Candidato | `b7cf4e561ba2455bbf432ef1d1bd99c8` |
| Manifesto do candidato, SHA256 canônico | `198e247a0a7ec5bf64f5a7146f6c96056f9c04b80ecdc2812ab6f608d97f244a` |
| Pacote, SHA256 canônico | `f7cd21a806b101f3ea9309aa1d01816168c284ebc664e08f136e54891354e2c8` |
| Plano | `8200cec7ca81493f99e93594b2c56caf` |
| Plano, SHA256 canônico | `5a2c550a6e78ccdece5264afb6501414c0899f3ab486a5f264c695f68c0e9b68` |
| Escopo, SHA256 canônico | `7ad1e90d0718ab68329149bd1ce03f9f7d603d67fa089592107d1b693ac1700a` |
| Operação | `99102954ab604580ac570878325855c4` |
| Begin, SHA256 canônico | `616e819393a33a5ac714ad5381cc921fa00b2274fe651ccc18c1627e0068940d` |
| Corpo do recibo, SHA256 canônico | `beeb77678edc49c26244c6bb19b732182a6483a03d5e14875c23ca223d60d4a4` |

Pedido registrado às20:05:50 UTC, cleanup às20:06:37 UTC e recibo às20:06:38 UTC,
dentro dos limites originais. failure_phase, failure_code e
artifact_inventory_failure_code são null; artifact_inventory_verified=true.
TLS controls verified permanece false pela ressalva acima, sem reinterpretar EOF.

`runner_identity_review.py` foi executada com os cinco pins retidos da saída
original e retornou `saved_identity_artifacts_verified_not_runtime_rechecked`,
records_reviewed=14, recorded_assay_status=identity_assay_inconclusive_and_closed. Exit0 dessa
CLI comprova integridade dos registros relativos aos pins; não é aprovação de
todos os controles TLS nem nova inspeção do runtime.

## Encerramento e preservação

Cleanup retornou `owned_resources_absence_verified`, resources_reviewed=3,
operation_closed=true, managed_resources_absence_verified=true, sem blockers
ou remoção de volumes. A cadeia de18 eventos foi relida; runner, identity-client
e network-isolated estão ABSENT. Inspeção independente posterior confirmou
projeto sem containers/redes e volumes originais sem consumidores.

Metadados dos volumes/imagens fixadas, PKI pública original e qasrc iguais à
baseline. Inventário de redes igual. Um container de outro projeto mudou de
running para restarting com mesmo ID/imagem durante o intervalo; não foi adotado
ou alterado por este ensaio. Não alegar igualdade global dos estados de containers.
O Demo permaneceu preservado.

Não houve DB/Redis/API/worker/Wazuh, marcador, montagem dos volumes originais,
mudança de PKI/binding ou permissão de operação normal. O material original,
candidatos, imagens, planos, autorizações, artefatos e fences foram preservados.
Diretórios privados e logs não são publicados; este documento contém somente
pins públicos e resultado proporcional às evidências. Hash não é assinatura.

## Validação e aceite delimitado

CI integral do código executado: [42889684349](https://github.com/Buraddomoon/AEGIS/actions/runs/42889684349),
quatro partições Python e React SUCCESS. Source-review42889684314 também SUCCESS.
Testes locais da correção Btrfs:90passed/1aviso upstream; reprodução somente de
filesystem confirmou leitor anterior0arquivos/leitor corrigido14. A correção
anterior f49f987 teve345testes locais e CI integral42883729885 aprovada; não somar
rodadas repetidas. Comandos e diagnóstico estão registrados na issue #47 e no
[diagnóstico técnico](../../development/identity-assay-diagnostics.md).

O objetivo positivo de autenticar as identidades novas foi observado em ambiente
nativo, com integridade e encerramento conferidos. O aceite de #47/#3 preserva
explicitamente o controle negativo inconclusivo e não libera execução normal.
As autorizações foram consumidas. Não executar outra tentativa, renovar TTL,
apagar fences ou avançar para ativação/binding/diário sem outro escopo autorizado.
