# Segunda tentativa, com autorização específica — 2026-11-10

Após a correção f49f987, o usuário aprovou explicitamente o novo pacote:
“Autorizo essa nova tentativa e o cleanup”. Foi uma invocação da CLI para esse
plano novo; não houve retry, start manual ou reaproveitamento da autorização anterior.

O cliente e o servidor autenticaram com os certificados candidatos em TLS1.3,
com identidade e DER conferidos, e repetiram a verificação positiva ao final.
O controle com CA anterior foi recusado. Sem certificado cliente houve fechamento
da conexão sem motivo TLS verificável: **esse controle é inconclusivo**.

O cliente terminou `probe_completed_and_removed` com
`identity_tls_controls_inconclusive`. O recibo geral terminou
`identity_assay_failed_and_closed`, exit1, por
`identity_assay_artifact_inventory_unconfirmed`, com diagnóstico
`identity_artifact_unexpected_inventory`. O erro de enumeração Btrfs foi depois
reproduzido em fixture de filesystem e corrigido; ver
[diagnóstico técnico](../../development/identity-assay-diagnostics.md).
O recibo geral não é promovido a sucesso e permanece inalterado.

| Referência | Valor |
| --- | --- |
| Fonte executada e CI completa aprovada | `f49f9879dbcd68ea77cb9bb607f96dccebb73895` |
| Candidato | `5010d1020d51455181620e4dcca08206` |
| Manifesto do candidato, SHA256 canônico | `7a5d4512ed0b4e7df79eb8d4a74f469d34d8fd6b6863dadfaa6d2106023f8a41` |
| Pacote, SHA256 canônico | `218a82daff73a6692a883629909998cdb1675695eb84aba9f6095794c1d679d7` |
| Plano | `5894e87571194ba1996418a1b234e558` |
| Plano, SHA256 canônico | `4ab870acd397812b6e22adf64467576911d228a2859ac8dc3543b5fd306eeb3d` |
| Escopo, SHA256 canônico | `9eb0dbd8da98780a61f47d7f2e1cdce018cf33c0de52442d5e50723afcb3c7f9` |
| Operação | `6ae6cc6ff1044904bd8353cad5116097` |
| Begin, SHA256 canônico | `f9e4fdb057a7de009017e64799c70f1f2eb215fb7061089d7456b82aff3ff5eb` |
| Corpo do recibo, SHA256 canônico | `7d430f50da7bf2f69753eab8520bb44a1576e6354a74a63c97a7375b782f58d8` |

Pedido registrado às19:44:30 UTC, cleanup às19:45:17 UTC. O gate start do cliente
foi observado às19:44:56.858452 e persistido às19:45:04.136877, dentro da janela
original; start e revisão exited foram concluídos. Nenhum limite foi aumentado.

**Cleanup confirmado:** dois containers próprios e bridge removidos, três
recursos ausentes, operação encerrada, zero blockers e nenhum volume removido.
Inventário independente posterior confirmou projeto vazio/volumes sem consumidores
e igualdade da baseline para containers, redes, qasrc e metadados de volumes/imagens
fixadas; PKI pública original preservada. Nenhum DB/Redis/API/worker/Wazuh, marcador,
montagem de volumes originais, mudança de PKI/binding ou operação normal.

Há14 arquivos de registro preservados somente no host, junto aos planos, fences,
saída original e inventários, sem upload de chaves/logs. A CLI de revisão continua
recusando a confirmação integral do recibo que declara inventário não verificado;
a correção do leitor não muda esse fato histórico. Nenhuma terceira tentativa
foi feita; a autorização deste plano está consumida.
