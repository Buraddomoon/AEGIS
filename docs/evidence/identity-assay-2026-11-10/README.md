# Tentativa nativa identity-only — 2026-11-10

Resultado da subissue #47, após preparar #45 e obter a aprovação específica de
#46. O usuário autorizou o pacote apresentado: “autorizado, depois que acabar
derruba”. Uma única invocação da CLI revisada foi realizada; não houve retry,
start manual ou intervenção para alterar o resultado.

**Resultado: `identity_assay_failed_and_closed`, exit1.** A falha foi registrada na
etapa cliente/start, sem resultado TLS validado. O cleanup terminou com os três
recursos próprios ausentes e a operação encerrada. Não declarar sucesso de mTLS,
ativação ou DETECTED. A entrega #3 permanece aberta.

| Referência | Valor |
| --- | --- |
| Commit executado | `02408cde22ca0f78a3c5e49b458ae235c2d27a05` |
| Fonte executável testada | `f0c95b2f6cdb62fb7da219cbe93a18807838758d` |
| Pacote de revisão, SHA256 canônico | `634db436ad8bd7f0b91ca6fb54c205b6badb617e61fb39def972769ae08a4636` |
| Plano | `218022f318ab4c5cbbfcb163c90d43e6` |
| Plano, SHA256 canônico | `48b681cdcbefb1a45f46b44a53d5d455d470380e5869bd94c5f736445695010d` |
| Escopo, SHA256 canônico | `5795abc9000c41434d57622d12b81e926ef64fc0f9a5ae89ac83ce870c61668f` |
| Operação | `dd43e2f7c5fa43e6aca74ed34ae6a7f8` |
| Begin, SHA256 canônico | `ff1f766ba8e90a5c895d045fd6b2ea0099bbdd1906b4c31ffc91b25b689e3d10` |
| Corpo do recibo, SHA256 canônico | `e315a78f4c4c2e44ae835e3183e2805feba8bafc775ce641d380c9b6e10c05a5` |

O pacote estava vigente, main limpa e fonte/imagem equivalentes aos códigos
testados. A autorização foi registrada separadamente, preservando o pacote.
A tentativa utilizou a [imagem atual selada](../identity-image-2026-11-10/README.md).
Os comandos/pins e os critérios de autorização permanecem no
[procedimento](../../../labs/linux/IDENTITY.md) e nas issues #45/#46.

## Observações efetivamente registradas

- Begin às18:53:19 UTC; cleanup registrado às18:54:09 UTC, dentro do orçamento
  original. Rede criada e servidor identity-only iniciado/revisado; o cliente foi
  criado e recebeu fence START_REQUESTED, mas sua execução não foi confirmada.
- Lifecycle do cliente: `probe_execution_unconfirmed`,
  `identity_client_execution_unconfirmed`, fase `start`, failure_code=null,
  result=null. Sem gate exited ou resultado dos quatro controles. O recibo não
  identifica a causa exata; não atribuir a TLS/CA ou disponibilidade sem prova.
- Cleanup: `owned_resources_absence_verified`, resources_reviewed=3,
  operation_closed=true, managed_resources_absence_verified=true, sem blockers.
  Cadeia durável dos17 eventos relida: runner, identity-client e network-isolated
  em ABSENT. Projeto sem containers/redes ou consumidores dos volumes originais
  na inspeção independente posterior.
- Metadados dos volumes originais/imagens fixadas, PKI pública original e qasrc
  iguais aos da baseline. Inventário de redes igual; nenhum container anterior
  desapareceu. Um container de outro projeto foi acrescentado ao inventário
  global durante o intervalo; não foi adotado, parado ou alterado pelo ensaio.
  Igualdade global de containers não é alegada.

## Limitação da revisão dos registros

Há13 registros privados, incluindo cleanup e recibo, todos preservados. O recibo
declara `artifact_inventory_verified=false` e artifacts=null. A CLI
`runner_identity_review.py` foi executada com os pins retidos da saída original
e retornou exit1, `identity_saved_artifacts_unconfirmed`. Essa recusa é uma falha
de validação integral; não foi contornada nem transformada em aprovação.

Uma inspeção somente leitura dos envelopes individuais confirmou encoding/hash/
âncoras dos13 arquivos naquele momento. Isso não corrige o recibo, não explica
por que o inventário não foi confirmado durante a execução e não equivale à
revisão completa do conjunto. Nenhum registro foi editado para fazer o gate passar.

PKI privada, stdout/stderr da CLI, artefatos, baseline e inventário posterior
continuam somente no host, fora do Git. O registro de autorização é uma anotação
local, sem assinatura criptográfica. Não publicar os diretórios privados.

## Encerramento e pendências

Os recursos próprios foram derrubados conforme solicitado. Não houve montagem
dos volumes originais, DB/Redis/API/worker/Wazuh, marcador, campanha, mudança de
PKI/binding ou operação normal. Os históricos, candidatos e fences foram preservados.

A autorização de uso único está consumida. #47 e #3 permanecem abertas: falta
diagnosticar a falha de cliente e de inventário sem repetir o efeito, e comprovar
a identidade nativa em eventual tentativa futura sob outro pacote/plano e nova
aprovação. Não reiniciar, renovar TTL ou apagar registros/fences desta operação.

Validação anterior:364 testes locais passaram; CI integral da fonte e revisão
documental aprovadas, conforme a evidência de imagem. Não houve alteração de
código executável após a tentativa para alegar que essa validação cobriria uma
correção. A atualização deste resultado altera somente documentação.
