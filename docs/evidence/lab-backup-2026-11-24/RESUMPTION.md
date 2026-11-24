# Retomada da #9 — implementação completa, ensaio histórico pendente

O usuário pediu concluir o escopo todo após a preparação parcial inicial. A
implementação restante foi feita antes de solicitar aprovação do ensaio real.
As [provas iniciais](README.md) e seus estados históricos foram preservados.

## Código e validação

| Commit | Comportamento |
| --- | --- |
| `46a6ba8` | Arquivos frios, extração manual segura e custódia privada |
| `75b8e33` | Transporte Docker saneado/limitado com timeout/kill/reap |
| `cb9dd59` | Cluster novo isolado, restore integral e cleanup durável |
| `6a07521` | Coordenador dos dois perfis, plano/escopo, gates e uso único |
| `bce1f87` | Campo opcional de metadados Docker consultado sem dereference inválida |

Todos em main/origin, sem branch/PR/force push. Nenhuma imagem construída,
substituída ou publicada; sem alteração de dependências, versão ou schema ativo.
Procedimentos em [lab-backup](../../operations/lab-backup.md) e
[lab-recovery-native](../../operations/lab-recovery-native.md).

Validações locais efetivas, PG/Redis15 sequenciais:

- `make test-lab-recovery`:297passed em54,34s, zero skips e aviso upstream
  Starlette/httpx; antes,293passed e288passed, sobrepostos.
- Após as duas negativas adicionais de rede efetiva:8casos de runtime passaram.
  Depois da correção do campo opcional:27casos de plano/metadados passaram.
  São conjuntos complementares/sobrepostos, não uma única suíte somada.
- `make lint`: Ruff/formato/mypy/TypeScript/Prettier aprovados. Checks staged,
  segredos, whitespace e release aprovados antes de cada commit.
- Suítes cobrem perda de resposta/create sem replay, ausência sem ID insuficiente,
  colisão/ownership/runtime/mounts/rede alterados, cleanup falho/interrupção,
  retenção de scratch e bloqueio da próxima tentativa, gate terminal, deadline,
  metadados/imagens, scope/hash/código/expiração e variáveis libpq ambientais.
- Fonte histórica precisa ser b7/33tabelas; outra revisão ou contagem bloqueia,
  sem migração/correção automática. Falta de CLEANED já bloqueada pelo revisor
  existente. Arquivos host/tar são dados, nunca carregados como instruções.

CI final da fonte:
[45454864685](https://github.com/Buraddomoon/AEGIS/actions/runs/45454864685),
`bce1f874bf111923267eb522cd015e30d508de2c`: **SUCCESS**, quatro jobs Python e
React conferidos. Partições0/1/2/3:982/1011/1060/1017passed, respectivamente;
**4070Python/9skips**, sem falhas. React: **154testes/21arquivos** aprovados,
incluindo lint/formato/build e revisão de dependências. Revisão de entrega da
documentação a292c79/45455424610 também SUCCESS.
CI anterior cb9dd59/45447954364 SUCCESS, de parte da implementação. As execuções
intermediárias canceladas por pushes seguintes permanecem distintas da CI final.

Aceite técnico #64/#65: código e testes completos, com snapshot consistente,
custódia protegida, restore novo em quarentena e nenhuma retomada de jobs ou
liberação por ausência/404. O ensaio da fixture descrito neste documento é synthetic=true;
o aceite histórico dos dois perfis permanece exclusivamente na #66 e no pai #9.

## Ensaio real de fixture, separado dos originais

`make test-lab-recovery-native-fixture` executou de fato pg_dump/pg_restore,
initdb/PostgreSQL novos, helpers tar RO, extração fria, pg_controldata, reabertura
da cópia e novo dump. Schema descartável e2a71c9d064b, **36tabelas/734linhas**.
O source engine foi vinculado ao cluster de desenvolvimento por system_identifier;
somente o schema exclusivo da fixture foi exportado. Sem acesso aos quatro volumes
históricos. Todos os containers próprios encerrados/removidos e scratch removido.

Fixture final da revisão6a07521:
`3536842b1dba44839c369f6dd8f20d07`, **VERIFIED**,1passed/11,26s, synthetic=true.
Recibo privado em `.local/lab-recovery-fixtures/3536842b1dba44839c369f6dd8f20d07/verified.json`.

| Medição | SHA256 |
| --- | --- |
| Recibo canônico | `a1e3dedaf9f564fbbe339432307650f4c46c7947f08e6808dee42d2404697f20` |
| Fontes exercitadas da ferramenta | `7b9233f9d9fb52e1ab717554e3d3eacb005ba1a4b981ee3279d79513bda52386` |
| Inventário SQL inicial/restaurado/reaberto | `08fb7dd36ffff15669f7fdf28d2e48e1f4c77144fbea1c39c6ea3d46d694a490` |
| Dois arquivos frios iguais | `de9b5eb15e12a2c0d1dd0bd82dd108474a8ab0e41b1a1324b44d319af81eeebc` |

UTF8/libc, locale `en_US.utf8` e collation_version null iguais. A correção posterior
bce1f87 muda apenas projeção de metadados de imagem, não esses arquivos de runtime.
O manifesto `/1` do snapshot e seus flags false não foram reescritos para representar
prova física. O envelope de recuperação/finalização é separado.

Falhas preservadas: primeiro restore recusou inventário estrutural por search_path
diferente; engine de verificação corrigido, sem normalização extra dos dados.
Uma fixture de teardown usava handle anterior à retomada e outra pinava hash
divergente; fixtures corrigidas, guardas mantidas. Uma rodada sem seleção da
configuração local correta teve48passed/1erro de autenticação PG; não houve reset
de contas/grants/arquivos. Preparação de plano recusou `.Config.Volumes` ausente
na imagem de aplicação; uso de `index` para campo opcional corrigido, mantendo a
exigência exata do volume declarado PostgreSQL. Nenhuma dessas falhas foi ensaio
histórico ou produziu recibo real da #66.

## Plano histórico pronto, sem autorização consumida

Metadados apenas: quatro volumes originais sem consumidores e censo de3689arquivos/
20.457.443bytes/zero links. Plano
`d8665fed78e349cea4080b2519157d85`, SHA
`17d63858350c61f1ebcbe4a167b8c8e9f046bfd422cbefcbc262b760bf765f5e`,
estado **PREPARED_NOT_AUTHORIZED**. [Escopo concreto para aprovação](REQUEST-66.md).

Implementação/fixture não substituem a autorização específica da #66. Originais,
PKI, Demo, qasrc, volumes auxiliares, journals/fences/candidatos e imagens antigas
preservados. Sem novo marcador, run/veredicto, cutover, migração ou implantação.
Somente após ensaio histórico aceito encerrar #66 e o pai #9, e então parar.
