# Preparação offline da execução Atomic — #14

Baseline `421a03e`, main limpa e igual a origin/main. Lidos AGENTS, guia de
sessão, #14, seus três filhos nativos e provas finais das dependências #13/#5.
Não foi lido o PROGRESS inteiro nem usada conversa anterior como autorização.

## Implementação

`270e48d49e340a2fdb3cfb54b6c6e822cf64e2b8`:
`docs(atomic): pin the reviewed file permission candidate (Refs #78)`.
[Dossiê reproduzível](../../integrations/atomic-permissions-review.md), fixture
oficial integral/licença e inspeção de fonte/metadata. #78 encerrada com provas.

`7e3dde580a6ea9336c47d234c892316c402c1963`:
`feat(atomic): add one pinned owned-file permission adapter (Refs #79)`.
Somente GUID `34ca1464-de9d-40c6-8c77-690adf36a135`, T1222.002. O programa
próprio aplica `fchmod`0400→0600 num arquivo de43bytes gerado pelo próprio job;
não executa shell, processo chmod, comandos, setup ou cleanup do YAML upstream.
Não generalizar para detecções de command line/process creation do Atomic oficial.

Revisão completa SHA256
`9e283889776cbd42ebf9b7b25bc1ebfbad452157398ecbe0ab77415136c35673` prende
GUID/commit/hash/licença/configuração/versão/hash do programa e compõe o test_id.
O escopo/binding preserva o manifesto completo. O runner verifica e executa os
mesmos bytes próprios, sem reabrir o caminho após conferência. Perfil exclusivo,
UID sem privilégios, workspace/journal privados e novos, aprovação segregada,
dispatch durável, lease/deadline, processo supervisionado e cleanup confirmado.

Reutiliza `execution_kind=linux_marker` como transporte de arquivo fixo;
`behavior=owned-file-permissions` distingue o novo efeito. Não há novo schema,
serviço ou engine de shell. O seed é explícito e não foi aplicado a um original.
Entradas importadas/revisadas, inclusive o mesmo GUID, continuam não executáveis.
Serialização histórica do perfil marcador e seus recibos não ganhou campos.

## Validação local efetiva

Rodadas **sobrepostas**, não somar os números:

| Comando/conjunto | Resultado |
| --- | --- |
| `pytest tests/test_atomic_review.py -q`, #78 |2passaram/0,19s |
| Protocolo/engine/transporte do runner |36passaram/1,32s |
| Primeiro conjunto de software/API após seleção correta do PG |47passaram/43,38s |
| Regressão13arquivos |274passaram/115,45s |
| Conjunto final5arquivos |181passaram/94,67s |
| Publicação ATT&CK após correção da expectativa de impacto |15passaram/1skip/8,36s |
| `make lint` |Ruff/formato/mypy/TypeScript/Prettier aprovados |
| `npm --prefix apps/web test` |98passaram/16arquivos |
| `pytest --collect-only -q` |3584coletados; coleta não é execução |

Conjunto de13arquivos: `test_atomic_execution`, `test_atomic_review`,
`test_linux_campaigns`, `test_runner_protocol`, `test_runner_engine`,
`test_runner_transport`, `test_runner_journal_continuity`, `test_binding_review`,
`test_linux_binding_rotation`, `test_linux_schema_compatibility`,
`test_atomic_api`, `test_atomic_catalog`, `test_integrations` (todos em `tests/`,
extensão `.py`, `-q`). Rodada final após guardas adicionais: os dois Atomic,
campanhas Linux, continuidade do journal e binding review.

Exercitados: modos/recibos reais do programa próprio apenas em temporários;
perfil incompatível, comandos/paths/revisões livres recusados, drift de fonte/
programa/definição, API/RBAC/CSRF/aprovação segregada, ausência de promoção por
metadata, dispatch antes da RPC, cancelamento/lease/restart e cleanup, arquivos
desconhecidos preservados, perda de resposta/commit e recuperação sem replay.
JSON/HTML e métricas mantêm Demo/real/recibo/evidência separados. API/worker
completaram a fixture com INCONCLUSIVE, sem eventos ou evidência defensiva.
RPC por TestClient/MockTransport não comprova mTLS ou isolamento nativos.

Aviso conhecido Starlette/httpx preservado. A primeira tentativa local com a
role runtime não tinha CREATE SCHEMA:28erros de setup/19testes sem PG aprovados.
Selecionadas somente no ambiente do processo as credenciais de administração
local já existentes, sem alterar grants, contas ou arquivos de configuração.
Repetição47passou. Suítes PG/Redis15 executadas em sequência, schemas próprios
descartáveis; nenhum banco de outro projeto alterado. Um ajuste de formatação
foi aplicado antes dos checks/commit; não houve exclusão de teste ou relaxamento
de CI. Logs privados em `.local/issue14`, sem upload.

## CI integral

A primeira [run44167225423](https://github.com/Buraddomoon/AEGIS/actions/runs/44167225423),
fonte7e3dde5, encontrou1falha na partição1 (830passaram/2skips). O teste de
publicação ATT&CK pressupunha `demo-shell` na posição0 do impacto; a nova
definição Atomic também deve exigir revisão quando T1222.002 está ausente do
candidato reduzido. O comportamento estava correto; a expectativa posicional
foi substituída pela exigência dos **dois IDs**, técnicas, versão e aprovação.
Imutabilidade/ausência de mutações continuam verificadas. O commit
`e2e02776951e01fe3ba7f4aaaf1ce810488625d7`, `test(atomic): require the new catalog impact without positional assumptions (Refs #79)`,
altera somente essa asserção, sem filtros ou relaxamento de gates. A suíte local
de publicação passou; o skip é o alias loopback já usado pela conexão local.

Na primeira run, Python0 e React passaram;2/3 foram canceladas automaticamente
pela substituição da run. Resultado global CANCELLED, com a falha1 preservada.
Não é validação integral verde nem soma de rodadas complementares.

Fonte exata `e2e02776951e01fe3ba7f4aaaf1ce810488625d7`,
[run44168295232](https://github.com/Buraddomoon/AEGIS/actions/runs/44168295232):
**SUCCESS**, cinco jobs e respectivos logs conferidos:

| Job | Resultado |
| --- | --- |
| Python0 |937passaram/2skips |
| Python1 |831passaram/2skips |
| Python2 |940passaram/1skip |
| Python3 |867passaram/4skips |
| React |98passaram/16arquivos; lint/tipos/formato/build/auditoria aprovados |

Total único da CI: **3575Python passaram/9skips opcionais**,3584coletados,
igual à coleta independente local. Skips: projeção opt-in de imagem, objetos
Demo API/DB/rede ausentes, ferramentas PG locais ausentes e quatro inspeções
Wazuh sem objetos Demo próprios. Não foram criados recursos para obter green;
sem filtros/exclusões/partições/timeouts novos. Auditoria Python manteve
1finding explicitamente revisado; npm0. Isso não é alegação de zero findings
Python nem validação de um laboratório. A última consolidação altera somente
Markdown, com inputs executáveis idênticos à fonte aprovada.

## Fonte privada preparada, sem imagem

`scripts/runner_activation_image_source.py prepare` e `verify` passaram,
81arquivos do commit7e3dde5, source ID `d49012c559c54639afd52356823f36b4`.
Manifesto SHA256 `a0455a690dcc7b6e021fb6f41640e7cb890131e526815d967784e1cae91f4ded`,
árvore SHA256 `b95dc6e7bdbabb601c3609d6e95577ed503e05a3b6d37a7a4fae13ce2c5e417f`.
Contexto retido em `.local/pki-image-sources/d49012c559c54639afd52356823f36b4`.
`image_built=false`, `image_provenance_verified=false`, `effects_authorized=false`.
O snapshot contém fonte versionada, sem env/PKI/logs/runtime; não é pacote
operacional autorizado, imagem instalada ou evidência de laboratório.
Os81inputs de build foram comparados por bytes/SHA256 com HEAD e permanecem
idênticos depois do ajuste exclusivo no teste de publicação em e2e0277.

## Limites e bloqueio da #80

Sem build/start de Lab, marcador/Atomic em endpoint, migração/seed/abertura de
volumes originais, consulta defensiva ou implantação. Sem eficácia/detecção
atribuída a T1222.002. Redes qasrc, PKI, IDs, imagens, journals/fences, campanhas
e evidências históricas preservados. Sem bump/tag/release/PR/branch ou mudança
de visibilidade do repositório.

Consulta RO final aos containers ÆGIS mostrou somente os quatro serviços
Demo já existentes (API/worker/PG/Redis), sem reinício por esta sessão.
`GET http://127.0.0.1:18780/api/v1/health/ready` retornou
`status=ready,database=true,redis=true`; isso não é implantação da fonte nova.

#80 continua aberta: não existe autorização específica nem imagem/ambiente
nativo/pacote de uma tentativa revisados. As autorizações #5/#7/#8 foram
consumidas. [Procedimento e bloqueadores](../../operations/atomic-permissions.md)
separam preparação de fonte, revisão de imagem/ambiente, autorização e ensaio.
Não preencher IDs, imageIDs, resultado ou aprovação fictícios para prosseguir.
Pai #14 permanece aberto e a sessão encerra nesse limite.

Antes dos commits: revisão staged/segredos, diff --cached --check,
check_staged/check_release aprovados; push direto origin/main após cada commit.
Comentários #14/#79/#80 registram resultado final, último hash e sincronização.
