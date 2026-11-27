# Aceite offline do registro de laboratórios — #25

Fonte integrada corrigida: `c419d4b5c4bfe91bf8d1c35b9de7863748625ac4`.
Escopo: #108 → #109 → #110; dependência #4 fechada, sem bloqueadores nativos
adicionais. Sem implementação de outra entrega. A condição da #25 é offline:
fixtures/Firefox Demo não comprovam implantação, mTLS nativo ou detecção real.

## Comportamento conferido

| Unidade | Resultado e provas |
| --- | --- |
| #108 | Registro host-only opt-in, IDs/revisões/owner/isolamento/PKI e endpoint restrito. Caminhos, symlinks, permissões, tamanho, chaves JSON duplicadas, SSRF e identidades duplicadas recusados. Lista administrativa omite caminhos/chaves/endpoint; confirmação inclui hash dos certificados públicos. `tests/test_lab_registry.py` e `tests/test_lab_registry_api.py`. |
| #109 | Migração explícita `f3b28c5d901a`, vínculo exclusivo e ativo opcional de campanha com FK composta. Colunas/JSONs históricos preservados; downgrade recusa perder seleções. Preflight, autorização, escopo, fila, worker e recuperação resolvem o lab exato; drift invalida a operação. Dois runners HTTP em memória completam dispatch/cleanup separados, sem contato nativo. `tests/test_multi_lab_execution.py`, testes de API/concorrência e regressão. |
| #110 | Cadastro por conexão revisada, owner host-only, seleção de ativo e allowlist por laboratório, estados revogado/desconectado/sem capacidade e histórico por ativo. Windows não recebe controles/perfil Linux. React e Firefox verificam o percurso, incluindo1440/390px. |

Um registro Linux mantém exatamente um runner/ativo; múltiplos registros são
laboratórios distintos. Demo pode selecionar ativos sintéticos explícitos.
Wazuh continua sujeito à política revisada existente, sem registro livre de
conectores/agentes. Identidades internas e externas são exibidas separadamente;
esta entrega não inventa `agent.id`. Remoção/drift nunca redireciona recuperação
para outro runner nem atualiza evidências/aprovações anteriores.

## Verificações locais realmente executadas

Comandos e efeitos detalhados em [testing](../../development/testing.md) e no
[procedimento de operação](../../operations/lab-registry.md). Credenciais dos
serviços já existentes foram selecionadas só no processo, sem mudar `.env`,
contas, grants ou dados de outros projetos. Suítes PG/Redis15 foram sequenciais.

- `pytest tests/test_lab_registry.py -q --tb=short`:25 aprovados no contrato final.
- Regressão inicial Linux/binding/fluxo/migrações:132 aprovados.
- Suíte ampliada dos12arquivos indicados em testing:238 aprovados/1falha em239.
  A falha simulava drift via monkeypatch da antiga função global de hash, que
  deixou de resolver operações por lab. O teste passou a mudar a configuração
  temporária em disco, mantendo a exigência de INVALIDATED/zero dispatch.
- Reexecução complementar de `test_lab_registry.py`, `test_lab_registry_api.py`,
  `test_multi_lab_execution.py` e `test_linux_scheduling.py`:62 aprovados, incluindo
  esse caso corrigido e quatro casos acrescentados. A coleta final dos12arquivos
  contém243casos; não se anuncia uma execução local única de243aprovados.
- `npm --prefix apps/web test`:172 aprovados/23arquivos. `make lint` e
  `make build`:aprovados. Verificação de sintaxe dos dois roteiros JS:aprovada.
- `scripts/check_staged.py`, `git diff --cached --check` e
  `scripts/check_release.py`:aprovados antes dos commits.

A primeira preparação PG falhou por credencial local desatualizada (nenhuma
asserção de produto validada); tentativas permanecem locais. Desenvolvimento
React teve falhas de fixture/sincronização e tipagem corrigidas, sem exclusões de
testes ou gates. A primeira tentativa Firefox falhou no preenchimento do nome;
`acceptance-61o1yvd8` está FAILED, com cleanup confirmado. `acceptance-rrowubnr`
passou nas asserções iniciais, mas a captura móvel revelou cartões comprimidos:
foi recusada visualmente. CSS corrigido, verificação de legibilidade adicionada e
ensaios repetidos. Uma recusa por TIME_WAIT da porta, antes de criar recursos,
levou a corrigir somente o probe de socket do harness. Tentativas e logs locais
foram preservados; não são substituídos pelo aceite final.

## Compatibilidade histórica descoberta na CI

A CI da fonte3d3f9cb, execução45684589411, foi **FAILURE**: a partição1 teve
três falhas no caminho de rotação; a partição2 teve dez erros de preparação
(a inserção ORM de campanha em b7 seguida de falhas de fixture em cascata).
Partições0/3 e React passaram; isso não foi anunciado como workflow verde.

Correção `c419d4b`: a seleção nova é deferred/raiseload no ORM, não lida nem
reescrita pelo caminho legado. O probe /1 conserva as colunas históricas
obrigatórias, valida `registry_id` quando presente e aceita sua ausência nos
schemas preservados. RLS/tipos/nullable/read-only/identidade/histórico permanecem
verificados. A fixture de catálogo b7 insere somente sua projeção física e
restaura head inclusive se a preparação falhar; dados/asserções de preservação
não foram substituídos por uma migração implícita de b7.

Localmente, a primeira verificação de compatibilidade teve115aprovados e uma
falha na preparação do novo caso NOT NULL (linhas de fixture ainda nulas).
A preparação foi corrigida transacionalmente; reexecução dos três casos de
schema, binding, registro/API e dois runners:27aprovados. Os dez testes de
adoção de catálogo passaram separadamente. Rotação completa, interrupção e
cleanup com pins históricos ficaram entre os115aprovados. Sem skips novos,
filtros ou remoção de checks para obter green.

## Firefox final e encerramento

Comando: `.venv/bin/python scripts/lab_registry_e2e.py`, com as credenciais de
infraestrutura apenas no ambiente do processo. Pacote host-only final:
`.local/lab-registry/acceptance-pninquzz`, status **VERIFIED**.

API/worker/schema/conta próprios; dois labs Demo e um Windows de fixture. O
cadastro Linux usa bytes de PKI offline inválidos para transporte e permanece
revogado/desconectado. Nenhum preflight nativo, marcador nativo, SIEM ou volume
original foi acessado. As duas campanhas **synthetic=true** foram COMPLETED:

- `622a8aab-80bc-473f-adc2-0c2bc8ba2dd0`;
- `0599b1ca-0486-496d-8de4-1c37424abb54`.

Seleção exata de ativo pela UI e histórico da segunda run conferidos sem
interceptar/substituir a API. Duas capturas1440/390px, sem overflow/compressão dos
IDs e zero erros JavaScript; inspeção visual realizada. Processos próprios
encerrados, schema removido e porta18789 sem listener. API/worker Demo existentes
mantiveram IDs, imagens e StartedAt idênticos ao registro anterior ao ensaio.
Consulta posterior ao catálogo PG confirmou zero schemas `aegis_registry_e2e_*`
remanescentes; recibo host-only em `.local/labs25-environment-final.json`.

| Artefato local preservado | SHA-256 |
| --- | --- |
| `summary.json` (404bytes) | `d52554fe3087ea6d7217b05a4de88d6bcf937a02822b5b7648af9d26af3e75bf` |
| `labs-1440.png` (325680bytes) | `2268b33c60abd9c9b13bc1f39c002de69e85b00aab751e2a0da3a3dcd7a9a515` |
| `labs-390.png` (265435bytes) | `ef80edeee5637e1579fbd918470a543470031d71281527578a9ce52a381a4966` |

Hashes comprovam identidade dos arquivos locais, não assinatura ou eficácia.
Sem implantação, migração de originais, mudança de rede/qasrc/PKI, uso de
pacotes/autorização históricos ou operação contínua. A migração nova exige código,
imagem e procedimento compatíveis em futura implantação explicitamente autorizada.

## CI e sincronização

Commits publicados em `origin/main`:

- `724d200` — `feat(labs): define protected deployment registry` (Refs #108);
- `c17d653` — `feat(labs): bind execution and history to reviewed lab assets`
  (Refs #108/#109);
- `3d3f9cb` — `feat(ui): select reviewed connections and authorized lab assets`
  (Refs #110);
- `c419d4b` — `fix(labs): preserve historical schema readers after registry migration`
  (Refs #109).

CI da fonte integrada corrigida:
[Validate AEGIS45686709531](https://github.com/Buraddomoon/AEGIS/actions/runs/45686709531)
**SUCCESS**, executada em25/11 e conferida para o aceite em27/11/2026.
As quatro partições Python e React foram verificadas individualmente:

| Job | Aprovados | Skips previstos |
| --- | ---: | ---: |
| Python0 | 1010 | 2 |
| Python1 | 1053 | 2 |
| Python2 | 1060 | 1 |
| Python3 | 1111 | 4 |
| Total Python | 4234 | 9 |
| React (23arquivos) | 172 | 0 |
| Glob | 21 | 0 |

Logs/contagens preservados host-only em `.local/labs25-final-ci-*`. Não houve
filtros/exclusões ou alteração do workflow para obter green. A execução
anterior724d200 foi SUCCESS, mas não substitui esta validação integrada.
A CI intermediária45684004820 foi cancelada pela publicação seguinte;
45684589411 foi FAILURE, conforme descrito acima. Ambas permanecem registradas.

Aceite conjunto offline da #25 e critérios das #108/#109/#110 atendidos.
Os quatro commits executáveis acima estão publicados em `origin/main`;
o fechamento documental é um commit separado, sem implantação, tag ou release.
Comentários finais nas issues registram seu hash/mensagem e sincronização.
**Parar nesta entrega, sem iniciar outra feature ou operação de laboratório.**
