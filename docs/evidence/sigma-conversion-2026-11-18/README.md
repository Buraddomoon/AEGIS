# Conversão Sigma offline — entrega #16

18/11/2026. Fonte executável completa:
`69ae1e4f2730c64b93841d1f8a67c3e2250ada16`. Escopo exclusivo#16/#84/#85/#86.

## Problema resolvido e comportamento

A [pesquisa inicial](../sigma-compatibility-2026-11-18/README.md) continua
correta: os wheels publicados OpenSearch2.0.3/Elasticsearch2.1.1 exigem core<2,
incompatível com o parser2.0.1 da aplicação. Não foi necessário fazer outra
entrega, ignorar requisitos ou reduzir o parser da aplicação.

Após pedido explícito para resolver o bloqueio, o
[ADR0036](../../architecture/decisions/0036-isolated-sigma-converter.md)
adotou um conjunto oficial compatível em venv/processo separados:
pySigma1.5.1/OpenSearch2.0.3/Elasticsearch2.1.1. São18pins/wheels/hashes, resolução
completa e pip check; os locks originais da API continuam idênticos. Não houve
alteração/cópia de código upstream, checkout Git, patch de METADATA ou instalação
de backend incompatível no processo da API. Nenhum serviço de rede foi criado.

- #84: conjunto isolado, lock próprio, instalação de desenvolvimento/CI/Docker,
  auditoria separada e teste de import/conversão oficial sem cache/efeitos.
- #85: perfil novo `aegis-marker-lucene/1`, política literal-boolean/1, pipeline
  oficial fechado, API somente leitura por versão exata e artefato com procedência.
  Unsupported tem motivo e query/hash null; ausência/drift/falha não geram sucesso.
- #86: ação **Gerar consulta** em Regras, escolha da versão, query e procedência,
  conferência criptográfica do contrato/documento/query antes de mostrar download.
  Resposta de outra versão/perfil, erro/refetch e contrato alterado não mantêm
  sucesso ou artefato anterior. O download JSON inclui a query e sua procedência.

O perfil/hash candidato anterior e os contratos de análise/prévia não mudaram.
Textos da UI identificam o candidato não executável sem apresentar esse
diagnóstico como indisponibilidade global do conversor isolado.

## Limites e integridade

Somente logsource exato do marcador,16seleções planas/8campos, strings até512bytes
ou listas de8strings, AND/OR/NOT/parênteses limitados. Modificadores/fieldref,
keywords/selectors, números/null/booleanos, wildcards/backslash, campos sem destino
e metadados executáveis/desconhecidos são recusados. Chaves duplicadas/merge
YAML são recusadas antes do parser para não descartar termos silenciosamente. Estimativa conservadora de
expansão antecede o processo; YAML64KiB, JSON64KiB e query8KiB. API confere regra/
ownership/versão/SHA e limita30/min/usuário; perfis60/min. Viewer permitido, sessão
obrigatória. Mesmas políticas RBAC/CSRF/origem de importação existentes.

Python-I/-B e ambiente limpo,3sCPU/512MiB virtuais/5s de prazo, até2filhos por
processo da API. Audit hook antes do backend impede imports de cache/discovery/
validators/data, rede, subprocessos e mutação de arquivos. Invariância da detection
é conferida após o pipeline oficial. Nenhum YAML de pipeline/índice/destino/plugin
ou comando do cliente é aceito pelo conversor.

Hash não é assinatura. A query gerada não foi executada no SIEM; caminhos
candidatos não comprovam tipos/analisadores ou correspondência no índice físico.
`siem_queried`, `deployment_performed` e `index_mapping_verified` são false.
Nenhuma regra foi implantada e nenhuma eficácia é alegada. Validação nativa da
consulta continua na entrega#17, fora desta sessão e sem autorização implícita.

Não houve alteração de regra/versão histórica, scope, aprovação, evidência,
veredicto, cobertura ou relatório. Demo e Linux/Wazuh originais não foram
implantados/iniciados; volumes, PKI, qasrc, journals e pacotes consumidos intactos.

## Verificações locais efetivamente executadas

```sh
make sigma-converter-setup
.venv/bin/python -m pytest tests/test_sigma_conversion.py tests/test_sigma_converter_worker.py tests/test_sigma_readiness.py tests/test_sigma_mapping.py tests/test_sigma_mapping_api.py tests/test_sigma_analysis.py -q --tb=short
.venv/bin/python scripts/audit_dependencies.py
npm --prefix apps/web test
npm --prefix apps/web run build
npm --prefix apps/web run lint
npm --prefix apps/web run format:check
npm --prefix apps/web audit --audit-level=high
.venv/bin/ruff check apps/api scripts tests
.venv/bin/ruff format --check apps/api scripts tests
.venv/bin/mypy
```

Resultado final da suíte pertinente: **139passed em19,54s**,1warning existente
Starlette/httpx. Inclui48casos novos do processo/adaptador/API e91regressões;
não somar rodadas repetidas. Duas sondas adicionais confirmaram lista OR
`data.aegis.schema:(one OR two)` e literal com espaço
`data.aegis.schema:"one two"`, sem alterar a fonte. Golden queries reais
AND/OR/NOT/parenteses, semânticas
negativas, efeitos reais bloqueados em processo novo, core2.0.1 preservado,
protocolo corrompido/timeout/ausência/capacidade, limites, Redis indisponível,
ownership, RBAC, conteúdo legado e histórico imutável.

PG em schema descartável e Redis15, executados sequencialmente. A primeira
tentativa específica do adaptador teve15passed/3errors de autenticação PG por
divergência da configuração.env; após usar as credenciais dos serviços próprios
já ativos somente no ambiente do processo, a suíte integral pertinente passou.
Nenhuma senha/conta/grant/env foi alterado; credenciais não foram escritas no Git.

React: **115passed/17arquivos**, incluindo17casos novos de consulta/integridade/
download/races; mais21casos de segurança do glob, registrados separadamente.
Uma primeira versão do teste de race identificava `/v1/` também no prefixo da API;
o teste foi corrigido para `/versions/v1/` e os17casos passaram. Lint/formatação/
tipos/build passaram. Auditoria npm:0vulnerabilidades. Auditoria Python dos dois
grafos:1finding distinto já revisado, DiskCache5.6.3/PYSEC-2026-2447, sem novos
findings. Não houve import de DiskCache; não é alegação de zero vulnerabilidades.
Uma tentativa inicial de auditar os dois cores como grafo único foi recusada;
o script agora audita separadamente os ambientes, sem esconder conflitos.

## Firefox real e artefato baixado

Percurso de `scripts/e2e.py`/`apps/web/e2e.mjs`, com API/worker/PG/Redis reais de
teste, contas e schema próprios; porta18784 e Redis14. Credenciais dos serviços
de desenvolvimento foram passadas em memória ao processo. Comando do percurso:

```sh
AEGIS_E2E_SCREENSHOTS=../../.local/sigma16/screenshots-final .venv/bin/python scripts/e2e.py
```

Resultado: **PASS**,5runs/20testes Demo sintéticos,2snapshots automáticos,
4PDFs,17capturas e0erros JS. São dados de teste, sem laboratório nativo.
O percurso agora gera uma query pelo backend/pipeline reais isolados, confere
hash/flags e texto na UI e clica no download real. Um observador do Blob preserva
o download do navegador e permite comparar o JSON baixado à resposta exata da
API. Não há mock de API/backend. Relatórios histórico e automático congelado
continuam idênticos antes/depois. Diálogo verificado a390px sem overflow;
captura desktop inspecionada visualmente. Recursos de teste encerrados/schema
descartado pelo finally do ensaio; nenhum serviço próprio do ensaio ficou ativo.

Exemplo observado, somente sintético:

```text
data.aegis.schema:aegis\-json\/1 AND data.aegis.observation:marker_file_read
```

| Contexto | Valor verificado |
| --- | --- |
| Regra / versão do ensaio | `c68241c1-66d2-4321-a6c2-456f2a305022` / `5fdd3679-d531-46c6-945f-6f00258b4002`, v1 |
| Conteúdo SHA-256 | `ffd65ed3e668c4bbd76a8c9de64c8ac1029feca23a0e388c3fdfaa4b02b33413` |
| Perfil SHA-256 | `2b41c55d951ba1e46a222e560b9b36f3ce0b55049a9039cc60d8c3848cf096db` |
| Implementação SHA-256 | `0a089ab9c2f89eaeb61bbb12e6d9da8496c98639f11058f9bb8f95a9904d6b9b` |
| Contrato SHA-256 | `05384e98437fc49aa98231074250311cc3c91d547513aa8469e6922658d0abff` |
| Query UTF-8 SHA-256 | `924cbb0bf9deba5db7916e43d4a2c01bf3af2747295eb1d0167f78371cebfa4a` |
| Documento canônico SHA-256 | `e3a416915cd458546e58e1471dbaa71343539f669c382cb25ab9b58aee523f19` |
| Bytes do JSON baixado SHA-256 | `65c2190facb68602c570f9a052c6490300ecfe11a82eb37af5eadb3286d0e6b5` |

O arquivo local `.local/e2e/sigma-query.json` foi reconferido independentemente
em Python; hashes do documento canônico e dos bytes do download são distintos
por serialização/indentação. Captura `.local/sigma16/screenshots-final/sigma-query.png`
SHA-256 `19ee6c26ae728487a601f8a711c4a130daeb21dbe5f0f82d537ff395371b2ef7`.
Esses gerados/logs são host-only, não adicionados ao Git. A tabela registra os
fatos revisados sem atribuir durabilidade ou assinatura externa aos temporários.

## Build e implantação são estados diferentes

Build dedicado final `docker build --pull=false -t aegis-sigma16-review:69ae1e4 .`
aprovado; imagem `sha256:8787f04a88472296e175f67cdd0153ac34dbea69459a1e27eb3e73bcae188956`.
Sonda com `docker run --rm --network none --read-only --cap-drop ALL
--security-opt no-new-privileges --pids-limit 32 --memory 768m --cpus 1`, apenas
import/conversão, confirmou core2.0.1 na aplicação, core1.5.1 no filho e query
converted/mesmo contrato; input com chave duplicada retornou unsupported. Nenhum mount, serviço de banco, API ou Lab iniciado
nesse container. Também houve build/sonda intermediários com tag própria; não
foram apresentados como implantação ou como fonte final de UI.

Demo ativo continua na imagem anterior
`sha256:b8abe5e44af4bad90d2e302a045f38fb9cf268932be5ea0493fc72f078657a23`.
Nenhuma tag/imagem ativa foi sobrescrita. Novas imagens de revisão locais retidas
em tags dedicadas; nenhum push de imagem, bump, tag Git ou release publicado.

## CI e sincronização

CI integral da fonte final:
[44379443285](https://github.com/Buraddomoon/AEGIS/actions/runs/44379443285).
**SUCCESS**, head69ae1e4 conferido: **3781Python passed/9skips** e
**115React passed/17arquivos**, mais21casos de segurança glob. Os quatro jobs
Python e React foram conferidos individualmente, incluindo lint/tipos/build e
as auditorias. Nenhum filtro/exclusão/timeout/partição foi reduzido para obter green.

| Partição | Passed | Skipped | Deselected | Tempo pytest |
| --- | ---: | ---: | ---: | --- |
| Python0 | 962 | 2 | 2826 | 129,01s |
| Python1 | 869 | 2 | 2919 | 203,10s |
| Python2 | 1026 | 1 | 2763 | 246,06s |
| Python3 | 924 | 4 | 2862 | 206,68s |

Coleta complementar:3790casos,3781passed+9skips, sem somar deselected.
Skips existentes: projeção opt-in de imagem1, Demo API ausente1, ferramentas PG
locais ausentes1, Demo DB ausente1, rede Demo ausente1 e objetos próprios de
inspeção Wazuh ausentes4. Não foram criados esses recursos para eliminar skips.
Logs completos são host-only; links dos jobs constam da workflow.

Histórico de falhas preservado:
[44375980908](https://github.com/Buraddomoon/AEGIS/actions/runs/44375980908)
falhou no setup dos quatro jobs Python porque make supunha `.venv` no runner;
React passou. `SIGMA_SETUP_PYTHON=python` corrigiu o ambiente CI em `bf0288e`.
A [44377146133](https://github.com/Buraddomoon/AEGIS/actions/runs/44377146133)
foi cancelada pela substituição normal de fonte ao publicar a UI final; não
é apresentada como workflow aprovada. A
[44378077888](https://github.com/Buraddomoon/AEGIS/actions/runs/44378077888)
também foi substituída pela correção final de YAML ambíguo. Checks locais são
evidência distinta. O E2E foi repetido depois dessa correção: as contagens acima
são da última rodada; a primeira PASS na fonte5322558 permanece host-only em
`.local/sigma16/e2e-source532` e não é somada como novos casos.

Commits executáveis, todos em main com push direto:

- `850fe020e7dce02f5083ea87fab3a1a903fbb280` — build(sigma): isolate compatible official converter dependencies (Refs #84).
- `bf0288e9b9aa30a2e04d4dda17c196f30980e235` — feat(sigma): generate bounded versioned query artifacts offline (Refs #85).
- `532255813369304aa5d996c7e73146a7168fa382` — feat(sigma): show verified query artifacts for exact rule versions (Refs #86).
- `69ae1e4f2730c64b93841d1f8a67c3e2250ada16` — fix(sigma): reject ambiguous YAML before query conversion (Refs #85).

Checks de staged/segredos, diff --cached --check, check_staged.py e
check_release.py executados antes de cada commit. Último hash/mensagem e
sincronização final são registrados nos comentários das issues. Aceite conjunto da#16 conferido após as provas de#84/#85/#86:

| Critério | Evidência / limite |
| --- | --- |
| Backend/pipeline oficialmente compatíveis |18pins resolvidos e instalados em ambiente separado, pip check, classes oficiais e testes reais; parser da API2.0.1 preservado |
| Conversão limitada por regra/versão/perfil/hash | API/contrato, positivos/negativos, golden queries, limites/RBAC/histórico e CI integral |
| Unsupported explícito sem perda silenciosa | Motivos, query/hash null, recusa de modificadores/fieldref e YAML ambíguo antes de converter |
| UI/artefato íntegros |115React, hashes/contexto/races, Firefox real e download observado; sem alegação de implantação/eficácia |
| História e autorizações preservadas | Schemas/contas de teste separados, relatórios congelados idênticos; zero operação SIEM/Lab/originais |
| Fonte/testes/build/implantação distintos | CI69ae1e4, imagem dedicada testada sem rede/volumes e Demo ativo b8 anterior |

#84/#85/#86 e critérios do pai#16 atendidos. Nenhuma dependência da entrega#17
foi antecipada. Encerrar esta entrega e parar; implantação do Demo não foi
realizada. Último commit documental e estado local/remoto constam dos comentários
finais, sem atribuir os testes a uma fonte executável diferente.
