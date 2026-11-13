# Validação integral da fonte — issue #10

## Diagnóstico remoto — #67, 13/11/2026

A [run42671146994](https://github.com/Buraddomoon/AEGIS/actions/runs/42671146994)
da fonte `0609ad293db69c8f87822fe610037e1982f60fb2` continua `failure`.
A API informa tentativa2 e check suite115572612052 com falha, mas somente o
job129348390003, `Python partition 1`, aparece concluído com sucesso. A consulta
da tentativa1 não retorna jobs. O check desse job não tem anotações e
`gh run view 42671146994 --log-failed` não retorna logs de job com falha.
Os grupos0/2/3 e React ausentes não podem ser considerados aprovados.

O [incidente oficial Actions/Checks API](https://www.githubstatus.com/incidents/tp8cghg7tlc4)
registra falhas ao iniciar/atualizar runs entre18:07 e18:59UTC em09/11, cobrindo
a execução18:07:12–18:26:45UTC. O relatório do provedor atribui a indisponibilidade
a capacidade/limites insuficientes após migração de banco do Actions.
A coincidência temporal e os jobs ausentes sustentam a classificação como falha
de infraestrutura; a API não comprova a causa interna individual desta run.
O CorrelationID `e6a1e75e-97aa-4415-982b-f6da9520983e` foi preservado do inventário
da issue, sem reapresentá-lo como anotação recuperada nesta consulta.

Em13/11, o [status oficial](https://www.githubstatus.com/api/v2/summary.json)
indicava Actions operacional e nenhum incidente ativo. Não foi feito rerun da
fonte antiga. A workflow e o particionador permanecem inalterados: quatro grupos,
max-parallel2,18min, fail-fast desabilitado e todos os checks existentes.

Verificação local na fonte `3a6059ac8d70fe4d5e0936debb4f95819db96054`:
`.venv/bin/pytest tests/test_ci_partitions.py -q` →16passed,0failures,
1warning de depreciação Starlette/httpx. É teste do mecanismo de seleção,
não execução da suíte completa.

## Validação integral — #68, 13/11/2026

Fonte fixada: `1f667b1592c5b5e56b2843b50dcccd24e95329f5`.
A [run43440100468](https://github.com/Buraddomoon/AEGIS/actions/runs/43440100468),
iniciada uma vez por `gh workflow run ci.yml --ref main`, terminou `success`.
Os cinco jobs foram conferidos pela API, incluindo suas etapas e logs.
É uma workflow integral aprovada dessa fonte, sem composição com runs antigas
ou execução local. Nenhum check, timeout, partição ou filtro foi alterado.

| Job remoto | Aprovados | Skips | Selecionados | Tempo pytest |
|---|---:|---:|---:|---:|
| [Python0](https://github.com/Buraddomoon/AEGIS/actions/runs/43440100468/job/131935187924) | 832 | 2 | 834 | 175,07s |
| [Python1](https://github.com/Buraddomoon/AEGIS/actions/runs/43440100468/job/131935187694) | 805 | 2 | 807 | 277,72s |
| [Python2](https://github.com/Buraddomoon/AEGIS/actions/runs/43440100468/job/131935187948) | 911 | 1 | 912 | 248,44s |
| [Python3](https://github.com/Buraddomoon/AEGIS/actions/runs/43440100468/job/131935187862) | 829 | 4 | 833 | 149,60s |
| Total Python | **3377** | **9** | **3386** | — |
| [React](https://github.com/Buraddomoon/AEGIS/actions/runs/43440100468/job/131935187297) | **91**,15arquivos | 0 | 91 | — |

Cinco coletas locais independentes, em sequência na mesma fonte, confirmaram
`3386 = 834 + 807 + 912 + 833`: união exata de nodeIDs, nenhuma omissão, extra,
duplicação ou sobreposição. Comandos: `.venv/bin/pytest tests -q --collect-only`,
seguido de `.venv/bin/python scripts/run_ci_tests.py --shard N --collect-only`
para N=0,1,2,3. Coleta local não foi contada como teste executado. As contagens
selecionadas correspondem aos aprovados+skips de cada job remoto; os casos
`deselected` são os destinados às outras partições, não exclusões da união.

Os9skips existentes foram conferidos no resumo `-ra`:

- Grupo0:1projeção opt-in de metadados de imagem e1inspeção de API Demo ausente.
- Grupo1:1inspeção de compatibilidade sem ferramentas PostgreSQL locais e
  1inspeção de banco Demo ausente.
- Grupo2:1inspeção de rede Demo ausente.
- Grupo3:4inspeções Wazuh sem objeto Demo próprio preexistente.

Nenhum desses testes cria os recursos ausentes para passar a inspeção. As
suítes de integração restantes executaram com PostgreSQL/Redis próprios dos jobs.
Cada grupo emitiu1warning de depreciação Starlette/httpx, sem falha de teste.

Ruff lint/format e mypy passaram no grupo0. Auditoria Python passou com
1finding previamente revisado: `diskcache5.6.3/PYSEC-2026-2447`, caminho do parser
não afetado segundo o gate existente; isso não significa zero findings.
React passou TypeScript, Prettier, Vitest, build e `npm audit --audit-level=high`
(0vulnerabilidades reportadas). Dependências foram instaladas dos locks.
O [source-review43440053259](https://github.com/Buraddomoon/AEGIS/actions/runs/43440053259)
também passou para a fonte fixada.

Logs e coletas permanecem privados em `.local/ci-issue10`, sem versionar logs ou
dados de runtime. Nenhum fluxo de produto foi alterado nesta entrega documental;
E2E não foi reexecutado nem herdado como validação nova. CI/fixtures não são
ensaio Linux/Wazuh nem implantação.

## Publicação e implantação — #69, 13/11/2026

As #67 e #68 foram concluídas em sequência, com comentários de evidência e
fechamento no GitHub. Commits desta entrega, somente em main:

- `1f667b1`: diagnóstico remoto, `Refs #67` e fonte fixada da CI integral.
- `3eccdc2`: registro das contagens/checks completos, `Refs #68`.
- O commit documental `docs(ci): publish validation and deployment checkpoint
  (Refs #69)` publica esta seção e os links no guia de testes/sessões; o hash
  final e o estado remoto ficam nos comentários de #69 e #10, evitando
  autorreferência impossível no próprio commit.

Os commits posteriores à fonte testada alteram apenas Markdown. O conjunto de
inputs fora dos `paths-ignore` de `ci.yml` contém **418 arquivos**, incluindo
aplicação, testes, scripts, locks, workflows, políticas JSON e receitas.
SHA256 desse conjunto: `5ff9a27a2d8eb67bbe767b0d660e09b4b894f86fda79775884ba8cbd851f4820`.
Foi calculado sobre as linhas de `git ls-tree -r COMMIT`, na ordem original,
removendo caminhos terminados em `.md`, `docs/images/**` e `LICENSE`, juntando
as linhas por LF e acrescentando um LF final, em UTF-8. Cada linha inclui
modo, tipo, object ID e caminho. Comparar as listas, além do digest, comprova
a equivalência dos inputs Git entre a fonte fixada e a entrega documental;
não equivale a executar a CI novamente em cada hash documental.

O Demo foi apenas inspecionado, sem build/restart: `aegis-api-1` e
`aegis-worker-1` usam `aegis-local:0.1`, imagem
`sha256:b8abe5e44af4bad90d2e302a045f38fb9cf268932be5ea0493fc72f078657a23`,
sem mounts de código e sem label OCI de revisão. O guia associa historicamente
essa implantação a `0609ad2`; a inspeção atual confirma o ID, não uma revisão
nova nem equivalência com a fonte validada. As imagens Wazuh locais preparadas
na #58 também não foram implantadas por esta entrega. Portanto, a CI comprova
a fonte testada, sem afirmar atualização do Demo ou dos laboratórios.

Checks de whitespace, staged/segredos e `check_release.py` foram executados
antes de cada commit. Source-review remoto é uma verificação documental
distinta dos cinco jobs da CI integral. Logs/coletas não foram publicados;
somente resumo, links, contagens e limites revisados. A run antiga permanece
com seu resultado original, e nenhuma evidência histórica foi reescrita.
Escopo #10 encerrado após o aceite dos três filhos; nenhuma próxima feature
ou operação de laboratório é autorizada por este checkpoint.
