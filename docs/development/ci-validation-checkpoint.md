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
ensaio Linux/Wazuh nem implantação. A publicação da distinção de implantação
e da equivalência dos inputs finais pertence à #69.
