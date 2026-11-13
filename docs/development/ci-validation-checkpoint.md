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

## Próximas unidades

Na #68, fixar a fonte após este registro documental e executar `ci.yml` uma vez
por `workflow_dispatch`. Conferir quatro jobs Python, React, contagens/skips,
lint/tipos/build/auditorias e união das coletas sem overlap/omissões.
Na #69, publicar o resultado real e a diferença entre fonte testada e implantada.
Não existe mudança de fluxo de produto nesta entrega; E2E novo só será necessário
se uma correção alterar esse fluxo. Nenhuma implantação ou execução de Lab é
parte desta validação.
