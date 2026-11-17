# Retomada da validação da #13 —17/11/2026

A entrega inicial teve testes locais/E2E aprovados, mas a CI integral falhou.
O fechamento posterior por pedido do usuário preservou aquelas pendências.
O usuário então solicitou corrigi-las e deixar a entrega validada. A #13 foi
reaberta para essa retomada. Os registros anteriores não foram apagados.

## Correções e fontes

- `1d9686053564734a2001cd3aa557b7b206431417`: helper de adoção Wazuh com inventário
  fixado em b7/33tabelas, incluindo Alembic, sem depender das novas tabelas do
  ORM. Snapshot e locks usam esse inventário; schema c8 ou tabelas extras são
  recusados. Fixture realmente usa b7 em schema descartável e restaura head.
  Nenhuma ampliação de compatibilidade/autorização dos laboratórios originais.
- `166da8819e1547dc0f39c2b4ebd6c6438df1f241` e
  `0517d24df4f08736db4f0bd4daaa67ed4a589b5b`: correção real do parser picomatch
  usado no build, com dependência local privada/licenciada, origem/hashes fixados,
  resolução verificada de todos os consumidores e regressões de segurança.
  Base: release4.0.7mais PR237não mesclada, acrescida de correções de compatibilidade
  para aspas e separadores durante revisão local. Não é uma release oficial.
  [Revisão e manutenção](../../security/picomatch-2026-11-17.md),
  [proveniência e licença](../../../apps/web/vendor/picomatch/README.md).

A correção de glob não exclui advisory, não reduz severidade nem desativa npm
audit. O namespace do fork não é avaliado pelo banco de advisories upstream;
por isso audit0 é separado da prova efetiva do parser, de seus hashes e dos
testes dos consumidores. O finding Python preexistente DiskCache continua
explicitamente revisado, com regressão que proíbe seu uso no parser.

Dockerfile copia vendor antes de npm ci; um contexto limpo só com manifests,
vendor e scripts de teste passou em npm ci offline e nas21regressões. Não houve
build de imagem Docker nesta retomada; a imagem Node24alpine não estava local,
e nenhum pull/stack/implantação foi iniciado para obter essa prova.

## Verificações locais

| Verificação | Resultado observado |
| --- | --- |
| Reproduzir `tests/test_wazuh_cycle_catalog.py` antes da correção |7falhas por exigência b7 |
| Wazuh catalog + Atomic catalog + prontidão Linux após correção |47passaram/1aviso Starlette-httpx |
| Partição Python2 integral, sem mudar particionador/filtros |922passaram em208,75s, zero skips locais |
| Fonte picomatch original em subprocesso, `+(*a)` e40letras `a` seguidas de `!` | Ultrapassou1s; filho terminado por deadline |
| Mesmo caso com correção local |false,1,69ms na observação; não é promessa de desempenho |
| Testes de segurança do fork |21passaram: hashes/resolução, quantificadores, deadline2s e semântica |
| Comparação curta adicional com release original |11padrões×1555inputs=17105comparações, zero diferenças de matching |
| `npm --prefix apps/web test` |21testes Node de segurança +98React/16arquivos aprovados |
| `make lint` e build |aprovados |
| `make audit` |npm0; Python1finding conhecido/revisado, sem novos findings |
| E2E Firefox real/API/worker/PG/Redis próprios |PASS;17metadados/1revisão/0execuções Atomic, allowlist preservada |
| Regressão Demo no mesmo E2E |5runs/20testes sintéticos/2snapshots/4PDFs/16capturas/0errosJS |

O E2E usou Redis14/schema/conta próprios e terminou o cleanup. Imagens/logs
privados ficam em `.local/issue13/retake-screenshots` e arquivos da retomada.
Após o último ajuste de compatibilidade do parser, todos os arquivos do build
foram comparados por SHA256 e são byte a byte idênticos aos usados nesse E2E;
o backend não mudou após1d96860. Nenhum Atomic foi executado/instalado.

## CI integral da fonte final

Fonte: `0517d24df4f08736db4f0bd4daaa67ed4a589b5b`.
Execução: [44151198083](https://github.com/Buraddomoon/AEGIS/actions/runs/44151198083).
**SUCCESS: cinco jobs concluídos/aprovados e logs conferidos.**

| Job Python | Passaram | Skips | Duração pytest |
| --- | ---: | ---: | ---: |
|0|907|2|133,23s|
|1|831|2|301,13s|
|2|921|1|170,10s|
|3|866|4|195,86s|
|Total|3525|9|quatro grupos complementares|

Coleta independente local:3534casos;3525+9=3534, sem mudança no particionador,
limites18min/max-parallel2, filtros ou exclusões. Os9skips são os controles
opcionais existentes: uma projeção de imagem opt-in, API Demo ausente, ferramentas
PG locais ausentes, DB Demo ausente, rede Demo ausente e quatro inspeções Wazuh
sem objeto Demo próprio. Nenhum recurso foi criado para transformar skip em pass.
Os sete testes Wazuh que falhavam passaram na partição2.

React:98passaram/16arquivos; Node:21regressões de segurança passaram, incluindo
hashes/resolução e caso hostil com deadline. Lint/tipos/format/build e auditorias
aprovados. npm0; Python1finding DiskCache revisado, com teste de caminho não
afetado preservado. Source-review0517d24 também aprovado, execução44151197447.
Workflow verde refere-se à fonte0517d24; alterações posteriores deste checkpoint
são somente Markdown, sem mudança nos inputs executáveis.

Demo ativo e Labs originais b7 preservados; sem migração de originais, startup
Lab, marcador, rede/PKI/journal/fence alterados ou implantação. Todo teste SQL
usou schemas/bancos descartáveis. A fonte Atomic continua exigindo migration c8
explícita para qualquer implantação futura.
