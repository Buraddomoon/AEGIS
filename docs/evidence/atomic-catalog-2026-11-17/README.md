# Catálogo Atomic offline — entrega #13

Implementação das #75/#76/#77 em17/11/2026, sem execução Atomic ou implantação.
**Estado no encerramento inicial:** aceite funcional demonstrado; pai mantido
aberto pela CI/auditoria.

**Fechamento posterior:** o usuário solicitou fechar a #13, com as três subissues
concluídas. A CI44144791638 terminou com falha: Python0/1/3 passaram; Python2 e
React falharam. O fechamento preserva o histórico e essas limitações, sem declarar
workflow verde nem autorizar execução Atomic, laboratório ou implantação.
Python2 registrou7falhas em `tests/test_wazuh_cycle_catalog.py`, com erro
`wazuh_catalog_explicit_b7_upgrade_required` (911passaram/1skip nessa partição).
Essas falhas foram registradas no fechamento; não foram corrigidas nesta ação.

## Fonte e comportamento

- `f1564e9`: versões imutáveis por commit/técnica/hash, GUIDs preservados,
  parser bounded, comandos/defaults removidos da projeção; Refs#75.
- `043992f`: importação/consulta/revisão autenticadas, RBAC/CSRF, paginação/filtros,
  auditoria, limites e revisões append-only com sequência esperada; Refs#76/#75.
- `22e8266`: fixtures do gate Linux usam o b7 real e restauram head; Refs#75.
- `13011b6`: biblioteca Atomic consultando API e fluxo Firefox; Refs#77.

Todos enviados a origin/main, sem branch/PR/tag/release. A migration explícita
`c8e4a6d21f90` acrescenta3tabelas ao b7:36incluindo Alembic. Upgrade populado
comparou todas as linhas legadas; nenhum `test_definition` é criado pela
importação. O gate operacional Linux permanece em b7 e recusa c8 sem revisão
específica. Demo/Labs originais continuam sem essa migração/implantação.

A fonte declarada é `redcanaryco/atomic-red-team`, commit
`3c62c9701d1009b991ad0224606c762fa02ba513`, arquivo
`atomics/T1059.004/T1059.004.yaml`,12923bytes, SHA256
`2a26f69f3fdcf6f3f2135d4405a184cfd365ed662c42f71fd4a1aa978b018021`.
[Fixture e licença](../../../fixtures/atomic/README.md) fixadas. Os17GUIDs/técnica
foram comparados aos bytes oficiais; nenhum comando foi executado. A aplicação
não faz download/verificação upstream: commit e hash são declarações do operador,
com autenticidade não verificada explícita na UI/API. Hash não é assinatura.

| Critério | Prova local |
| --- | --- |
| Parser hostil, limites antes da construção, duplicatas e comandos omitidos | `tests/test_atomic_catalog.py`, fixture oficial fixada |
| Idempotência concorrente, versões, constraints e upgrade populado | PostgreSQL real, schemas descartáveis; mesmo arquivo de teste |
| RBAC/CSRF/origem, erros sem echo, limites, Redis indisponível e auditoria | `tests/test_atomic_api.py` e `tests/test_security.py` |
| Revisão concorrente/stale, histórico imutável, grants SELECT/INSERT sem UPDATE/DELETE | PostgreSQL/API em `tests/test_atomic_api.py` |
| Importação não libera campanha; outra versão não herda revisão | API e Firefox; allowlist/execuções idênticas antes/depois |
| Filtros/paginação, roles, formulário, erro/refetch e texto sem HTML | `apps/web/src/atomic-catalog.test.tsx` |
| Procedência/requisitos/cleanup/elevação/risco e estado não executável na UI | Firefox real com API/worker/PG/Redis, desktop e390px |

## Comandos e resultados

Rodada local final, sequencial em Redis15 e schemas PG descartáveis:

```text
.venv/bin/pytest tests/test_atomic_catalog.py tests/test_atomic_api.py tests/test_integrations.py tests/test_security.py tests/test_linux_schema_compatibility.py tests/test_linux_campaign_preparation.py tests/test_migrations.py -q
83 passed, 1 warning in 32.72s
make lint
PASS (Ruff, format, mypy, TypeScript, Prettier)
npm --prefix apps/web test
98 passed / 16 files
make e2e
PASS / Firefox / 17 metadados importados / 1 revisão / 0 execuções Atomic
5 runs Demo / 20 testes sintéticos / 2 snapshots / 4 PDFs / 16 capturas / 0 erros JS
```

E2E usou schema/conta/API/worker próprios e Redis14; cleanup do driver concluído.
Capturas/logs ficam host-only em `.local/issue13`, sem substituir imagens
históricas versionadas. Revisão visual desktop/390px, sem overflow horizontal.
Hashes das duas capturas Atomic finais:

- Desktop: `3f092062262abe6164d9d741c89b0d59e37afe313d3143d87077f93abeb4e858`.
- Mobile: `78cb7a5a0269d80ea5b2ae29bdac732712bdb36e82f13fb2ed36513a1821aea9`.

Ruff/format, revisão staged/segredos, `git diff --cached --check`,
`check_staged.py` e `check_release.py` passaram antes de cada commit.
Credenciais já existentes foram selecionadas somente no ambiente de subprocessos;
nenhum .env/conta/grant de outro projeto foi alterado.

## Falhas observadas e bloqueio restante

- Whitespace upstream inicialmente recusado: fixture em envelope JSON conserva
  os bytes exatos, sem enfraquecer os checks nem alterar o hash do conteúdo.
- Alembic check histórico estava comparando b7 ao ORM novo: todas as verificações
  históricas foram preservadas; comparação ORM ocorre após restaurar head.
- CI parcial043 detectou a fixture de prontidão que reetiquetava head como b7:
  corrigida em22e8266 com downgrade real do schema descartável e restauração final;
  negativa adicional comprova que o gate continua recusando c8.83testes finais
  exercitam os arquivos juntos. Sem operação Linux/Wazuh.
- Preenchimento Puppeteer de textarea não atualizou o estado React na primeira
  tentativa. O E2E simula paste via setter nativo/eventos e verifica SHA256 no
  navegador. Uma tentativa intermediária usou método ausente da biblioteca;
  corrigida. Duas rodadas completas posteriores passaram; não somar como casos novos.
- Aviso upstream Starlette/httpx permanece visível.
- A auditoria npm local e da CI acusa6pacotes high na cadeia de `picomatch`,
  [GHSA-fc5q-39xc-vjpf](https://github.com/advisories/GHSA-fc5q-39xc-vjpf),
  revisado em17/11 e sem versão corrigida anunciada na consulta. O lockfile é
  idêntico à base9c44631. Nenhum audit fix forçado, override, exclusão ou
  relaxamento de threshold foi aplicado. Esse bloqueio externo impede declarar
  CI integral verde e motivou manter a #13 aberta no encerramento inicial.
  O pedido posterior de fechamento está registrado no início deste relatório.

As contagens locais não substituem as quatro partições Python e React da CI.
IDs/estados finais da CI e hash documental constam no comentário da #13.
Nenhuma capacidade de execução, laboratório, volume, PKI, journal, fence ou
histórico foi reutilizado/alterado para produzir esta evidência. Encerrar aqui;
outra entrega ou implantação depende de escolha/autorização específica.
