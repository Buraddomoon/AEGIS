# Checkpoint da issue4 — 11/11/2026

Escopo: #4 e seus quatro filhos nativos, sem descendentes adicionais. Dependência
nativa #3 confirmada fechada. Somente main, commits pequenos e push direto.
Trabalho em `/home/IVPTER/AEGIS`; os cinco arquivos locais da outra cópia
`/home/IVPTER/codes/aegis` foram preservados e não entraram nos commits.

## Entregue e pendente

| Issue | Estado desta sessão |
|---|---|
| #48 | Preparação/testes entregues; aberta, falta backup/restore/upgrade em clone do original |
| #49 | Núcleo e executor nativo implementados/testados; fechamento técnico após revisão/CI do complemento; execução depende de #48/#51 |
| #50 | Implementação API/UI concluída e fechada com evidência de testes; sem binding/preflight original implantado |
| #51 | Procedimento/casos de falha preparados; aberta, falta ensaio nativo autorizado |
| #4 | Aberta, aguardando gates anteriores e aceite conjunto |

O plano de metadados anterior continua executor_implemented=false; o executor
nativo tem CLI/pacote próprios, sem ampliar autorizações antigas. Seu código
verifica mounts, isolamento e ownership; testes com daemon simulado não comprovam
ensaio real. O núcleo interno anterior continua sem prova de runtime nativo.

## Commits sincronizados

- `df5f5ef`: `test(linux): rehearse a0 to b7 upgrade and isolated restore (Refs #48)`.
- `9f31e48`: `feat(runner): join persisted and journal continuity reviews (Refs #49)`.
- `c99e14d`: `feat(linux): retain revoked bindings and show current trust (Refs #50)`.
- `8399ad3`: `feat(runner): coordinate one-use rotation review and revoked binding (Refs #49, Refs #51)`.
- `19c9eec`: `test(linux): preserve populated receipts and approvals through restore (Refs #48)`.

Na primeira etapa, a fonte executável era8399ad3;19c9eec reforçou os documentos de
teste de schema. O complemento nativo inclui295b8b8 e a consolidação seguinte.
Até este checkpoint, nenhum build/deploy de imagem do Lab ou Demo foi feito; build frontend
foi somente validação local. Imagens históricas, PKI, volumes, journals, candidatos
e fences preservados. Nenhum Linux/Wazuh/marker real iniciado ou qasrc alterada.

## Verificações reais

Todas as suítes PostgreSQL/Redis15 foram sequenciais, com configuração de
desenvolvimento existente fornecida ao processo. O `.env` desta cópia tinha
credencial desatualizada; o primeiro teste falhou em autenticação antes de criar
schema. Não houve reset/rotação de senha nem alteração do arquivo para contornar.

- `pytest tests/test_linux_schema_compatibility.py -q`: **3passed/4,10s**, última
  rodada, dump/restore PG17 executado, sem skip. Schema aleatório/populado com
  scopes, aprovação usada, recibo e cleanup; comparação de todas as linhas e
  ACLs antigas, migração aditiva e grants em papel NOLOGIN descartável.
- `pytest tests/test_runner_rotation_coordinator.py tests/test_runner_activation_review.py tests/test_linux_binding_rotation.py tests/test_linux_schema_compatibility.py tests/test_runner_diagnostic_gates.py tests/test_runner_diagnostic_coordinator.py -q`:
  **70passed/65,31s**. A rodada de schema acima reforçou depois a fixture de
  receipts/approvals; não somar os casos repetidos.
- `pytest tests/test_linux_binding_rotation.py tests/test_binding_review.py tests/test_linux_campaigns.py -q`:
  **72passed/72,43s**. Sobrepõe os seis casos de binding do grupo anterior.
- `pytest tests/test_runner_pki_generation.py tests/test_runner_pki.py tests/test_runner_pki_tls.py tests/test_runner_journal_continuity.py tests/test_runner_persisted_review.py tests/test_runner_journal_probe.py tests/test_runner_persisted_probe.py -q`:
  **229passed/23,55s**, incluindo TLS de loopback e continuidade em temporários.
- React: suíte completa **91passed/15arquivos**; tipos/build/format aprovados.
  Rodada dirigida de21casos é subconjunto, não contagem adicional.
- Ruff lint/format globais, mypy, diff e scripts check_staged/check_release
  aprovados. Aviso upstream Starlette/TestClient-httpx continua visível.

CI de c99e14d: [43089994373](https://github.com/Buraddomoon/AEGIS/actions/runs/43089994373)
SUCCESS, quatro Python e React conferidos:3.107Python passaram/9opcionais pulados,
91React. A revisão de fonte43089994371 também passou. Isso não cobre sozinho o
núcleo posterior. CI final exata de19c9eec:
[43091653314](https://github.com/Buraddomoon/AEGIS/actions/runs/43091653314)
**SUCCESS**, quatro Python e React conferidos: **3.120Python passaram/9opcionais
pulados,91React**. Inclui todos os casos novos, sem filtro/exclusão adicional.
O dump/restore da fixture foi efetivo localmente; na CI, sem o container de
desenvolvimento, esse caso é um dos skips explícitos. As execuções intermediárias
canceladas não são workflow verde. O handoff seguinte altera somente Markdown.

## Retomar pelo bloqueio concreto

Ler [ACTIVATION-ASSAY](../../labs/linux/ACTIVATION-ASSAY.md), seção “somente clone
da #48”, e [compatibilidade](../operations/linux-schema-compatibility.md).
É necessária aprovação específica para ler/copiar a frio o PostgreSQL original
em mount read-only, iniciar PostgreSQL somente nos clones e testar restore/upgrade
ali. A issue genérica não autoriza essa intervenção; os originais não foram
abertos nesta sessão. Não iniciar a rotação real antes dessa evidência e da
pacote nativo revisado. O diário original nem entra nessa primeira proposta.

O complemento da #49 está em `scripts/runner_rotation.py` (prepare/run/cleanup),
`runner_rotation_native.py` (lifecycle concreto), `runner_rotation_package.py`
(pins, evidência de clone e confirmação), `runner_rotation_runtime.py` (receitas e
inspeção projetada) e `aegis.lab_runner.rotation_probe` (cinco fases fechadas).
Os testes usam revisores SQL/SQLite reais em temporários e Docker/TLS simulados;
o controle de trust anterior distingue issuer/path de expiração/EOF. Ver
[operação nativa](../operations/runner-native-rotation.md). Não afirmar execução
nativa a partir de resultados de fixtures ou da disponibilidade da CLI.

Comentários por unidade preservam evidências e limites:
[#48](https://github.com/Buraddomoon/AEGIS/issues/48#issuecomment-6805894478),
[#49](https://github.com/Buraddomoon/AEGIS/issues/49#issuecomment-6805895280),
[#50](https://github.com/Buraddomoon/AEGIS/issues/50#issuecomment-6805896079),
[#51](https://github.com/Buraddomoon/AEGIS/issues/51#issuecomment-6805896568).
Não avançar para outra entrega. Não fechar o pai com gates/filhos pendentes.
