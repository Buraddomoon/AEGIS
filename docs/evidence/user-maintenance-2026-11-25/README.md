# Manutenção de contas — #24, 25/11/2026

**Implementação/validação locais; sincronização bloqueada.** #24 e #105/#106/#107
permanecem abertas. A fonte local não foi publicada nem combinada com o avanço
concorrente do remoto; não há CI desta fonte nem implantação. O
[checkpoint](../../development/user-maintenance-checkpoint.md) permite retomar sem
chat ou leitura integral do PROGRESS.

## Comportamento e aceite técnico local

- #105: papel/situação, senha própria com senha atual, redefinição administrativa
  de outra conta, consulta e revogação de todas as sessões. Lock transacional
  serializa login/criação/manutenção e relê ator/sessão depois da espera.
  Concorrência preserva o último administrador ativo. Argon2id, CSRF, RBAC,
  limites Redis e auditoria sem senhas/hashes/tokens expostos.
- #106: controles pessoais para todos e administrativos apenas para admin;
  confirmação, estado ocupado, erros reais, senhas apagadas após tentativa ou
  fechamento e ausência delas no cache. HTTP401 descarta identidade/consultas;
  mudança própria ou encerramento próprio volta ao login. API real no Firefox.
- #107: solicitante e aprovador distintos revalidados antes do start e na fila;
  revogação durante execução/cleanup não elimina a limpeza. Aprovação, escopo e
  resultado anterior mantêm conteúdo/identidade. Nenhum histórico é reescrito.

Arquivos de implementação: `apps/api/aegis/identities.py`, `api.py`, `schemas.py`,
`linux_labs.py`, `services.py`, `worker.py`; `apps/web/src/AccountSettings.tsx`,
`Management.tsx`, `App.tsx`, `lib.tsx`, `style.css`. Contratos e limites em
[autorização](../../security/authorization.md). Não há migração nova de schema.

## Verificações executadas

PostgreSQL real em schemas descartáveis e Redis15, sempre em sequência; credenciais
dos serviços já ativos selecionadas apenas no ambiente do processo. A configuração
local antiga falhou na autenticação PG; nenhuma conta/grant ou `.env` foi alterada.

```sh
.venv/bin/pytest tests/test_user_maintenance.py tests/test_security.py tests/test_cleanup.py tests/test_scheduling.py tests/test_linux_campaigns.py -q --tb=short
.venv/bin/pytest tests/test_user_maintenance.py::test_waiting_actor_cannot_use_revoked_admin_dependency tests/test_user_authorization_lifecycle.py -q --tb=short
.venv/bin/pytest tests/test_flow.py tests/test_transactions.py tests/test_wazuh_campaigns.py tests/test_scheduled_reports.py -q --tb=short
npm --prefix apps/web test
make lint
make build
node --check apps/web/accounts-e2e.mjs
.venv/bin/python scripts/user_maintenance_e2e.py
```

- Primeiro grupo: **124passed**, antes da adição do caso da dependência obsoleta.
  Segundo grupo: **6passed** (esse caso novo e cinco casos de ciclo de autorização).
  Não somar os nove testes de autenticação da rodada inicial, já incluídos.
- Grupo complementar: **36passed**, código de saída0 confirmado em rodada isolada; união dos três
  grupos: **166casos Python distintos**.
- React: **161passed/22arquivos**, mais **21glob** separados. Lint (ruff,
  formatação, mypy, TypeScript e Prettier), build e sintaxe do roteiro passaram.
- Checks obrigatórios de staged/segredos/whitespace e `check_release.py` passaram
  antes de cada commit. Não são prova de CI, implantação ou ensaio nativo.
- Há aviso existente de depreciação Starlette/httpx no transporte TestClient.

Os casos verificam sessões antigas após reativação, senha com espaços, CSRF,
expiração, limites, RBAC, corrida entre dois admins, login concorrente à troca de
senha e ator lido antes do lock. Os contratos Linux/Wazuh são **fixtures**, sem
iniciar servidores nativos ou transformar recibo em evento defensivo.

## Firefox e custódia das provas

Resultado final: **VERIFIED**, pacote privado `acceptance-kcnep4_i`, `synthetic=true`,
`deployed=false`, três capturas, zero erros JS; schema/processo/limites próprios
removidos. As sete tentativas registradas tiveram seus schemas removidos,
conferidos por consulta ao catálogo PG (zero remanescentes).
Três contas próprias em schema novo, API própria em18788, sem worker/contêiner/Lab.
Firefox não intercepta nem substitui respostas. Preserva proteção do último admin,
viewer/operator, senha administrativa/própria, papel, desativação/reativação e
revogação. Capturas de viewport1440×1000 e390×1000 aguardam a geometria final da
barra lateral; botões são rolados até posição visível e recebem clique real após
checagem de obstrução. Corpo sem overflow e zero erros JavaScript.

Resumos, logs e capturas permanecem privados em `.local/issue24/` e
`.local/user-maintenance/acceptance-*`; nenhum log, screenshot gerado ou credencial
foi adicionado ao Git. Inventário SHA256 final (identificação de bytes):

| Artefato privado | SHA256 |
|---|---|
| `.local/user-maintenance/acceptance-kcnep4_i/summary.json` | `db3a2897d15950b150bfbd9232acb37ec208944964f403dd4e7640962f09c9da` |
| `.local/user-maintenance/acceptance-kcnep4_i/browser-summary.json` | `a257e6a6eef66f9b4f11a8998a2dcdd5346ee9a55d71f1d636be507b04c55f60` |
| `.local/user-maintenance/acceptance-kcnep4_i/last-admin.png` | `29264725fb4ad3b333ace8fc5e2598ef9cf272fa80bd15fe8907ca5bb649de59` |
| `.local/user-maintenance/acceptance-kcnep4_i/accounts-desktop.png` | `f379967fa6623944ca1972fed275b0432946843bfa6841b0f3be67d0f9213c82` |
| `.local/user-maintenance/acceptance-kcnep4_i/accounts-mobile.png` | `c03ac4c4818cdb0ef0961184dd77911b4a86ffc4debc99d1a1a0e7d849f96edf` |
| `.local/issue24/api-tests-2.log` | `3f98e2d9ede19bffeaaeab8b2f313f55add1d3ada46c4feae17ceebf842f8b77` |
| `.local/issue24/lifecycle-tests.log` | `38efa00b833a56082b2aeb3e8e958e5275e88d655e979db0f954df3c06e69359` |
| `.local/issue24/regressions-2.log` | `f70b131ac8f099effe51fd087858b99383be97a5f481382d887088b91a69fce4` |
| `.local/issue24/regressions-exit.json` | `e7f3ae2410a7c5aa8433a23ce46c256bf6779aa4907802d702c5dd61e6feb69e` |
| `.local/issue24/web-tests-layout.log` | `24fa194fc84d60762865f405d4cc486ad01a9ec569ec259ad688761668c9d642` |
| `.local/issue24/lint-layout.log` | `c937f345dbe3e0e0cec8e91b821c7a1b0893e32d154f99beb0da4bca5bcbe504` |
| `.local/issue24/build-layout.log` | `bb38b5cecd32b18a80a8ff6b7c0a7a25acf806ccc657546356ec0bc5906b9901` |
| `.local/issue24/cleanup-verification.json` | `bf7685027e294b3293bb7b4af2919c133c8b0efe25595cac870c92a8c6b585d4` |

## Falhas preservadas e correções

- Backend inicial: **3failed/121passed**. Corrigidos contador do teste de limite,
  nome da função `process_run` no teste e ordem da checagem para preservar a
  mensagem da autorização recorrente. Rodada seguinte124passed.
- React inicial: **5failed/156passed** pela ausência de `showModal` no jsdom;
  adotado o stub já usado pelo projeto. Lint apontou dois tipos de papel,
  corrigidos; rodadas completas seguintes161passed.
- Firefox `fx_4e4rt`: seletor de label incluía texto das opções do select.
  `ngor6a5i`: timeout de180s ao alternar páginas em background; API/schema/limites
  removidos, Firefox próprio PID168147 foi terminado explicitamente e sua saída
  confirmada. Roteiro passou a trazer páginas ao primeiro plano e fechar o browser
  sob deadline próprio. Nenhum processo de outro projeto foi terminado.
- `_93ea16l`: VERIFIED antes dos ajustes de apresentação; capturas fullPage
  representavam mal a barra lateral fixa. `m4mr5acc` e `9u0ynsfl`: botão encoberto
  por notificação após a nova altura do painel; nenhuma criação foi presumida.
  Espera por labels e clique em posição desobstruída corrigiram o roteiro.
- `r4xk_zf7`: VERIFIED com layout final; captura mobile ocorreu durante transição
  CSS. Acrescentada espera pela geometria final, sem eliminar verificações.
- Primeira rodada complementar reportou36passed, mas a sessão do comando terminou
  com143. Não foi tratada como verificação encerrada: repetição em sessão própria
  confirmou36passed e `command_exit_code:0`; ambos os logs foram preservados.

## Git, bloqueio e limites

Base local: `5f6f880`. Implementação API `c0a0aa8`, UI `e1efb92`, apresentação
`11c7601`. QA/roteiro final `e468e73780400e3509d6baec3f529741c3193ad4`
(`test(auth): verify revocation cleanup and isolated browser lifecycle`).

`git push origin main` após `c0a0aa8` foi rejeitado com `fetch first`.
Fetch de leitura confirmou `origin/main=5e4737a81d5ab3a11a443ff95beb81fc878422e3`,
dez commits após a base e sobreposição em API/Linux/schema/worker. O remoto foi
reconferido por `git ls-remote`. Conforme AGENTS, apenas sincronização foi
interrompida; sem merge, rebase, force push, branch, PR ou sobrescrita. Commits
posteriores são locais e não foram reapresentados ao remoto após esse bloqueio.

Nenhum deploy: API/worker Demo continuam na imagem
`b8abe5e44af4bad90d2e302a045f38fb9cf268932be5ea0493fc72f078657a23`, sem mounts de
fonte web; build local não substitui a aplicação ativa. Não foram alteradas contas
humanas, PKI, rede, volumes originais, grants ou autorizações de laboratório;
nenhum Linux/Wazuh foi iniciado ou marcador executado. A combinação da fonte nova
com o avanço remoto e sua validação/CI/publicação continuam pendentes. Parar no
escopo #24; não iniciar outra entrega.
