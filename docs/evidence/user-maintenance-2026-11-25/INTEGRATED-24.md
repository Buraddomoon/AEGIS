# Integração e aceite da fonte publicada — #24

Registro da retomada autorizada em25/11/2026. **Entrega atendida, fonte integrada/publicada e CI integral aprovada**.
#105/#106/#107 e critérios conjuntos da #24 validados, sem pendência técnica
de sincronização. Encerrar somente esse escopo, sem iniciar outra entrega.
O [registro inicial](README.md) conserva provas e falhas da fase local anterior.

## Conciliação preservando os dois trabalhos

- Base comum `5f6f880157d5b160c02fa1db63177ff2f9ca2540`.
- Pai local `f174e33ea1e21c16a0fde7d4f5a91f0c2f4fa086`: cinco commits da #24.
- Pai remoto `5e4737a81d5ab3a11a443ff95beb81fc878422e3`: dez commits concorrentes.
- Merge `38f2fee8ddef409ed60b5503ca9b52694d5759b3`,
  `fix(auth): reconcile account maintenance with current main`, publicado em
  `origin/main` após revisão e testes. Sem rebase, force push, branch ou PR.
- Houve um conflito textual em `docs/development/testing.md`; ambas as seções
  foram preservadas. API, schemas, Linux e worker combinaram os dois deltas.
  Os22arquivos alterados apenas pelo remoto mantêm seus blobs exatos.
- A checagem comum de contas da #24 precede o aceite da aprovação; a verificação
  do grant recorrente/segregação do remoto também é mantida. Não foi habilitada
  a flag de implantação nem acionado o workflow de ensaio nativo.

## Regressão de integração

`tests/test_user_scheduling_revocation.py` acrescenta quatro casos: papel da conta
alterado pela API para solicitante/aprovador distintos, antes da emissão ou com
run na fila. A sessão antiga recebe401; a emissão invalida o agendamento ou o
worker rejeita a run, sem dispatch/efeito no runner. Grant, plan/hash e escopo
históricos são preservados e a reserva é liberada. Somente fixture/PKI temporária,
HTTP em memória e schema PostgreSQL descartável; não é operação Lab nativa.

Grupo focado, em sequência com as outras suítes PG/Redis15:

```sh
.venv/bin/pytest tests/test_user_maintenance.py tests/test_user_authorization_lifecycle.py tests/test_user_scheduling_revocation.py tests/test_linux_scheduling.py -q --tb=short
```

Resultado: **42passed**, incluindo quatro novos; não somar a rodada ampliada
abaixo, que inclui os mesmos casos. Lint completo, TypeScript/Prettier/build e
React **166passed/22arquivos**, mais **21glob**, aprovados sobre a fonte integrada.
Checks obrigatórios de staged/segredos/whitespace e release passaram antes do merge.

```sh
.venv/bin/pytest tests/test_user_maintenance.py tests/test_user_authorization_lifecycle.py tests/test_user_scheduling_revocation.py tests/test_security.py tests/test_cleanup.py tests/test_scheduling.py tests/test_linux_campaigns.py tests/test_wazuh_campaigns.py tests/test_flow.py tests/test_transactions.py tests/test_scheduled_reports.py tests/test_scheduled_report_api.py tests/test_linux_scheduling.py tests/test_linux_scheduling_policy.py tests/test_scheduling_native_preparation.py -q --tb=short
.venv/bin/python scripts/user_maintenance_e2e.py
```

**255passed**, código de saída0; avisos existentes Starlette/httpx. Firefox
`acceptance-b4berp8_` **VERIFIED**, synthetic=true/deployed=false, três contas e
três capturas1440/390px, zero erros JS/overflow. Captura mobile revisada após a
transição da navegação. API/schema/limites próprios encerrados; ausência do schema
conferida novamente no catálogo PG. API/worker Demo b8 anteriores preservados.
Nenhuma falha nova nesta retomada; falhas da fase local continuam no registro inicial.

## CI da fonte exata

Workflow [Validate AEGIS45677946104](https://github.com/Buraddomoon/AEGIS/actions/runs/45677946104),
fonte `38f2fee8ddef409ed60b5503ca9b52694d5759b3`.
**SUCCESS**, quatro partições Python e React conferidos. **4188passed/9skips**
opcionais existentes, **166React/22arquivos e21glob**. Coleta4197=
1010+1030+1061+1096; seleção complementar do runner preservada, sem omissão ou
nova exclusão para obter green.

| Partição | Passed | Skipped | Selecionados | Pytest(s) |
|---|---:|---:|---:|---:|
| 0 | 1008 | 2 | 1010 | 175.32 |
| 1 | 1028 | 2 | 1030 | 266.09 |
| 2 | 1060 | 1 | 1061 | 257.96 |
| 3 | 1092 | 4 | 1096 | 257.09 |

Lint/tipos, build e auditorias integrantes da workflow aprovados. Auditoria Python
conserva1finding distinto explicitamente revisado; npm0. Isso não declara ausência
de vulnerabilidades. Serviços de CI isolados; nenhum ensaio Lab ou workflow nativo.
Revisão de fonte [45677946198](https://github.com/Buraddomoon/AEGIS/actions/runs/45677946198)
SUCCESS no mesmo commit. Verificação local complementar é prova distinta dessa CI.

## Custódia e encerramento

Artefatos privados, sem logs/credenciais/capturas geradas no Git. SHA256 identifica
bytes, não assinatura. Saídas de cada comando e os dois códigos0 foram retidos.

| Artefato privado | SHA256 |
|---|---|
| `.local/issue24-integration/merge-review.json` | `035c71c772474e47efea1bafe275eb76f1e0b5a999176d27210c5027486ff8b1` |
| `.local/issue24-integration/quick-tests.log` | `b978434874ca7ac332dbb2adba293408a0c24bb0c113cbf44f46d81c16023efa` |
| `.local/issue24-integration/lint.log` | `13311599dd3f9e712017161300cea6d44a1dce5bb6720bae715296badd6b8b9c` |
| `.local/issue24-integration/web-tests.log` | `5034131d6e56864aa2b339c3310bd79d89abc6357af90353d1dd7b3b30a0620a` |
| `.local/issue24-integration/build.log` | `91dd19baa93c2002331926237b22f4085b80209a94cb720c2b49b4bbf217bb99` |
| `.local/issue24-integration/regressions.log` | `e9052416f0748fa0e00b37dfeaf9e85cac7e2bc43c2d752f70b6222a2f9c5345` |
| `.local/issue24-integration/regressions-exit.json` | `99edc9b7bcb9f34b952be721e1f42535419e6b5f06567d704244b597e8062028` |
| `.local/issue24-integration/browser.log` | `1ccbb1f49cd02dd6fbb8914e9b6c5c8c9534cfcfc25170a754dccd13b66694a8` |
| `.local/issue24-integration/browser-exit.json` | `ff08bf040a237790a19eb1b053236b2e2c6d479c60313d9f115f726765e49c87` |
| `.local/issue24-integration/cleanup.json` | `5437d4cbd850a68f8f824ebd057d3f6c61051e73d10eaa560a799fc03f74c0b0` |
| `.local/issue24-integration/source-inputs.json` | `8ebd9db92387e292961567ea5ae48336ff9994f7ea9f9a99e98e0a5b11580e18` |
| `.local/user-maintenance/acceptance-b4berp8_/summary.json` | `a4e2a8c6f8aa7ef28f0e56158fe0e0e3277d7e36cbef6a96a2b51aded89f92af` |
| `.local/user-maintenance/acceptance-b4berp8_/browser-summary.json` | `a257e6a6eef66f9b4f11a8998a2dcdd5346ee9a55d71f1d636be507b04c55f60` |
| `.local/user-maintenance/acceptance-b4berp8_/last-admin.png` | `6e631faf0aedb3ea5c014e385f6ed7b81289c7d14da455e41f5fc6bad1bc86cc` |
| `.local/user-maintenance/acceptance-b4berp8_/accounts-desktop.png` | `49acb467a241f3df00bbc1f0e056c0deca3b783d5c2180468817d9a1f60e8d25` |
| `.local/user-maintenance/acceptance-b4berp8_/accounts-mobile.png` | `260d8adfadc3173100ac4ce606fa1e91b66504408487e7f039a808514a44cc57` |
| `.local/issue24-integration/ci-run.json` | `c5f42692f27edfdfba2b76a6ea1c055271361ac5b997b4f0e5b6634967ca28a7` |
| `.local/issue24-integration/ci-summary.json` | `4b1dbd3abd3a1a5c2c069ea8a26970a5344ef67ea4acbb0e054fe5dffd254c4a` |
| `.local/issue24-integration/ci-python-0.log` | `ef7ec68faf27b5ac1355a4c0141fdf0e980ec336ca735aa61bfc22a6437da84c` |
| `.local/issue24-integration/ci-python-1.log` | `99307e05c0c74c759ff2f056080e392367ad28d79a1e3d2775e191e67b0885c6` |
| `.local/issue24-integration/ci-python-2.log` | `8d7818a2a7f0961d67640fe04d8c7dbb8628a734da78d00097a31a3ffd44e72d` |
| `.local/issue24-integration/ci-python-3.log` | `9b8312382bd0fdc484f85fedc5f40b17fa033beedc2bd78510ce9b9a692da0da` |
| `.local/issue24-integration/ci-react.log` | `ffba219fa80338344d911a1f8e77789e6f5282214b5bc6b3e9d40dd423382693` |

A atualização final após a CI é exclusivamente Markdown (checkpoint, nota
histórica, teste/aceite e AGENTS). Os569arquivos não Markdown da fonte testada são
idênticos, manifesto `3bd2e48fe57450a100ba3e178a89dab924d687c91076c8eeb4af42b6d9a3ba3c`.
O commit documental recebe revisão de fonte própria; não é apresentado como nova
execução integral de CI. Último hash/mensagem e sincronização registrados nos
comentários finais das issues após o push e sua conferência.

Nenhuma implantação, alteração de contas humanas, grants/volumes originais,
marcador, PKI, rede ou migração de originais. Demo API/worker permanecem b8, running,
sem mounts de fonte. O ensaio Firefox inicia somente API/schema próprios e faz
cleanup; contratos Linux/Wazuh continuam identificados como fixture. Autorizações
de uso único anteriores não foram reaproveitadas. Não houve bump/tag/release,
PR, branch, force push ou alteração de visibilidade. Parar após #24 e seus filhos.
