# Relatórios congelados e reconciliação — #71

## Snapshot real do Demo

O [recibo b7 real](b7-reconciliation.json) corresponde ao backup criado na #70:
33tabelas/3399linhas,23runs COMPLETED e **zero scheduled_reports**. A reconciliação
restaurou outro clone offline, removeu a sessão restaurada, desativou o usuário
ativo e revogou o laboratório autorizado. A auditoria nova e a sessão removida
se compensam na contagem final3399; não inferir preservação somente desse total.
Inventário original, SQL de preservação e comparações posteriores confirmaram
estrutura/histórico protegido. API SELECT em quarentena confirmou o ID/hash
exato e todos os fences atuais zerados. API/DB removidos antes do recibo.

Esse resultado demonstra fidelidade e encerramento do acesso do backup real;
nunca declara terem existido nele documentos READY/FAILED/PENDING.

## Ensaio não vazio, explicitamente sintético

O [resumo agregado](fixture-summary.json) e o
[recibo de reconciliação](fixture-reconciliation.json) usam **outra cópia**, criada
somente em um clone offline descartável do b7. Nenhuma fixture entrou no Demo.
O manifesto novo identifica `isolated_synthetic_fixture_not_active_Demo` e o
backup de origem, sem reescrever dump, manifesto ou dados originais.

A fábrica versionada [recovery_report_fixtures.py](../../../tests/recovery_report_fixtures.py)
criou um laboratório/ativo/usuário/campanha/plano/grant próprios, quatro runs e
suas ocorrências. Aprovações e sessão são dados fictícios, sem senha válida ou
login; não representam autorização operacional. Três runs estão CANCELLED e a
quarta QUEUED; nenhuma foi iniciada/executada. Os documentos iniciais e de
comparação foram construídos pelas funções reais de snapshot sobre esses dados,
sem resultado defensivo ou denominador válido. Comparação permanece não
comparável e delta ausente; nada foi alterado para fabricar detecção.

Estado antes do dump: **2READY** (BASELINE e COMPARISON), **1FAILED** por
GENERATION_FAILED e **1PENDING** com duas tentativas/erro/horário de retry. Também
havia reserva, fila, sessões, contas ativas, lab autorizado, agendamento ACTIVE e
grant não revogado. Helper de preparação encerrado antes do dump; nenhum escritor
concorrente. Inventário antes/depois do dump idêntico. Cópia derivada:
33tabelas/3463linhas; origem e helper removidos antes do ensaio de restauração.

O procedimento existente restaurou esse dump em **outro clone**, verificou o
inventário inteiro, aplicou a reconciliação e iniciou somente a API SELECT em
recovery. A probe recebeu uma leitura/renderização adicional dos documentos
salvos no mesmo container, sem rota normal, sessão, Redis, scheduler ou worker.
As guardas, testes de recusa, comparação final e cleanup existentes continuaram
obrigatórios; nenhum recibo foi criado antes da remoção dos recursos próprios.

Resultado:

- READY e FAILED originais: todas as colunas idênticas, incluindo documentos,
  hashes, origem, tentativas e timestamps.
- PENDING: somente state/error_code mudaram para FAILED/RECOVERY_RECONCILED;
  tentativas/next_attempt_at e identidade preservados, sem documento parcial.
- JSON canônico e HTML: hashes iguais antes/depois. Dois PDFs renderizados em
  cada fase, lidos por parser pypdf independente: texto idêntico, IDs e aviso
  DADOS SINTÉTICOS presentes. A comparação é de conteúdo; metadados/bytes PDF
  podem variar. Os hashes publicados não são assinatura.
- Zero sessões/usuários ativos/labs autorizados/reservas/runs ou filhos
  pendentes/agendamentos retomáveis/grants/relatórios pendentes; zero dispatches.
  Aprovações e ocorrências históricas não reescritas. API vinculada ao ID/hash
  atual, `normal_operation_permitted=false` e sem alegar cleanup externo.
- Helper, clone de origem, API e clone de restore removidos. Intenções, dumps,
  documentos e PDFs permanecem privados no host; só agregados foram publicados.

## Validação e limites

`tests/test_recovery_reconciliation.py`, `tests/test_scheduled_report_storage.py`
e `tests/test_scheduled_report_api.py`: **55passed**, um aviso Starlette/httpx.
Novos casos conferem linha inteira, READY/FAILED/PENDING, exports antes/depois,
fences, idempotência e recusa de reativação de todos os quatro pedidos finais.
A primeira preparação da fixture tentou incrementar várias tentativas numa
única atualização; a trigger recusou corretamente (5failed/37passed).
A fábrica foi corrigida para respeitar cada incremento; nenhuma guarda mudou.

Regressão final `make test-recovery`: **235passed**, um aviso upstream,80,48s.
Essa suíte se sobrepõe aos55casos anteriores; não somar como casos exclusivos.
`make lint` passou (Ruff, formato, mypy, TypeScript e Prettier). Não houve mudança
de aplicação/frontend e E2E não foi repetido. CI remota é registrada à parte no
aceite da entrega; esses resultados locais não são um workflow verde.

O ensaio Docker foi executado pelo harness privado `.local/issue11/native-fixture.py`
(SHA256 `f4d8eda58a1c5b94c75d679bebc840b72d12a990d926db0e9cf88100347680d7`),
reutilizando a fábrica de teste e `scripts/demo_backup.py`/`rehearse`. Imagem b7
fixada no mesmo ID compatível da #70; nenhum build ou nova implantação.
O teste de API continua separado: no clone em quarentena as rotas normais são
bloqueadas, e a renderização usou os exportadores diretamente, sem reativar login.

O ensaio não vazio é **fixture com dump/restore Docker reais**, não documento de
campanha operacional do Demo. Não comprova nova execução defensiva, ciclo normal,
cutover, failover, recuperação de roles/Redis/journals, custódia externa ou RPO/RTO.
Linux/Wazuh/qasrc/PKI/volumes/journals/fences preservados. O Demo em uso conserva
imagem/schema/dados e permanece ready.

[Preservação da fonte](source-preservation.json): inventário completo do public
ativo idêntico ao manifesto b7 após todos os ensaios/testes,33tabelas/3399linhas;
dump/manifesto a0 original e cópia privada com hashes iguais. API e worker ainda
no mesmo ID b8abe5e44af4, health ready database/redis=true e zero containers de
recovery remanescentes.
