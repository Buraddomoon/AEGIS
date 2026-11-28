# Recuperação operacional — checkpoint #29

Atualização após a retomada dos testes: [CI integral46112721312](https://github.com/Buraddomoon/AEGIS/actions/runs/46112721312)
**SUCCESS**, fonte `287ed69`, 4.304Python/9skips existentes e186React. Conjunto de
recuperação235casos aprovado em Linux. Relato cronológico, primeira falha e
correção abaixo; #29/#119/#120/#121 continuam abertas pelas pendências
operacionais, sem transporte/cutover ou aceite entre hosts.

Sessão de 28/11/2026, limitada a #29/#119/#120/#121. Base
`e7fe3e08cc05cd6390f30f29efedaf6a73caa535`, `main`, árvore limpa;
`git ls-remote origin refs/heads/main` conferido no mesmo hash.
Última mensagem da base: `docs(scheduling): record native proof and integrated acceptance (Refs #104, #23)`.

## Entregue e pendente

Preparação documental em
[procedimento operacional](../operations/operational-demo-recovery.md): matriz
do conjunto recuperável, compatibilidade imagem/schema, plano de retenção/export
de imagens, roles/ACL/configuração, gates existentes da quarentena/reconciliação
e campos do pacote para decisão. Nenhum código/teste/workflow alterado.

- **#119 aberta:** definição preparada; inventário concreto das imagens/segredos
  permanece privado e ainda não foi coletado para este ensaio. Exportação,
  transporte e boot isolado com papéis mínimos não executados. Não há conjunto
  completo certificado por esta sessão.
- **#120 aberta, depende da #119:** fluxo descartável existente inspecionado,
  sem reimplementação. Validação completa e transição operacional persistente
  não demonstradas. Não iniciar worker ou reaproveitar autorização antiga.
- **#121 aberta, depende da #120:** destino/recursos não escolhidos nem aprovados;
  sem autorização específica de transporte, interrupção de origem ou cutover.
- **#29 aberta:** sem aceite conjunto, recuperação entre hosts ou RPO/RTO medidos.

Consulta REST GitHub: pai e três filhos abertos/zero comentários prévios;
filhos nativos confirmados. Bloqueadores nativos do pai #11/#28 fechados; listas
nativas dos filhos vazias, sem remover a ordem técnica escrita #119→#120→#121.
Aceites finais e checkpoints das dependências lidos: #11 limita-se a recuperação
offline e #28 à custódia manual/restore nativo local; não autorizam nova operação.
Conector indisponível (`USER_NOT_LOGGED_IN`), consultas por REST. Visibilidade
pública observada, divergente de AGENTS.md; não alterada, nenhum dado privado
incluído nesta documentação.

## Provas locais e falhas

Lidos AGENTS.md, session-workflow, issues/dependências/comentários, as três
referências indicadas e contratos/testes/guia/Makefile pertinentes. PROGRESS e
chat antigo não foram usados. Introspecção local sem conexão ao banco:
`required_revision()` → `f3b28c5d901a`; metadata + Alembic → 36 tabelas. Isso
descreve o checkout, não o Demo implantado. O backup aceito na #28 é b7/33/3.399
linhas; revisão de aplicação precisa coincidir, sem migração implícita.

Ambiente disponível: Windows/PowerShell, `.venv/Scripts/python.exe` 3.14.4.
`docker`/`psql` não encontrados no PATH; WSL não oferece shell Linux disponível.
`demo_backup.py` exige POSIX (`getuid`, ownership/permissões, socket Unix local).
Não instalar infraestrutura ou adaptar/remover guardas para fazer passar.

Primeira tentativa com `.venv/Scripts/python.exe -m pytest` não coletou testes:
`ModuleNotFoundError: aegis`, instalação editável deste venv não resolve o pacote
do checkout atual. Repetição com `PYTHONPATH` apontando para `apps/api` somente
no processo, sem mudar o venv/configuração persistente:

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) 'apps/api')
.venv/Scripts/python.exe -m pytest tests/test_recovery_cycle_runtime.py tests/test_recovery_probe.py -q --tb=short
```

**19 failed, 11 passed, 4 errors, 1 warning, 3.14s.** Os 19 casos de filhos/falhas
parametrizados pararam na asserção de arquivo0600 (Windows informa0666); quatro
fixtures de recibo falharam em `os.getuid` ausente. Docker é driver simulado
nessa suíte; nenhum container foi iniciado. Não se verificaram os caminhos de
cleanup/rollback que esses casos deveriam exercitar. As guardas e asserções
permanecem intactas; falhas não ocultadas por skips ou exclusões da suíte/CI.

Validação complementar dos contratos de recusa antecipada, explicitamente
distinta da suíte de orquestração que falhou:

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) 'apps/api')
.venv/Scripts/python.exe -m pytest tests/test_recovery_guards.py tests/test_recovery_probe.py -q --tb=short
```

**19 passed, 1 warning, 0.30s.** Entry points worker/scheduler/CLI/migration e
aplicação de catálogo recusados antes de DB/threads; modo/token e destino da
probe revisados. Casos usam fixtures de contrato sem DB/Docker; não são boot ou
ensaio nativo. Há sobreposição com a tentativa anterior; não somar contagens.
Aviso existente de depreciação Starlette/httpx em ambas as rodadas.

Nenhuma suíte PG/Redis, CI integral, restore, build, exportação de imagens,
acesso a backup/chave operacional, implantação ou alteração da fonte foi
executada. Sem instalação, compra, upload, conta nova, Lab/Linux/Wazuh/SIEM,
abertura/migração de volumes originais, rede qasrc ou cutover.

## Encerramento e retomada

Registrar revisão staged/segredos, whitespace, checks staged/release, commit,
mensagem e sincronização nos comentários de #119/#120/#121/#29. Manter todos
abertos. Retomar somente esta entrega com ambiente POSIX/Docker compatível e
conjunto/destino concreto, respeitando ordem e gates. O pacote específico será
revisado antes de solicitar aprovação dos efeitos; esta preparação não o aprova.
Parar após o registro, sem avançar para outra feature.

## Retomada dos testes em ambiente compatível — 28/11/2026

Após o pedido explícito do responsável, “pode realizar os testes”, foi disparado
o workflow existente `ci.yml`, por `workflow_dispatch` em main, em 28/11/2026
05:19:27 UTC. Fonte fixada e conferida antes do dispatch:
`1de0ba7bf2bf7669cda23e3b1fd15053ce9a3eb2`.
[Execução 46111578459](https://github.com/Buraddomoon/AEGIS/actions/runs/46111578459).

Ubuntu24.04/Python3.13, PostgreSQL17 e Redis8 novos por job, quatro partições
Python complementares, max-parallel2/timeout18min e React. Workflow, seleção,
testes, limites e dependências não alterados. Não foi adicionado skip para
contornar as falhas Windows. Serviços de testes são descartáveis na VM de CI;
nenhum backup, chave, `.env` ou volume humano foi enviado à execução.

Primeira execução **FAILURE**, cinco jobs encerrados e logs conferidos:

| Job | Resultado da primeira execução |
| --- | --- |
| Python 0 | 1.016 passed, 2 skipped, 1 warning, 136,64s |
| Python 1 | 1 failed, 1.095 passed, 2 skipped, 1 warning, 379,89s |
| Python 2 | 1.081 passed, 1 skipped, 1 warning, 265,36s |
| Python 3 | 1.111 passed, 4 skipped, 1 warning, 326,37s |
| React | 186 passed/24 arquivos, 21 testes glob, lint/formato/build/audit aprovados |

Total Python **4.303 passed, 1 failed, 9 skipped**; não é workflow verde. Os
235 casos de recuperação pertencem às partições0/2/3, todas aprovadas; nenhum
skip delas pertence aos nove arquivos do target. As falhas Windows da sessão
anterior não se repetiram nesses testes em Linux. A API em quarentena/papéis
mínimos e o ciclo API/worker usam PostgreSQL/Redis reais descartáveis; Docker
da orquestração e suas falhas continuam simulados. Não houve restore/boot de
imagem operacional ou transporte de backup humano.

Falha única em
`tests/test_sigma_validation.py::test_private_scope_expiry_drift_and_recovery_fail_closed`:
`NOW` é calculado na importação durante a coleta e a aprovação da fixture vale
cinco minutos. O teste rodou após esse prazo e `load_scope()` recusou corretamente
a autorização expirada. Não foi identificada falha da guarda da aplicação.

Correção mínima de teste em `287ed692042967195b30358798312b6bbfbfcae1`,
`test(recovery): make private scope expiry deterministic (Refs #120, Refs #29)`:
relógio controlado só nesse caso, aprovado no instante do teste, expiração
exatamente no limite exclusivo com documento ainda válido. Após o caso de
symlink, arquivo/permissões/prazo válidos são restaurados e aceitos antes da
recusa em recovery; assim a asserção de quarentena não é satisfeita por outro
erro de arquivo/prazo. `load_scope`, validação de escopo e guardas POSIX não
foram substituídos; nenhum código de aplicação ou validade operacional mudou.
Ruff check/formato desse arquivo, staged/segredos/whitespace e release-check
aprovados antes do commit, push direto concluído. Nova CI integral disparada
pelo push, com as mesmas quatro partições/limites e React. Logs consultados por
API autenticada, sem publicar credencial, log bruto ou artefato operacional.

Coleta complementar local, com `PYTHONPATH=apps/api` somente no processo:
`.venv/Scripts/python.exe -m pytest` com os nove arquivos do target
`make test-recovery`, `--collect-only -q` → **235 testes coletados em1,88s**,
exit0/um aviso existente Starlette/httpx. Coleta não é execução. A função
inalterada de `scripts/run_ci_tests.py` atribui os arquivos assim:

| Partição | Arquivos do conjunto de recuperação |
| --- | --- |
| 0 | `test_backup_cli.py`, `test_recovery_guards.py`, `test_recovery_api.py` |
| 1 | Nenhum dos nove arquivos; contém os demais contratos da suíte integral |
| 2 | `test_backup_vault.py`, `test_recovered_demo_cycle.py`, `test_recovery_cycle_runtime.py` |
| 3 | `test_backup_inventory.py`, `test_recovery_probe.py`, `test_recovery_reconciliation.py` |

Os resultados Windows anteriores permanecem históricos e válidos para aquele
ambiente. O pedido atual autoriza os testes; não escolhe um destino operacional
nem aprova novo transporte de backup/imagens, interrupção de origem ou cutover.
As pendências concretas de #119/#120/#121 e o pai continuam abertas até suas
próprias provas e gates. Nenhum ensaio entre hosts/RPO/RTO decorre da CI.

### Resultado final da validação compatível

[CI46112721312](https://github.com/Buraddomoon/AEGIS/actions/runs/46112721312)
**SUCCESS**, fonte `287ed692042967195b30358798312b6bbfbfcae1`, evento push,
attempt1, 05:34:29–05:44:59 UTC em28/11. Quatro jobs Python e React encerrados
com sucesso; todos os passos esperados completos e logs de resultados lidos.

| Job | Resultado final | Job ID |
| --- | --- | --- |
| Python 0 | 1.016 passed, 2 skipped, 1 warning, 148,53s | 140879624099 |
| Python 1 | 1.096 passed, 2 skipped, 1 warning, 264,56s | 140879624315 |
| Python 2 | 1.081 passed, 1 skipped, 1 warning, 256,77s | 140879624211 |
| Python 3 | 1.111 passed, 4 skipped, 1 warning, 267,97s | 140879624278 |
| React | 186 passed/24 arquivos; 21 testes glob; lint/formato/build/audit aprovados | 140879624331 |

Total **4.304Python passed/9skips existentes**, partições complementares,
4.313casos totais; não somar os deselected entre partições ou rodadas. Os235
casos do target de recuperação foram exercitados nas partições0/2/3, sem skip
nesse conjunto. Casos reais em PG/Redis descartáveis cobrem permissões, bloqueio
de sessões antigas/token independente, reconciliação/fences, rollback por falha
tardia, plano obsoleto/lock concorrente, dispatch ambíguo recusado, conta nova,
ciclo API/worker sintético e relatórios/histórico preservados. Os23casos de
orquestração que falharam/deram erro no Windows passaram no Linux com o driver
Docker simulado existente, sem remover as asserções de permissões/cleanup.

Nove skips opcionais mantidos: projeção de metadata de imagem(1), API Demo
existente ausente(1), ferramentas PostgreSQL locais opcionais ausentes(1),
inspeção do DB Demo existente ausente(1), rede Demo existente ausente(1) e
objetos próprios de inspeção Wazuh ausentes(4). Não criar esses recursos para
eliminar skips. Aviso upstream Starlette/httpx existente por partição.
Ruff/formato/mypy aprovados. Auditoria Python: um finding diskcache5.6.3
PYSEC-2026-2447 explicitamente revisado como caminho do parser não afetado;
não é alegação de zero findings. npm audit: zero vulnerabilidades.

**Implementado nesta retomada:** correção determinística de uma fixture de
recovery e registro de provas. **Testado:** fonte atual nas suítes integrais,
contratos e integração com dados/papéis descartáveis. **Implantado:** nada.
O ambiente de testes compatível foi obtido pela CI, sem instalar Docker/WSL ou
stack no Windows. Inventário/exportação/transporte das imagens concretas e boot
de imagem compatível com o backup humano continuam pendentes na #119; o aceite
operacional da #120 depende disso. A #121 continua sem destino/recursos/cutover
aprovados. Nenhum backup/segredo operacional foi acessado ou transportado,
nenhuma fonte/volume original alterado e nenhum Lab/SIEM iniciado.

Commit final documental, checks staged/release, push e sincronização devem
constar nos comentários das quatro issues. A primeira CI vermelha e as falhas
Windows permanecem registradas; nenhuma foi substituída por alegação de sucesso.
Encerrar os testes pedidos e parar nesta entrega, mantendo pai/filhos abertos.
