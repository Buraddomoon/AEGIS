# Recuperação operacional — checkpoint #29

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
