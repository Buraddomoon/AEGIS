# Recorrência Linux delimitada — provas da #23

Estado final em27/11/2026: #102/#103/#104 e aceite conjunto atendidos.
[Prova nativa verificada](VERIFIED-104.md), [aceite conjunto](ACCEPTANCE-23.md)
e [incidentes preservados](INCIDENTS-104.md). CI46090184659 SUCCESS na fonte4812780:
4304Python/9skips existentes,186React/21glob. Ensaio46090496469 SUCCESS:
duas ocorrências reais43bytes, mesmo grant, recibos/cleanup, dois snapshots e
encerramento confirmado. Orçamento/pacote consumidos; sem replay ou operação
contínua. Os registros abaixo preservam o estado histórico de24/11, inclusive
o bloqueio inicial e a proposta depois expirada; não são o estado atual.

## Registro histórico da implementação e preparação inicial

Implementação em `main`, restrita a #102/#103/#104. Base `5f6f880`; commits
`03d7dd3`, `656caec` e `d46850c`. Dependência #5 fechada, sem autorização reutilizável.

## Comportamento implementado

`LINUX_SCHEDULING_ENABLED` é falso por padrão. Um plano Linux só admite o
marcador benigno original, com confirmação real na criação e aprovação explícita
por outro administrador ativo. Snapshot/hash fixa lab, ativo, teste/versões,
catálogo, ambiente, PKI/binding e telemetria; plano separado fixa janela, cadência,
duração, orçamento e concorrência1. Slots descartados consomem orçamento.

Ocorrências revalidam identidades com locks compartilhados ordenados, grant
original e preflight vigente. Emissão/reserva/aprovação derivada/ocorrência/fila/
pedido de relatório são atômicos. O worker mantém dispatch antes de RPC,
lease/fences, supervisor e recuperação sem replay. Cleanup continua após revogação;
ambiguidade retém reserva e impede outra ocorrência no laboratório. Reaprovação
preserva calendário/consumo e não reativa grants antigos.

UI distingue modos, apresenta escopo/orçamento e impede revisão própria Linux.
Snapshots Linux preservam `synthetic=false`, política `scheduled-linux-report/1`
e resultados/evidências originais; Demo preserva sua política e hashes históricos.
Downloads JSON/HTML/PDF não emitem testes, não renovam grants e não dependem do
laboratório ativo. Recibo do runner não é alerta defensivo.

Arquivos: `scheduling.py`, `linux_labs.py`, `scheduled_reports.py`,
`scheduled_report_api.py`, configuração/schemas/API/worker, `Scheduling.tsx`,
`ScheduledReports.tsx` e testes específicos. Operação em
[scheduling.md](../../operations/scheduling.md) e
[scheduled-reports.md](../../operations/scheduled-reports.md).

## Verificações locais efetivamente executadas

Windows, Python3.14.4 e Node24.15.0. Usado `PYTHONPATH=apps/api` e
`.venv/Scripts/python.exe` como equivalentes locais dos caminhos POSIX documentados.

- `pytest tests/test_linux_scheduling_policy.py -q --tb=short`: **22 passaram**;
  aviso upstream Starlette/TestClient-httpx preservado.
- `ruff check apps/api scripts tests`, `ruff format --check apps/api scripts tests`
  e `python -m mypy`: aprovados.
- `npm --prefix apps/web test`: primeira rodada com158React aprovados.
  Após a última correção, `npm --prefix apps/web test -- --maxWorkers=1`:
  **159 React/21 arquivos** e **21 checks glob**, sem excluir testes.
  Componentes pertinentes também passaram isoladamente:12testes/2arquivos.
- `npm --prefix apps/web run build`, `run format:check` e
  `npm --prefix apps/web audit --audit-level=high`: aprovados, zero vulnerabilidades
  na auditoria executada.
- Antes dos commits: staged revisado, `git diff --cached --check`,
  `scripts/check_staged.py` e `scripts/check_release.py`: aprovados.

Falhas locais retidas neste registro: primeiro `npm test` não encontrou picomatch
no node_modules anterior; `npm ci` pelo lockfile restaurou188pacotes, sem alterar
lockfile/dependências. Primeiro build detectou variável de teste não usada;
correção de tipagem seguida por build/formatação/auditoria aprovados.
O novo teste de erro ao consultar laboratório inicialmente disputou seu timeout
com o retry de1s; o wrapper de teste passou a usar retryDelay0. Outra rodada
paralela teve13falhas/timeouts; com2workers restou um timeout no teste de cadastro
Linux fora da alteração. A rodada serial completa passou, sem alterar timeouts,
excluir testes ou modificar a CI.

PostgreSQL `localhost:18782` e Redis de testes não responderam às probes com
timeout; nenhuma conta, grant ou arquivo de configuração foi alterado para isso.
`pytest tests/test_linux_scheduling.py --collect-only -q` neste Windows falhou
na importação de `fcntl`, requisito Linux do runner; nenhum teste foi excluído ou
gate relaxado. Integração PostgreSQL e E2E dependem das execuções CI abaixo.

## CI e E2E

Fonte executável final: `d46850c93bf111beee7f08a3252e9b0fb12dc371`.

- [CI integral45502330997](https://github.com/Buraddomoon/AEGIS/actions/runs/45502330997):
  fonte656caec, **FAILURE**,4130aprovações/1falha/9skips existentes. Partições0/2/3
  e React passaram. Partição1 falhou somente em
  `test_sigma_validation.py::test_private_scope_expiry_drift_and_recovery_fail_closed`:
  `NOW` é fixado ao importar o módulo, validade de5min e partição levou374,45s;
  `load_scope` recusou validade. Teste/código Sigma não foram alterados nesta issue.
  Os41novos casos Python de política/origem e integração Linux foram exercitados
  nas partições0/3 aprovadas. Esse workflow não é apresentado como CI verde.
- [CI da fonte final45504635253](https://github.com/Buraddomoon/AEGIS/actions/runs/45504635253):
  **SUCCESS**, quatro partições Python e React conferidos. **4131Python/9skips
  opcionais existentes,159React/21arquivos e21checks glob**; lint/tipos/build e
  revisão de dependências aprovados. Contagens das partições:

  | Partição | Passaram | Skips | Tempo da suíte |
  | --- | ---: | ---: | ---: |
  | 0 | 1004 | 2 | 131,21s |
  | 1 | 1023 | 2 | 251,89s |
  | 2 | 1060 | 1 | 253,62s |
  | 3 | 1044 | 4 | 246,76s |

  A nova CI foi disparada pelo último ajuste de frontend; o teste Sigma passou
  sem alteração de seu código, sem filtro, exclusão, aumento de timeout ou mudança
  de particionamento. Falha anterior preservada acima.
- [E2E Demo45502359496](https://github.com/Buraddomoon/AEGIS/actions/runs/45502359496):
  **SUCCESS**, Firefox real/API/worker/PostgreSQL em schema descartável,
  **5runs/20testes sintéticos,2snapshots automáticos,5PDFs,0erros JS**. O fluxo
  registrou aprovação de agenda, duas runs automáticas, baseline/comparação
  congelados, PDF automático e preservação do snapshot após mudança de regras.
  O harness completo existente também verificou suas regressões; nenhuma nova
  funcionalidade de outra issue foi implementada.
- [E2E da fonte final45504677648](https://github.com/Buraddomoon/AEGIS/actions/runs/45504677648):
  **SUCCESS**, mesma fonte d46850c,5runs/20testes sintéticos,2snapshots,5PDFs e
  0erros JavaScript. Mantém os checks completos do harness, sem excluir regressões.
- CI inicial45501759075 na fonte03d7dd3 foi cancelada pela política de
  concorrência após push da fonte completa; não é evidência de CI integral verde.

Logs consultados ficam privados em `.local/linux-scheduling-ci/`; não adicionar
logs, dumps, credenciais ou gerados ao Git.

## Aceite técnico e sincronização

#102 e #103 atendidas por implementação e testes de contrato/fixture PostgreSQL
e runner local; isso não é ensaio nativo. #104 tem componentes/UI e E2E Demo
validados, mas o critério de recorrência nativa continua bloqueado. O pai #23 não
recebe aceite conjunto nem é fechado com esse filho pendente.

Commits executáveis enviados diretamente para `origin/main`:

- `03d7dd3` — `feat(scheduling): bind opt-in Linux recurrence to segregated grants (Refs #102, #103)`.
- `656caec` — `feat(scheduling): review real scope and preserve snapshot origin (Refs #103, #104)`.
- `d46850c` — `fix(scheduling): require confirmed laboratory mode before proposal (Refs #104)`.

O commit final desta sessão é documental e será identificado nos comentários das
issues, com estado de sincronização e último hash/mensagem. Fonte de CI/E2E e
implantação são distintas: nenhuma implantação foi realizada.

## Bloqueio da #104 e limites operacionais

Nenhum laboratório foi iniciado, nenhuma rede/PKI/volume/journal/fence original
foi aberto ou alterado e nenhum marcador nativo foi executado. A flag real não foi
habilitada em implantação. Não houve build/tag/release de imagem, migração,
implantação, reset de conta ou mudança de visibilidade GitHub.

O Windows atual não tem Docker no PATH nem daemon/processo Docker identificado;
PG/Redis locais estão indisponíveis e o runner exige Linux. Falta ambiente nativo
inspecionado e pacote de autorização novo com número exato de ocorrências.
Não foi fabricado pacote com hashes/identidades sem inspeção. Autorizações
históricas estão consumidas. #104 e o pai #23 permanecem abertos até ensaio real
especificamente aprovado e aceite conjunto. Fixture/CI/E2E Demo não substituem
esse ensaio. Parar neste escopo.

## Retomada: ambiente nativo preparado, aguardando autorização

Após o pedido de concluir todo o escopo, a fonte
`178e7df14e14e58ad2b2db2b480b07fbfcd340bc` acrescentou um procedimento nativo
fechado em VM Linux nova do GitHub Actions. O bloqueio de runtime local foi
contornado sem instalar stack neste Windows ou tocar em originais. O ambiente
foi **somente preparado**: imagens construídas, identidades e PKI novas, manifesto
concreto publicado; nenhum serviço de laboratório ou marcador nativo iniciado.

[Pacote28de3e3f para revisão](REQUEST-104-28de3e3f.md),
[manifesto14975638954](https://github.com/Buraddomoon/AEGIS/actions/runs/45514289124/artifacts/14975638954)
e [procedimento](../../operations/scheduling-native.md). SHA256 integral
`28de3e3f53ad79c39651feec2dd3f3d6013acf0ac63ff3b3ed71ca347fe2d65d`.
Propõe duas ocorrências reais do marcador benigno,60s/30s/concorrência1, sem
Wazuh/originais, com cleanup e descarte do host efêmero expressamente incluídos.
Autorização específica foi solicitada ao usuário; ainda não registrada.
O workflow45514289124 permanece na barreira de aprovação, com prazo fixo no pacote.

[CI45514261833](https://github.com/Buraddomoon/AEGIS/actions/runs/45514261833)
**SUCCESS** na fonte178e7df, quatro partições Python e React conferidos:
**4164Python/9skips existentes,159React/21arquivos e21checks glob**.
Partições:1004/2skips,1023/2,1060/1 e1077/4. Inclui33casos novos de preparação,
autorização/TTL/ator/host, receita, colisões, fence e inspeção independente do runtime.
Todos são testes sem Docker/efeito. O fsync POSIX de diretório é real na CI Linux.

Localmente passaram55casos combinados de preparação/política, lint/formatação,
mypy, sintaxe/formatação do cliente browser e checks de staged/release.
Primeira rodada teve29aprovações/2falhas por ausência de O_DIRECTORY no Windows;
o fixture passou a simular somente essa primitiva POSIX, mantendo o gate nativo
exclusivamente Linux. Não foi adicionada exceção ao runner ou à execução real.

Commits adicionais:178e7df (`test(scheduling): prepare isolated native assay with
exact human gate (Refs #104)`) e4a66f5b (pacote concreto documental).
Nenhum comentário de autorização foi fabricado a partir do pedido genérico,
silêncio, build ou CI. #104 e #23 continuam abertas até efeito/cleanup comprovados
e aceite conjunto, ou encerramento sem efeito se o pacote expirar sem aprovação.
