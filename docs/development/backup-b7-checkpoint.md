# Recuperação Demo com relatórios automáticos — #11

Aceite conjunto em16/11/2026, limitado à entrega
[#11](https://github.com/Buraddomoon/AEGIS/issues/11). Filhas executadas e
encerradas em sequência: [#70](https://github.com/Buraddomoon/AEGIS/issues/70)
e [#71](https://github.com/Buraddomoon/AEGIS/issues/71). Não iniciar outra
feature, laboratório ou ensaio a partir deste checkpoint.

## O que foi demonstrado

- Cópia pré-migração a0 de09/11:32tabelas/3399linhas, dump/manifesto original
  preservados, restore/inventário e API compatível em quarentena aprovados.
- Backup fresco b7:33tabelas/3399linhas, restore/inventário/boot restrito e
  reconciliação real aprovados em clones novos, sem tocar o banco ativo.
- Como o Demo real tem zero relatórios automáticos, outra cópia foi derivada
  somente em clone offline com fixture explícita:2READY (inicial/comparação),
  1FAILED,1PENDING, mais fila/reserva/sessões/grant/agendamento não vazios.
- Esse dump foi restaurado em outro clone: finais inteiros idênticos; PENDING
  alterado somente em state/error_code para FAILED/RECOVERY_RECONCILED; JSON e
  HTML iguais, conteúdo dos PDFs igual por parser independente. Sem executar
  as runs da fixture ou disparar campanha antiga.
- Todos os fences zerados, ID/hash de reconciliação atual conferidos,
  `normal_operation_permitted=false`. Clones/helpers/API removidos antes dos
  recibos; nenhum recurso de recovery remanescente.

[Evidências #70](../evidence/backup-b7-2026-11-16/README.md),
[relatórios e reconciliação #71](../evidence/backup-b7-2026-11-16/REPORTS.md),
[preservação da fonte](../evidence/backup-b7-2026-11-16/source-preservation.json).
Somente agregados publicados; dumps, manifestos, documentos, PDFs, configuração,
intenções e diagnósticos continuam privados no host.

## Código, testes e implantação

Partida `2b31144`; primeira unidade `c3d38c7`
(`docs(recovery): verify a0 and b7 backup compatibility (Closes #70)`);
segunda `a8db6da`
(`test(recovery): prove frozen reports and restored queue fences (Closes #71)`).
Commits pequenos/coerentes, somente main e push direto. Código de aplicação,
migrations, frontend e imagens não foram alterados; foram ampliados os testes
de preservação e adicionada uma fábrica sintética reutilizada no ensaio offline.
O commit de aceite muda somente documentação; hash final e sincronização constam
no comentário da #11.

Validações locais reais, PG/Redis15 das suítes em sequência:

- `make test-recovery`:229passed na #70;235passed na fonte final com os novos
  casos (80,48s). Um aviso upstream Starlette/httpx, sem skips.
- `pytest tests/test_recovery_reconciliation.py tests/test_scheduled_report_storage.py tests/test_scheduled_report_api.py -q --tb=short`:
  55passed/um aviso. Conjuntos sobrepostos; não somar contagens.
- `make lint`:Ruff/formato/mypy/TypeScript/Prettier aprovados.
- Checks staged/segredos, whitespace e `scripts/check_release.py` aprovados
  antes de cada commit. E2E não repetido; nenhuma alteração de UI.

Falhas preservadas: credencial deste checkout diferente da instalação ativa
(171passed/58errors e backup recusado); configuração local correta reutilizada,
sem alterar senha/conta. Preparação inicial da fixture recusada pela trigger ao
pular incrementos de tentativas (5failed/37passed); fixture corrigida para seguir
as regras existentes, sem relaxar guardas. Repetições finais aprovadas.

A [CI integral43952849990](https://github.com/Buraddomoon/AEGIS/actions/runs/43952849990)
passou no commit da #70, que ainda não continha os novos casos da #71. A CI da
fonte final precisa ser conferida separadamente; resultado/URL/contagens finais
constam na #11. Testes locais ou uma partição não significam workflow verde.

Demo continua implantado na imagem b8abe5e44af4 de relatórios automáticos,
schema b7/33tabelas. Inventário ativo completo idêntico ao manifesto após os
ensaios; API/worker com mesmos IDs, database/redis ready. Imagens compatíveis
a0/b7 retidas em tags dedicadas; nenhuma imagem antiga sobrescrita.

## Limites e encerramento

O ensaio não vazio é fixture sintética com dump/restore Docker reais; não houve
relatório automático não vazio no backup operacional utilizado. Comparação da
fixture permanece não comparável, delta ausente e sem resultado defensivo.
Quarentena e fidelidade não liberam operação. Não houve cutover, failover,
reconexão, novo ciclo, login restaurado ou prova de recuperação off-host/RPO/RTO.
Custódia externa continua adiada; configuração/roles/Redis/journals não integram
o dump. Nada disso é uma pendência escondida do escopo de verificação offline.
Linux/Wazuh/qasrc, volumes, PKI, journals e fences preservados. Entrega encerrada
após registro final na issue; parar neste escopo.
