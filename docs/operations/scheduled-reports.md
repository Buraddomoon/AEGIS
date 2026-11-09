# Relatórios automáticos de agendamentos Demo

Abra **Agendamentos → Detalhes → Relatórios automáticos**. Cada nova ocorrência
efetivamente emitida solicita um documento no banco junto com a run e seu grant.
O worker aguarda o estado terminal e salva um snapshot JSON com hash. Não é
necessário manter o navegador aberto ou solicitar geração manualmente.

## Seleção do par e interpretação

- Sem ocorrência executada anterior da mesma autorização: **Relatório inicial**.
- Nas seguintes: **Comparação automática** com a ocorrência executada imediatamente
  anterior do mesmo plano e do mesmo grant, inclusive quando ela falhou/cancelou.
- Reaprovar o plano inicia outra autorização e outro relatório inicial. Não cruza
  grants para obter uma taxa mais favorável.
- Horários descartados não geram run/documento nem resultado de detecção.
- Ocorrências antigas não recebem pedidos retroativos. Uma nova comparação pode
  usar uma run prévia já existente da mesma autorização, sem criar relatório para ela.

**Documento pronto** confirma somente a geração. As mesmas regras de comparação
manual exigem escopo/contexto/conclusão íntegros para declarar comparabilidade.
Delta fica ausente quando não há equivalência ou denominador. Execução falha,
cancelamento ou cleanup falho não vira detecção nem proteção empresarial.
Todos os documentos desse recurso são identificados como sintéticos.

O snapshot mantém plano, ocorrência, autorização, execuções, resultados e
evidências como estavam na geração. Alterar regras, revogar o grant ou baixar
novamente não regenera esse documento. `automation` identifica política, pedido,
par e instante UTC; `document_sha256` da solicitação cobre o documento completo.
O `integrity_sha256` individual continua cobrindo somente `run`; comparações
cobrem o documento retirando esse próprio campo. Hash não é assinatura.

## Estados, limites e falhas

| Estado da geração | Significado |
| --- | --- |
| PENDING | Aguarda término da run ou próxima tentativa do worker |
| READY | Snapshot salvo e conferido; downloads liberados |
| FAILED | Geração encerrada sem arquivo parcial; motivo operacional visível |

Até três tentativas em falhas transitórias, com esperas de10s/30s. Limite2MiB
do JSON armazenado; contexto inválido ou tamanho excessivo encerram sem retry.
Geração usa thread própria, sessões próprias e snapshot READ ONLY/SQL15s; não
bloqueia linhas de execução/lab/schedule. Processadores concorrentes publicam uma
vez por pedido, com auditoria na mesma transação. Crash antes do commit pode
recalcular o documento, sem repetir simulações ou publicar um artefato parcial.

Códigos públicos: CONTEXT_MISMATCH, SOURCE_LIMIT, GENERATION_FAILED e
RECOVERY_RECONCILED. Não armazenar mensagens de driver, segredos ou documento na
auditoria. Erro de geração não muda o resultado da simulação; o link da execução
permite consultar/exportar os fatos originais. Não há retry manual ou edição do
snapshot nesta versão. A reconciliação de um backup encerra pedidos pendentes
como FAILED/RECOVERY_RECONCILED e mantém documentos já finais intactos.

## API e exportações

```text
GET /api/v1/schedules/{schedule_id}/reports?limit=25&offset=0
GET /api/v1/schedules/{schedule_id}/reports/{report_id}?format=json|html|pdf
```

Lista paginada, limite1–100, apenas metadados; não carrega os corpos dos documentos.
Todas as rotas exigem sessão. Viewer consulta/exporta, conforme o workspace único
atual. Não existe POST web de geração e nenhum grant novo decorre de download.

Download aceita `expected_sha256` (64hex) e confere documento/contexto antes de
renderizar. Retorna attachment/no-store/nosniff e X-AEGIS-Report-SHA256 do documento
completo. Sem documento pronto ou hash divergente:409; contexto de outra agenda
ou ID inexistente:404. Input inválido:422. Exportações compartilham30/min/usuário
com relatórios analíticos; PDF compartilha também10/min/usuário com todos os demais
PDFs. Geração JSON automática não produz arquivos PDF em background: HTML/PDF são
renderizados do snapshot salvo ao baixar, com os [limites existentes](pdf-reports.md).
Um snapshot READY pode exceder o limite PDF; JSON/HTML continuam disponíveis.

## Migração e compatibilidade

Revisão `b7f3c2d91a06`, tabela `scheduled_reports`,33tabelas contando Alembic.
Identidades/par e artefatos finais protegidos por trigger; runtime não pode DELETE
nem atualizar colunas de origem. Migração aditiva não altera runs, aprovações ou
planos anteriores e não gera documentos retroativos.

Antes de migrar o Demo, manter backup privado e imagem anterior em tag local
dedicada, aplicar migração/grants restritos e atualizar API/worker compatíveis.
Não usar o startup padrão com seed para uma atualização que deve preservar dados.
Backups a0d9c7e21b45 continuam exigindo código/imagem compatíveis; o guard de
recovery atual não deve ser relaxado para aceitá-los. Dados/volumes Linux e Wazuh
não são migrados por essa etapa. [Implantação](deployment.md) e
[backup/recovery](backup-recovery.md).

Testes: test_scheduled_report_storage, test_scheduled_reports,
test_scheduled_report_api, test_recovery_reconciliation e scheduled-reports.test.tsx.
E2E Firefox usa duas ocorrências com cadência real de60s, exporta o PDF e confere
snapshot inalterado após edição Sigma e layout390px. Os testes usam bancos/schemas
descartáveis; não iniciam Linux/Wazuh. Estado real da CI/implantação no
[checkpoint](../PROGRESS.md) e contrato no [ADR0032](../architecture/decisions/0032-scheduled-comparison-reports.md).
