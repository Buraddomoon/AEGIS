import { useState } from 'react'
import {
  Badge,
  date,
  downloadFile,
  Empty,
  Failure,
  Go,
  Loading,
  Panel,
  useAction,
  useData,
} from './lib'
import type { Page, ScheduledReport } from './types'

const errors: Record<string, string> = {
  CONTEXT_MISMATCH: 'Contexto de origem não confirmado. Consulte a execução e a autorização.',
  SOURCE_LIMIT:
    'Documento excedeu o limite de armazenamento. Exporte as execuções individualmente.',
  GENERATION_FAILED: 'Falha ao gerar o documento. As tentativas automáticas são limitadas.',
  RECOVERY_RECONCILED: 'Pedido restaurado encerrado durante a recuperação. Histórico preservado.',
}

export function ScheduledReports({ scheduleId }: { scheduleId: string }) {
  const [offset, setOffset] = useState(0)
  const query = useData<Page<ScheduledReport> & { schedule_id: string }>(
    `/schedules/${scheduleId}/reports?limit=25&offset=${offset}`,
    3000,
  )
  const { busy, run } = useAction()
  const data = query.data
  const mismatch =
    data &&
    (data.schedule_id !== scheduleId ||
      data.items.some((item) => item.schedule_id !== scheduleId || item.synthetic !== true))
  return (
    <Panel
      title="Relatórios automáticos"
      subtitle="Snapshots sintéticos por autorização. Documento pronto confirma geração; não confirma detecção ou melhora."
    >
      <p className="muted-text scheduled-report-intro">
        A primeira execução de cada autorização produz um relatório inicial. As seguintes comparam
        com a ocorrência executada anterior da mesma autorização, preservando falhas e limitações.
      </p>
      {query.isLoading ? (
        <Loading />
      ) : query.error ? (
        <Failure error={query.error} />
      ) : mismatch ? (
        <Failure
          error={new Error('A lista recebida não corresponde ao agendamento selecionado.')}
        />
      ) : data?.items.length ? (
        <>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Documento</th>
                  <th>Estado da geração</th>
                  <th>Execuções de origem</th>
                  <th>Exportar snapshot</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((item) => (
                  <tr key={item.id} data-auto-report-id={item.id}>
                    <td>
                      {item.kind === 'BASELINE' ? 'Relatório inicial' : 'Comparação automática'}
                      <small>{date(item.generated_at)}</small>
                      <small>Autorização {item.authorization_id.slice(0, 8)}</small>
                    </td>
                    <td>
                      <Badge value={item.state} />
                      <small>Tentativas: {item.attempts}/3</small>
                      {item.error_code && (
                        <p role={item.state === 'FAILED' ? 'alert' : undefined}>
                          {errors[item.error_code] ?? 'Falha de geração registrada.'}
                        </p>
                      )}
                      {item.state === 'PENDING' && (
                        <small>
                          {item.attempts
                            ? `Nova tentativa a partir de ${date(item.next_attempt_at)}.`
                            : 'Aguarda o término da execução e o processamento pelo worker.'}
                        </small>
                      )}
                    </td>
                    <td>
                      <div className="scheduled-report-links">
                        <Go to={`executions/${item.run_id}`}>Execução atual</Go>
                        {item.previous_run_id && (
                          <Go to={`executions/${item.previous_run_id}`}>Execução anterior</Go>
                        )}
                      </div>
                    </td>
                    <td>
                      {item.state === 'READY' &&
                      item.document_sha256 &&
                      /^[a-f0-9]{64}$/.test(item.document_sha256) ? (
                        <>
                          <div className="toolbar">
                            {(['json', 'html', 'pdf'] as const).map((format) => (
                              <button
                                key={format}
                                className="button"
                                disabled={busy}
                                aria-label={`Baixar ${format.toUpperCase()} do relatório automático ${item.id.slice(0, 8)}`}
                                onClick={() =>
                                  void run(
                                    () =>
                                      downloadFile(
                                        `/schedules/${scheduleId}/reports/${item.id}?format=${format}&expected_sha256=${item.document_sha256}`,
                                        `aegis-auto-${item.document_sha256?.slice(0, 16)}.${format}`,
                                      ),
                                    'Snapshot automático exportado.',
                                  )
                                }
                              >
                                {format.toUpperCase()}
                              </button>
                            ))}
                          </div>
                          <details>
                            <summary>Hash do documento</summary>
                            <code className="scheduled-report-hash">{item.document_sha256}</code>
                          </details>
                        </>
                      ) : (
                        'Sem arquivo disponível'
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="pagination">
            <button
              className="button"
              disabled={!offset}
              onClick={() => setOffset(Math.max(0, offset - 25))}
            >
              Anterior
            </button>
            <span>{data.total} documentos</span>
            <button
              className="button"
              disabled={offset + 25 >= data.total}
              onClick={() => setOffset(offset + 25)}
            >
              Próxima
            </button>
          </div>
        </>
      ) : (
        <Empty title="Nenhum relatório automático solicitado">
          Somente ocorrências emitidas após a atualização solicitam documentos. Horários descartados
          não geram relatórios.
        </Empty>
      )}
    </Panel>
  )
}
