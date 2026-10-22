# Ensaio real registrado — 2026-10-22

Um único ensaio autorizado no projeto próprio `aegis-wazuh-lab`, Wazuh4.14.9,
campanha `987bd48f-fafc-4a34-bf2a-2d310e7ca794`. Resultado observado:
**COMPLETED / DETECTED / CLEANED**, `synthetic=false`.

- [alert.json](alert.json): documento original consultado no Indexer, com `_id`,
  `_index` e `_source` preservados. Todos os identificadores/IPs pertencem ao
  laboratório isolado deste projeto; não são dados corporativos.
- [observer.jsonl](observer.jsonl): única linha do observador passivo que leu o
  arquivo real. Wazuh converteu `artifact_bytes` numérico em string no decoder;
  `full_log` preserva a mensagem original. Não é cópia do recibo.
- [result.json](result.json): resumo selecionado da execução, recibos, coleta,
  aprovação, indicadores e verificações de encerramento. Não é o relatório JSON
  integral nem uma nova consulta ao SIEM. Relatórios completos permanecem locais.
- [sha256.json](sha256.json): hashes dos bytes destes três arquivos. O campo
  `alert_sha256` usa a serialização canônica da aplicação; não confundir os dois.

Hashes verificam alterações, não autenticidade do operador. Reprocessar estes
arquivos em testes **não constitui uma nova validação externa**. Os testes
`tests/test_wazuh_recorded_assay.py` verificam integridade e normalização desse
schema registrado sem iniciar serviços ou executar outro marcador.

O alerta `100200` confirma somente o pipeline do marcador benigno de43bytes,
sem associação ATT&CK. Os indicadores incluem **um teste válido** e **zero
técnicas avaliadas**. Não extrapolar o percentual desse teste para proteção de
uma organização, eficácia de EDR ou coverage de outros comportamentos.

Archives não foram ativados: `telemetry_available=false`, `alerts_available=true`.
A coleta positiva terminou após6 consultas; `window_satisfied=false` não impede
um alerta positivamente correlacionado. Uma conclusão negativa exigiria cumprir
a janela e todas as condições de completude. A instrumentação inclui regra
própria explícita; não demonstra detecção padrão do Wazuh.

Cleanup físico conferido, laboratório revogado, contas temporárias desativadas e
senhas temporárias removidas. Containers e redes do ensaio encerrados; volumes,
diário e evidências preservados. A autorização de um único ensaio foi consumida.
Não iniciar o stack nem repetir o marcador para gerar screenshots ou novos testes.

Veja [escopo e procedimento](../../../labs/wazuh/ASSAY.md) e
[registro de progresso](../../PROGRESS.md).
