# Relatórios PDF

Exportações disponíveis para execução individual, cobertura e comparação.
Usam os mesmos builders dos formatos JSON/HTML; nenhuma simulação ou consulta
SIEM é iniciada ao gerar um PDF.

## Uso na interface

- Execução: **Exportar PDF**, junto a HTML/JSON.
- Relatórios: botão **PDF** da execução concluída selecionada.
- Cobertura: aplique os filtros e use **Exportar recorte PDF**.
- Comparação: selecione o par, compare e use **Exportar comparação PDF**.

Filtros alterados ainda não aplicados, consulta com erro ou referência divergente
impedem exportação na UI. A API também valida o hash esperado do recorte. PDF
disponível não significa que a run terminou: o documento identifica o estado e
mantém resultados ausentes como NOT_TESTED.

## Conteúdo e integridade

Resumo executivo, resultados técnicos, escopo, limitações, recomendações quando
presentes na fonte e apêndice JSON completo. As classificações vêm do relatório
original; o exportador não recalcula detecção, comparabilidade ou causalidade.
Toda página distingue Demo, escopo misto ou laboratório real. Um recibo do
executor continua sem comprovar detecção defensiva.

Fontes Vera do ReportLab são incorporadas, mantendo acentos portugueses e ÆGIS.
Caracteres sem glifo e controles são mostrados como escapes Unicode; o apêndice
usa JSON com Unicode escapado. O layout pode acrescentar quebras em linhas longas:
para processamento automático, baixe JSON pela API.

O cabeçalho HTTP `X-AEGIS-Report-SHA256` e o texto **SHA256 do relatório JSON
completo** correspondem a `aegis.domain.validation.digest(report)`: JSON com
chaves ordenadas, separadores sem espaços e Unicode preservado em UTF-8. Inclui
o campo de integridade original. Não é hash dos bytes PDF ou assinatura digital.

`integrity_sha256` conserva o contrato anterior: execução individual cobre `run`;
cobertura/comparação cobrem o documento retirando somente esse campo. A exportação
de cobertura produz um novo snapshot datado; seu conteúdo pode diferir de uma
exportação JSON anterior do mesmo recorte. Hash de escopo não fixa os dados nem
substitui autorização.

## API e limites

```text
GET /api/v1/reports/{run_id}?format=pdf
GET /api/v1/coverage/report?format=pdf&expected_scope_sha256=HASH_DO_RECORTE
GET /api/v1/coverage/compare/report?before=RUN_ANTERIOR&after=RUN_ATUAL&format=pdf
```

Exigem sessão autenticada; viewer pode consultar/exportar, conforme o workspace
único existente. Resposta `application/pdf`, attachment, no-store e nosniff.
Auditoria registra formato/tipo/referência após geração bem-sucedida, sem payload.

- Máximo512KiB do relatório serializado para o apêndice: ASCII/indentação inclusos.
- Máximo120páginas e8MiB de saída; falha entrega erro JSON, sem PDF truncado.
- Orçamento cooperativo20s verificado ao paginar e finalizar; não é preempção de
  thread nem garantia de tempo de resposta sob carga.
- Uma renderização por processo; ocupado retorna503/Retry-After.
- Dez pedidos PDF por minuto/usuário, compartilhados pelos três endpoints.
  Exceder retorna429; cobertura/comparação mantêm também o limite analítico30/min.

413 pede recorte menor ou formato JSON/HTML; um relatório individual grande deve
ser exportado nesses formatos, sem alterar o histórico para caber no PDF. 409
recusa escopo obsoleto ou integridade não confirmada. Sem PDF/A, criptografia,
assinatura, garantia de acessibilidade ou suporte tipográfico universal.

## Verificação reproduzível

`pytest tests/test_pdf_reporting.py tests/test_pdf_api.py -q` gera/lê PDFs com
parser independente e exercita PostgreSQL/worker/Redis de desenvolvimento.
`npm --prefix apps/web test` verifica downloads, erros e bloqueios de filtros.
`make e2e` inclui os três downloads reais pelo Firefox sobre schema descartável.
O harness retorna à aba da aplicação após o download: Firefox pode ocultá-la e
TanStack Query pausa polling em abas ocultas por padrão.

Para preservar a galeria ao repetir E2E, defina `AEGIS_E2E_SCREENSHOTS` com um
diretório local de desenvolvimento. PDFs de verificação ficam em `.local/e2e`,
fora do Git. Não usar esse diretório para dados empresariais reais.

[Decisão e fontes oficiais](../architecture/decisions/0031-pdf-report-exports.md)
· [Checkpoint de testes/implantação](../PROGRESS.md).
