# ADR0031 — Exportação PDF dos relatórios existentes

Data: 2026-11-05. Decisão implementada; validação local concluída, CI/implantação
registradas em docs/PROGRESS.md.

## Escopo

O usuário adiou o laboratório e escolheu relatórios PDF. Exportar execução,
cobertura e comparação usando os mesmos builders/snapshots dos formatos JSON e
HTML. Não alterar classificações, evidências, aprovações ou configurações de
laboratório. A rede qasrc permanece preservada.

## Decisão

ReportLab **5.1.0**, Python>=3.9, licença BSD; Pillow **13.0.0**, MIT-CMU, é
dependência transitiva obrigatória. pypdf **6.21.4**, BSD-3-Clause, fica somente
em dev para verificar PDFs gerados. Hashes de wheels PyPI fixados nos locks,
mantendo as demais versões. Sem extras comerciais, navegador, executáveis ou
fontes baixadas no runtime. Fontes Vera fornecidas pelo pacote são incorporadas;
textos sem glifo disponível usam escapes Unicode explícitos. A licença Bitstream
Vera acompanha as fontes no wheel.

O adaptador gera bytes em memória. Layout fixo, conteúdo textual escapado antes
de Paragraph, sem HTML do usuário, links ativos, imagens, templates livres,
Macro/DocExec ou avaliação de expressões. O apêndice textual inclui todo o JSON
do relatório, com caracteres Unicode escapados, sem truncamento. Hash do JSON
completo e hash original conservam seus significados distintos; nenhum é uma
assinatura digital ou hash dos bytes PDF.

Limites iniciais: JSON de entrada512KiB, PDF8MiB/120páginas e orçamento cooperativo
20s verificado ao paginar/finalizar, sem preempção de thread;
uma renderização por processo e10pedidos PDF/minuto/usuário, compartilhados pelos
três endpoints. Recusar limite excedido antes de entregar qualquer arquivo
parcial; manter JSON/HTML disponíveis. Não criar jobs persistidos para documentos
pequenos e limitados. Os limites são proteções, não métricas de desempenho.

Manter autenticação/RBAC e filtros/hash de recorte existentes. Resposta PDF é
attachment/no-store/nosniff. Auditar exportação somente após geração bem-sucedida,
sem registrar conteúdo. Demo, misto e laboratório real recebem avisos distintos
em todas as páginas. O PDF não reclassifica recibos como detecção.

## Validação exigida

Ler o PDF com parser independente; conferir evidências/hashes, acentos, avisos,
paginação, limites e payloads de marcação como texto. Testar endpoints sobre
PostgreSQL real, autenticação/viewer, recorte obsoleto, auditoria e rate limit;
testar downloads/erros/bloqueios na UI e um fluxo Demo de navegador. Inspecionar
visualmente um PDF real gerado no teste. Não anunciar implantação no site antes
de verificar a versão em execução.

## Fontes oficiais consultadas

- [ReportLab no PyPI](https://pypi.org/project/reportlab/5.1.0/)
- [Notas 5.1 e correções de segurança](https://docs.reportlab.com/releases/notes/whats-new-51/)
- [Platypus e BytesIO](https://docs.reportlab.com/reportlab/userguide/ch5_platypus/)
- [Unicode e fontes](https://docs.reportlab.com/reportlab/userguide/ch3_fonts/)
- [pypdf no PyPI](https://pypi.org/project/pypdf/6.21.4/)

Limites: sem PDF/A, assinatura, criptografia, leitor de PDF importado pelo usuário,
garantia de acessibilidade ou tipografia universal. JSON é o formato de referência
para processamento automatizado; cópias baixadas contêm as evidências do escopo.
