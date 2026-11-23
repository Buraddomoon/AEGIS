# Checkpoint — comparação entre laboratórios #21

Escopo exclusivo:#21 e filhos#97/#98/#99. Não retomar automaticamente outra
entrega. Pai e bloqueadores lidos no GitHub; nenhuma dependência externa ativa.
Implementação offline, sem autorização operacional Linux/Wazuh.

Fonte executável final`8c1d74eb0c2f4ccab7218619180d13057cefa73b`:

- #97: coortes históricas por laboratório/modo/período/release, equivalência
  limitada aos registros, comparação descritiva ou incomparável. Contexto
  desconhecido/incompleto, parciais, origem contraditória e frequências diferentes
  impedem delta; Demo/real e denominadores sempre separados.
- #98: GETs de comparação/export em snapshot próprio RR/READ ONLY, membros e
  hashes, limites sem truncamento, sem coleta/simulação por consulta. Exportação
  revalida hash completo/data do preview e recusa409 em drift.
- #99: dois recortes explícitos, taxas/motivos/diferenças/contextos, invalidação
  de preview/export e cancelamento de resposta/download antigos. JSON/HTML/PDF
  usam o mesmo documento; contratos históricos preservados.

Validação local:92Python abrangentes,33contrato/API após reforço de fonte
(96casos distintos, conjuntos sobrepostos);144React/20arquivos com dois workers,
21glob, lint/build/auditorias. Falhas anteriores preservadas, inclusive workers
locais sob pressão de memória. Auditoria Python mantém um achado já revisado;
nenhuma alegação de zero findings.

Firefox finalVERIFIED: duas runs Demo/um teste cada, uma solicitação adicional
pendente sem start para provocar drift, três classificações e três exports,
PDF8páginas,1440px/390px, zero errosJS/overflow. Históricos individuais JSON/HTML/
PDF idênticos. Processos próprios encerrados e schema removido; consulta posterior
encontrou zero schemas de todas as tentativas. Sem repetir ensaio nativo.

Demo API/worker permanecem na imagem anterior`b8abe5e...`, sem implantação ou
migração de originais; rede/PKI/volumes/autorizações consumidas preservados.
As alterações locais de rede no outro checkout não foram tocadas. Cada commit
foi enviado diretamente em main; sem branch/PR/tag/release.

[Provas, falhas e hashes](../evidence/coverage-environments-2026-11-23/README.md).
[Operação/API](../operations/coverage-reports.md#contrato-da-comparação-entre-laboratórios--2197).
CI integral[45255847606](https://github.com/Buraddomoon/AEGIS/actions/runs/45255847606)
**SUCCESS** na fonte`8c1d74e`: quatro partições Python962/953/1060/955,
total3930passaram/9skips opcionais existentes,144React/20arquivos e21glob.
Todos os cinco jobs conferidos. Nenhum gate alterado; commit de encerramento
somente documental, inputs executáveis idênticos à fonte validada.

#97/#98/#99 e aceite conjunto#21 atendidos. Provas/falhas preservadas e
sincronização/último hash nos comentários GitHub. Entrega encerrada; **parar neste
escopo**, sem iniciar outra feature, implantação, autorização ou ensaio Lab.
