# Checkpoint da entrega #13 —17/11/2026

#75/#76/#77 implementadas: catálogo Atomic offline versionado, API autenticada e
biblioteca com requisitos/procedência/revisão. Entradas sempre
`approved=false`, `executable=false`, `available_for_new_scope=false`, separadas
da allowlist. Origem declarada pelo operador; nenhum download/instalação/execução.

[Provas, comandos, commits e limites](../evidence/atomic-catalog-2026-11-17/README.md):
83Python,98React, lint/build e Firefox real com17metadados/1revisão/zeroexecuções
Atomic, mais ciclo Demo5runs/20testes/2snapshots/4PDFs/16capturas/zeroerrosJS.
Schemas/processos E2E removidos; artefatos privados host-only. Não é implantação.

Fonte exige migration explícita c8/36tabelas; Demo/Labs originais b7 preservados.
Gate de prontidão Linux continua recusando c8 até revisão operacional específica.
Não migrar original nem iniciar Lab a partir deste checkpoint.

A #13 permanece aberta pelo bloqueio da auditoria npm na cadeia picomatch,
GHSA-fc5q-39xc-vjpf, sem versão corrigida na consulta17/11. Lockfiles preservados,
nenhum gate enfraquecido. CI parcial/falha não equivale a workflow verde;
conferir estado/IDs no comentário final da issue. Não ampliar escopo para
remediação genérica de dependências, outra feature ou implantação nesta sessão.
