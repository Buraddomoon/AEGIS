# Dependência que bloqueou a CI da #58 — 16/11/2026

A run43911527295 passou os testes do grupo0, mas a auditoria identificou
`opentelemetry-api1.45.1 / CVE-2026-126360`. O resultado permanece registrado;
não houve filtro, exclusão de teste ou acréscimo à lista de findings revisados.

O [advisory oficial GHSA-mf5v-w3w3-f6cg](https://github.com/open-telemetry/opentelemetry-python/security/advisories/GHSA-mf5v-w3w3-f6cg)
afeta versões até1.45.1 e indica1.45.2 como corrigida. O problema é complexidade
quadrática ao extrair contexto de um `traceparent` malformado; não inferir
comprometimento ou exposição da aplicação somente pela presença do pacote.
Foi escolhido o patch corretivo, sem ampliar o escopo de versões.

`requirements.lock` e `requirements-dev.lock` agora fixam1.45.2. Wheel universal
oficial60.335bytes, SHA256
`2cbd737377e710ee740d261c94e93fa0f08e6d037c18f17513cc0a2d94479a34`,
conferido nos [metadados PyPI](https://pypi.org/pypi/opentelemetry-api/1.45.2/json)
e nos bytes baixados. Instalação local sem resolver/atualizar outras dependências,
usando hash obrigatório; `pip check` passou. O requisito de FastAPI é compatível.

`scripts/audit_dependencies.py` passou: somente diskcache/PYSEC-2026-2447
anteriormente revisado permanece visível. Não é uma afirmação de zero findings.
Integrações, Sigma análise/readiness/mapping, catálogo e release-check:
119testes passaram, incluindo PostgreSQL descartável, em execução sequencial.
O aviso conhecido Starlette/httpx permanece. Não substituir isso por CI integral;
conferir quatro jobs Python e React na nova fonte.

As imagens históricas e suas45versões revisadas em13/11 continuam preservadas.
O patch dos locks não as atualiza nem implanta o Demo/laboratórios. Imagens
locais derivadas com o wheel corrigido devem ter novos IDs/manifestos e tags
dedicadas antes de serem selecionadas num pacote integrado futuro. Não reescrever
a prova de dependências antiga ou confundir build/conferência com implantação.
