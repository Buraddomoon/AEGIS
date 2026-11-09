# API v1

Base `/api/v1`. OpenAPI em `/api/openapi.json`, Swagger em `/api/docs`. A documentação Swagger pode carregar assets oficiais por CDN; a operação principal da SPA e do backend é local e não depende disso.

Sessão por cookie HttpOnly. Login JSON exige `X-Aegis-Request: browser`; origem, quando presente, deve ser PUBLIC_ORIGIN. Resposta define cookie CSRF legível e retorna token CSRF. Mutações autenticadas exigem `X-CSRF-Token` vinculado à sessão. Não usar tokens de sessão na URL ou localStorage.

| Recursos | Operações |
|---|---|
| auth | POST login/logout, GET me |
| users | GET lista, POST cadastro (admin) |
| labs/assets | GET lista, PATCH lab authorization, POST linux/register e preflight, GET verifications, POST recover (admin para mutações) |
| techniques | GET pesquisa/filtros/paginação; GET detalhe/history/simulações |
| catalog/attack | GET estado/proveniência; GET releases paginadas; GET releases/{id}/techniques snapshot pesquisável |
| tests | GET allowlist Demo e marcador Linux revisado |
| campaigns | GET/POST; POST `/{id}/runs` com idempotency_key |
| executions | GET lista/detalhe, POST approve/start/cancel/reject |
| schedules | GET/POST lista/criação; GET detalhe e occurrences; POST approve (admin), pause (operador), revoke (admin), com confirmação explícita |
| coverage | GET indicadores/runs; GET report; GET compare e compare/report, com formato PDF/HTML/JSON |
| rules | GET/POST import YAML; GET `/{id}/versions` e `/{id}/versions/{version_id}/analysis` |
| reports | GET lista de concluídas; GET `/{run_id}?format=json|html|pdf` |
| connectors | GET estado; POST `/wazuh/test` somente configuração do ambiente |
| audit | GET lista paginada (admin) |
| health | GET live/ready, sem autenticação |

Listagens grandes usam `offset` e `limit` (1–1000), com `items/total`. Catálogos pequenos labs/tests são listas limitadas pela allowlist/configuração. Execuções filtram state/campaign_id/mode; coverage e techniques aceitam mode=demo|linux, padrão demo; técnicas filtram q/tactic/platform/coverage. Ordenação é determinística por recurso (IDs/nomes ou criação recente), sem SQL de ordenação livre recebido do usuário.

Erros `{error: {code, message, request_id}}`; erros de input incluem somente campo/tipo, sem valores sensíveis. Status: 401 sem sessão, 403 sem papel/CSRF/origem, 404 inexistente, 409 conflito de estado/escopo, 413 payload grande, 422 input inválido, 429 rate limit, 502 conector falhou, 503 dependência indisponível. X-Request-ID auxilia diagnóstico.

ATT&CK: `lifecycle=active|revoked|deprecated|absent|all` (padrão active) e
`catalog_release_id=<SHA256>` opcional vinculam técnicas à release esperada;
409 recusa paginação/detalhe após troca de catálogo. Respostas incluem referência
de catálogo e ciclo de vida; cobertura atual requer mesma release/mode.
`catalog/attack/releases` aceita limit1–100/offset; snapshots limit1–1000/offset/q.
Rotas do catálogo só leem, autenticadas para todos os papéis. Publicação é CLI
host-only, com credencial de implantação e plano confirmado; não existe POST web.
Histórico de técnica informa versão registrada ou contexto desconhecido.

Polling controlado da UI acompanha estado e evidências, sem WebSocket fictício. Schedules operam somente Demo, conforme [política](../operations/scheduling.md). Campanhas Linux usam os mesmos endpoints de execução; approve exige confirm_real_execution=true e aprovador diferente do solicitante. Detalhes incluem runner_dispatch/runner_receipt/runner_cleanup separados de eventos defensivos. Implantação Sigma permanece indisponível. Integrações ainda não configuradas retornam estado explícito e teste de conexão retorna 409; não inventam sucesso.

Coleta Wazuh: GET `/labs/{id}/wazuh-binding` mostra status/política pública, sem segredos. PUT no mesmo caminho exige administrador, review e confirm_read_only_scope=true, Lab revogado/sem reserva; POST `/remove` com confirm remove vínculo e preserva escopos históricos. Conflito de agent/asset já vinculado retorna 409 com rollback da versão do ambiente. Endpoint não recebe destino, índice, query DSL ou credenciais. Executions incluem collection (tentativas/janela/disponibilidade/completude), separada de runner_receipt/runner_cleanup/events/evidence.

Revisão Linux: GET `/labs/{id}/binding-review`, administrador,30/min/usuário,
snapshot REPEATABLE READ READ ONLY/15s. Agregados de pais/filhos pendentes e provas
de cleanup por dispatch, limite1.000 e amostra25; sem runner/SIEM/ativação. Registro
Linux e bind/unbind Wazuh repetem esse predicado sob lock e recusam409 enquanto
houver pendência, mesmo sem reserva. Cancelar solicitações antes de mudar vínculo;
nenhum histórico é reescrito. [Contrato e limites](../operations/linux-binding-review.md).

Associações revisadas: GET `/rule-test-links` (rule_id/test_id/include_retired/limit/offset), POST `/rules/{id}/test-links` e DELETE `/rules/{id}/test-links/{link_id}` (retirada sem exclusão). Operador/admin escreve com CSRF; viewer consulta. Body fixa versão/hash/test_version/justificativa e replaces_id. Comparação retorna `scope_changes` de snapshots; vínculos desconhecidos no legado retornam null com link_context_recorded=false. [Contrato e limites](../operations/rule-test-reviews.md).

Análise Sigma: GET da versão salva confere SHA e retorna analyzer_version/pysigma_version, checks/skipped_checks, facts/findings e compatibility=not_configured. Somente leitura, sessão de qualquer papel, 60/min por usuário. 409 por integridade divergente, 422 por conteúdo não analisável/limites. Não altera veredictos nem implanta regras. [Contrato e limites](../integrations/sigma.md#análise-estática-de-versões).

Cobertura/relatórios: `mode=demo|linux`, `catalog_release=all|current|legacy|SHA256`,
`requested_from`/`requested_before` RFC3339 com offset, intervalo semiaberto pela
data da solicitação. Seleção/ID/hash/denominadores explícitos e snapshot coerente
READ ONLY. Legacy tem catálogo desconhecido/null. `/coverage/runs` pagina até100
opções por página; total do recorte acima5000 é recusado, sem truncar métricas.
`/coverage/report` aceita `expected_scope_sha256` para proteger o recorte e
`format=json|html`; `/coverage/compare/report` recebe before/after e format,
com relatos/evidências por lado. Exportações30/min/usuário, auditoria por hash;
não executam testes nem mudam veredictos. `/reports` compartilha os filtros,
padrão Demo; `/{run_id}` individual mantém contrato anterior.
[Semântica, exemplos e integridade](../operations/coverage-reports.md).

Relatório individual `GET /reports/{run_id}`: `report_version=1.2` acrescenta
`summary` com simulações no escopo, estados/resultados registrados, concluídos,
testes válidos, detectados, excluídos e percentual. Taxa exige pai/filho COMPLETED;
sem testes elegíveis retorna null. HTML/PDF mostram o mesmo resumo. O hash anterior
continua cobrindo somente `run`, sem mudar o histórico. [Cálculo e integridade](../operations/pdf-reports.md#resumo-da-execução).

Preparação Sigma: GET `/sigma/conversion-profiles` (60/min/usuário) e GET `/rules/{id}/versions/{version_id}/conversion-readiness?profile_id=...` (30/min) permitem viewer autenticado. Retornam perfil/hash, campos candidatos, metadados revisados versus pacotes instalados e bloqueios; can_convert/conversion_performed/deployment_performed=false. Não recebem destinos, pipelines ou consultas. [Contrato completo](../integrations/sigma.md#preparação-de-conversão-e-campos-candidatos).

Prévia Sigma: GET `/rules/{id}/versions/{version_id}/mapping-preview`, com
profile_id exato, sessão viewer/operator/admin,30/min e integridade SHA da versão.
Transformação fixa oficial de nomes, sem pipeline fornecido pelo cliente. Retorna
before/after normalizados somente no subconjunto revisado; unsupported tem ambos
null e blockers. Documento inteiro tem SHA; IDs/versões/hashes fixam o contexto.
Todos os flags de conversão/query/consulta/implantação/mapping físico são false.
404perfil/versão,409integridade,422budget/legado,429limite,503core/guard/Redis.
[Política e limites](../integrations/sigma.md#prévia-de-transformação-de-campos).
