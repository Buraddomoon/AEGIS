# API v1

Base `/api/v1`. OpenAPI em `/api/openapi.json`, Swagger em `/api/docs`. A documentação Swagger pode carregar assets oficiais por CDN; a operação principal da SPA e do backend é local e não depende disso.

Sessão por cookie HttpOnly. Login JSON exige `X-Aegis-Request: browser`; origem, quando presente, deve ser PUBLIC_ORIGIN. Resposta define cookie CSRF legível e retorna token CSRF. Mutações autenticadas exigem `X-CSRF-Token` vinculado à sessão. Não usar tokens de sessão na URL ou localStorage.

| Recursos | Operações |
|---|---|
| auth | POST login/logout, GET me |
| users | GET lista, POST cadastro (admin) |
| labs/assets | GET lista, PATCH lab authorization, POST linux/register e preflight, GET verifications, POST recover (admin para mutações) |
| techniques | GET pesquisa/filtros/paginação; GET detalhe/history/simulações |
| tests | GET allowlist Demo e marcador Linux revisado |
| campaigns | GET/POST; POST `/{id}/runs` com idempotency_key |
| executions | GET lista/detalhe, POST approve/start/cancel/reject |
| schedules | GET/POST lista/criação; GET detalhe e occurrences; POST approve (admin), pause (operador), revoke (admin), com confirmação explícita |
| coverage | GET indicadores; GET compare?before=UUID&after=UUID |
| rules | GET/POST import YAML; GET `/{id}/versions` e `/{id}/versions/{version_id}/analysis` |
| reports | GET lista de concluídas; GET `/{run_id}?format=json|html` |
| connectors | GET estado; POST `/wazuh/test` somente configuração do ambiente |
| audit | GET lista paginada (admin) |
| health | GET live/ready, sem autenticação |

Listagens grandes usam `offset` e `limit` (1–1000), com `items/total`. Catálogos pequenos labs/tests são listas limitadas pela allowlist/configuração. Execuções filtram state/campaign_id/mode; coverage e techniques aceitam mode=demo|linux, padrão demo; técnicas filtram q/tactic/platform/coverage. Ordenação é determinística por recurso (IDs/nomes ou criação recente), sem SQL de ordenação livre recebido do usuário.

Erros `{error: {code, message, request_id}}`; erros de input incluem somente campo/tipo, sem valores sensíveis. Status: 401 sem sessão, 403 sem papel/CSRF/origem, 404 inexistente, 409 conflito de estado/escopo, 413 payload grande, 422 input inválido, 429 rate limit, 502 conector falhou, 503 dependência indisponível. X-Request-ID auxilia diagnóstico.

Polling controlado da UI acompanha estado e evidências, sem WebSocket fictício. Schedules operam somente Demo, conforme [política](../operations/scheduling.md). Campanhas Linux usam os mesmos endpoints de execução; approve exige confirm_real_execution=true e aprovador diferente do solicitante. Detalhes incluem runner_dispatch/runner_receipt/runner_cleanup separados de eventos defensivos. Implantação Sigma permanece indisponível. Integrações ainda não configuradas retornam estado explícito e teste de conexão retorna 409; não inventam sucesso.

Coleta Wazuh: GET `/labs/{id}/wazuh-binding` mostra status/política pública, sem segredos. PUT no mesmo caminho exige administrador, review e confirm_read_only_scope=true, Lab revogado/sem reserva; POST `/remove` com confirm remove vínculo e preserva escopos históricos. Conflito de agent/asset já vinculado retorna 409 com rollback da versão do ambiente. Endpoint não recebe destino, índice, query DSL ou credenciais. Executions incluem collection (tentativas/janela/disponibilidade/completude), separada de runner_receipt/runner_cleanup/events/evidence.

Associações revisadas: GET `/rule-test-links` (rule_id/test_id/include_retired/limit/offset), POST `/rules/{id}/test-links` e DELETE `/rules/{id}/test-links/{link_id}` (retirada sem exclusão). Operador/admin escreve com CSRF; viewer consulta. Body fixa versão/hash/test_version/justificativa e replaces_id. Comparação retorna `scope_changes` de snapshots; vínculos desconhecidos no legado retornam null com link_context_recorded=false. [Contrato e limites](../operations/rule-test-reviews.md).

Análise Sigma: GET da versão salva confere SHA e retorna analyzer_version/pysigma_version, checks/skipped_checks, facts/findings e compatibility=not_configured. Somente leitura, sessão de qualquer papel, 60/min por usuário. 409 por integridade divergente, 422 por conteúdo não analisável/limites. Não altera veredictos nem implanta regras. [Contrato e limites](../integrations/sigma.md#análise-estática-de-versões).
