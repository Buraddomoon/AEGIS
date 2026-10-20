# API v1

Base `/api/v1`. OpenAPI em `/api/openapi.json`, Swagger em `/api/docs`. A documentação Swagger pode carregar assets oficiais por CDN; a operação principal da SPA e do backend é local e não depende disso.

Sessão por cookie HttpOnly. Login JSON exige `X-Aegis-Request: browser`; origem, quando presente, deve ser PUBLIC_ORIGIN. Resposta define cookie CSRF legível e retorna token CSRF. Mutações autenticadas exigem `X-CSRF-Token` vinculado à sessão. Não usar tokens de sessão na URL ou localStorage.

| Recursos | Operações |
|---|---|
| auth | POST login/logout, GET me |
| users | GET lista, POST cadastro (admin) |
| labs/assets | GET lista, PATCH lab authorization, POST recover (admin) |
| techniques | GET pesquisa/filtros/paginação; GET detalhe/history/simulações |
| tests | GET allowlist demonstrativa |
| campaigns | GET/POST; POST `/{id}/runs` com idempotency_key |
| executions | GET lista/detalhe, POST approve/start/cancel/reject |
| schedules | GET/POST lista/criação; GET detalhe e occurrences; POST approve (admin), pause (operador), revoke (admin), com confirmação explícita |
| coverage | GET indicadores; GET compare?before=UUID&after=UUID |
| rules | GET/POST import YAML; GET `/{id}/versions` |
| reports | GET lista de concluídas; GET `/{run_id}?format=json|html` |
| connectors | GET estado; POST `/wazuh/test` somente configuração do ambiente |
| audit | GET lista paginada (admin) |
| health | GET live/ready, sem autenticação |

Listagens grandes usam `offset` e `limit` (1–1000), com `items/total`. Catálogos pequenos labs/tests são listas limitadas pela allowlist/configuração. Execuções filtram state/campaign_id; técnicas filtram q/tactic/platform/coverage. Ordenação é determinística por recurso (IDs/nomes ou criação recente), sem SQL de ordenação livre recebido do usuário.

Erros `{error: {code, message, request_id}}`; erros de input incluem somente campo/tipo, sem valores sensíveis. Status: 401 sem sessão, 403 sem papel/CSRF/origem, 404 inexistente, 409 conflito de estado/escopo, 413 payload grande, 422 input inválido, 429 rate limit, 502 conector falhou, 503 dependência indisponível. X-Request-ID auxilia diagnóstico.

Polling controlado da UI acompanha estado e evidências, sem WebSocket fictício. Schedules operam somente Demo, conforme [política](../operations/scheduling.md). Endpoints de execução real e implantação Sigma não existem nesta versão. Integrações ainda não configuradas retornam estado explícito e teste de conexão retorna 409; não inventam sucesso.
