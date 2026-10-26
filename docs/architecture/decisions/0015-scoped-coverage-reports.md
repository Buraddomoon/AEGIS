# ADR0015 — Cobertura por recorte e relatórios comparativos

Data:2026-10-26. Incremento somente de leitura, sem migração, nova dependência,
mudança de aprovação/worker ou novo ensaio Linux/Wazuh. Preservar schema e backups
a0d9c7e21b45 e a conta humana existente.

Recorte explícito: mode=demo|linux, catalog_release=all|current|legacy|SHA256 e
requested_from/requested_before em RFC3339 com offset obrigatório. Comparar
CampaignRun.created_at em UTC, intervalo [from,before); não misturar período de
ingestão/execução/conclusão. Datas ausentes significam limite aberto. Rejeitar
intervalo vazio/invertido, datas sem fuso e release inexistente.

All mantém histórico misto e referência de catálogo atual para a contagem de
técnicas ativas; current resolve o ID vigente, histórico usa somente seu snapshot
imutável e legacy seleciona scopes sem identidade registrada. Não preencher
legado: denominador de catálogo e avaliação por release são desconhecidos (null),
enquanto resultados/IDs registrados continuam consultáveis. Contagens de testes
válidos continuam DETECTED+OBSERVED_NOT_ALERTED+NO_TELEMETRY, apenas runs e filhos
COMPLETED; total/estados de runs do recorte são separados e explícitos.

Transação analítica própria REPEATABLE READ READ ONLY produz um snapshot coerente
de catálogo, membros e resultados. Não reutilizar a transação de autenticação
para alterar seu isolamento depois de consultas. Sessão fecha após materializar
o resultado. Limite explícito de5000runs por recorte, sem truncar métricas:
exceder exige reduzir o escopo. Listagens permanecem paginadas. Sem índice/DDL
prematuros ou promessa de desempenho de grandes ambientes.

API/UI usam o mesmo contrato de seleção. Retornar recorte canônico, ID resolvido,
hash de escopo e contagens de contexto desconhecido. Exportação HTML/JSON fixa
esse recorte, inclui membros/hashes e hash do conteúdo entregue; a UI envia o
hash esperado para recusar mudança de referência durante exportação. Novos dados
no mesmo recorte podem aparecer no snapshot da exportação, explicitamente datado.
Controles pendentes/erro não exibem dados antigos como se fossem do novo recorte.

Comparação/exportação identifica ambas as runs, snapshots, evidências, diferenças
de regras/testes/ambiente e denominadores por lado. Mesma campanha obrigatória;
recusar comparação da run consigo mesma. Equivalência exige conclusão dos dois
lados, mesmo scope e contexto de catálogo/vínculos registrado; desconhecido não
vira igualdade comprovada. Delta percentual só no escopo comparável com dois
denominadores não vazios. Comparação mista deve identificar dados sintéticos.
Nunca inferir causalidade, comprometimento ou proteção empresarial a partir de
ausência de alerta. Relatórios individuais existentes mantêm formato/integridade.

Sem tabelas artificiais de relatórios: exportações autocontidas, HTML escapado,
sem scripts/recursos externos, geradas dos fatos persistidos. Views/exports exigem
sessão de qualquer papel; exportações limitadas por usuário. A UI pagina as opções
de runs e releases e limpa a seleção/comparação ao mudar recorte.

Fontes oficiais conferidas, sem atualização de pacotes neste marco:
[isolamento SQLAlchemy2.1](https://docs.sqlalchemy.org/en/21/orm/session_transaction.html#setting-transaction-isolation-levels-dbapi-autocommit)
e [datas Pydantic](https://docs.pydantic.dev/latest/api/standard_library_types/#datetimes).
Validar fronteiras/fusos, releases/legado, modo, denominadores vazios, snapshot
concorrente, limites, RBAC/export/hash/HTML e UI/E2E em schema Demo descartável.
