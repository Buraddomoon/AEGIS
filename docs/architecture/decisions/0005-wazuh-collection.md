# ADR 0005 — Coleta Wazuh aprovada e correlação de identidade

Status: implementação. Data: 2026-10-21. Continuidade de b8c9b0e (101 commits).

O usuário informou que ainda não possui Wazuh e pediu preparar a integração **sem instalar**. Não iniciar Wazuh, containers Linux, novos marcadores reais ou consultar serviços externos nesta etapa. Validar software com PostgreSQL/runner em fixtures descartáveis, HTTP local de teste e Demo existente.

## Decisões

- Indexer consulta alertas e, opcionalmente, archives; Server API de gestão permanece fora do fluxo. Ausência de índice archives não significa falha de telemetria. Índice inexistente, zero shards, timeout, falha parcial ou paginação truncada não confirmam consulta completa.
- Configuração de implantação tipada e opt-in fixa laboratório/ativo/agent.id, regra esperada, índices, campos/schema, janela de correlação e limites de polling. Segredos continuam no ambiente. API não recebe URL, IP, credenciais, índice livre, query DSL ou comando.
- Administrador revisa/vincula a configuração a laboratório Linux revogado e sem reserva. Binding é explícito; configuração sozinha não autoriza coleta. Alterar/desvincular invalida versão/aprovações anteriores. Credencial, CA e destino só são usados após verificar o fingerprint do escopo.
- Asset.id interno e agent.id externo são namespaces diferentes. Traduzir apenas agent.id que coincida exatamente com o mapping aprovado; preservar agent.id original no payload. Campo ausente/incompatível nunca é preenchido usando o contexto solicitado.
- Worker usa o contrato TelemetryProvider. Polling aguarda ingestão com orçamento monotônico e espaço para cleanup. Confirmação positiva exige alerta da regra esperada com identidade/marcador/comportamento/tempo correlacionados. Conclusão negativa requer rodada final completa e janela de ingestão cumprida. Orçamento insuficiente/falha => INCONCLUSIVE; falha de execução nunca vira DETECTED.
- Persistir resumo imutável da coleta: provedor/hash/schema, tentativas/período, disponibilidade, completude, janela e motivo público. Deduplicar eventos por origem/ID, rejeitar divergência de conteúdo, limitar páginas/documentos/bytes/tempo e liberar cursor. Guard de cancelamento continua ativo entre requisições/esperas.
- Comprovante do executor continua separado de evidência defensiva. Preparar observador passivo de proof.marker: leitura restrita e verificada, sem executar comandos ou reaplicar teste, produz log JSON que um agente Wazuh poderá coletar. Regras/XML são exemplos revisáveis, sem implantação automática; validar com wazuh-logtest e laboratório autorizado quando disponíveis.
- UI e relatórios descrevem binding, estado/configuração, coleta e limitações; não afirmar Wazuh conectado/detecção real só porque fixtures passaram. Demo mantém synthetic=true e não usa o conector real. Scheduler Linux permanece desabilitado.

## Fontes oficiais consultadas

- https://documentation.wazuh.com/current/user-manual/indexer-api/reference.html — autenticação e APIs de busca/scroll distintas da gestão.
- https://documentation.wazuh.com/current/user-manual/indexer-api/use-case.html — índices de alertas e Search.
- https://documentation.wazuh.com/current/user-manual/manager/event-logging.html — archives e indexação são opt-in próprios.
- https://documentation.wazuh.com/current/user-manual/manager/alert-management.html — limiar de alertas; não presumir todas as regras indexadas.
- https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/monitoring-log-files.html — coleta de logs, não receipt do executor como alerta.
- https://docs.opensearch.org/latest/api-reference/search-apis/search/ e https://docs.opensearch.org/latest/api-reference/search-apis/scroll/ — timeout, shards, cursor e permissões read/scroll/clear.

Sem novas dependências ou serviços pagos. Versões efetivas permanecem nos locks existentes. Testes de contrato não são integração Wazuh externa validada.
