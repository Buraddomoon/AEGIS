# Wazuh Indexer — adaptador somente leitura

Referência consultada: [API do Indexer](https://documentation.wazuh.com/current/user-manual/indexer-api/reference.html), documentação Wazuh current 4.14 durante pesquisa. Indexer pesquisa índices de alertas; Server API administra agentes/configuração. O adapter implementa a primeira e não consulta alertas pela API de gestão.

Implementado: conexão HTTPS com validação de CA, Basic Auth, IP de destino explicitamente fixado no ambiente, hostname original em TLS SNI e Host, sem proxy de ambiente nem redirects; consulta por agente, marcador e janela UTC; paginação scroll limitada a 25 páginas de 200 hits, liberação do cursor, resposta limitada a 8 MB por requisição; preservação de `_index`, `_id`, `_source`, rule.id e timestamps. Shards falhos, timeout, schema inválido e paginação truncada tornam coleta incompleta. Não há escrita de índice/documento ou gestão de agentes.

Variáveis opcionais: `WAZUH_URL=https://indexer.lab:9200`, `WAZUH_ALLOWED_IP=<IP autorizado>`, `WAZUH_USERNAME`, `WAZUH_PASSWORD`, `WAZUH_CA_BUNDLE`. Nunca preencher com alvo presumido autorizado. Somente administrador pode solicitar teste de conectividade; endpoint não aceita URL. Destinos loopback/link-local/multicast/unspecified, inclusive IPv4 mapeado, são rejeitados. IP privado explicitamente fixado é permitido para laboratório.

Compose repassa a configuração ao runtime. Para CA privada, crie override com volume somente leitura para caminho fixo. Crie usuário Indexer com leitura limitada aos índices necessários e permissões mínimas de busca/scroll. O GET `/` usado no teste requer acesso à informação básica da versão. Não usar conta admin genérica nem TLS desabilitado.

Padrão de alertas `wazuh-alerts-4.x-*`; archives é opcional no construtor. Sem índice de archives, ausência de alertas não fornece prova de telemetria. Schema inicial exige campos de marcador/identidade em `data.aegis` e `agent.id`; campo ausente não é preenchido a partir do contexto solicitado. Outras versões/schemas precisam de adapter/mapeamento explícito.

**Estado real:** testes `MockTransport` e fixture de contrato com identificadores fictícios passaram; nenhuma conexão externa foi estabelecida para esta entrega. A UI mostra desconectado ou configurado/não verificado. Um teste bem-sucedido informa apenas conectividade naquele instante, não detecção.

Antes de ligar execução real: mapear `Asset.external_id` (agent.id) à identidade interna de ativo; implementar polling até a janela de ingestão e prazo total de operação; validar logs/marcadores reais, relógios e índices; comprovar o ciclo num laboratório autorizado. O worker Demo não está conectado ao adapter Wazuh. Não há evidência de integração real end-to-end.
