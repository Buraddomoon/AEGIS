# ADR 0017 — Prévia restrita de transformação Sigma

Data: 2026-10-26. Status: implementado; validado por testes de contrato/API/UI e Firefox Demo.

A consulta atual aos metadados PyPI confirmou pySigma2.0.1, OpenSearch2.0.3 e
Elasticsearch2.1.1; ambos os backends ainda exigem pySigma<2. O bloqueio do
ADR0009 permanece: não instalar ignorando constraints, reduzir o parser da app,
criar backend próprio para simular suporte ou declarar conversão disponível.

Implementar uma etapa independente de backend: prévia somente leitura dos campos
transformados por `ProcessingPipeline` e `FieldMappingTransformation` oficiais do
core2.0.1 já instalado. Construção programática fixa, somente um item de rename
um-para-um baseado no perfil candidato wazuh-aegis-marker/1. Não ler/carregar YAML
de pipeline, vars, estado, templates, fontes externas, plugins ou finalizers.
O perfil anterior e seu hash permanecem inalterados; a prévia tem versão/hash próprios.

Aceitar apenas regras individuais com logsource exato do marcador, condição única
até2048caracteres, até32seleções planas/32campos por seleção e valores string
literais até1024bytes (ou listas de até16strings). Sem modificadores, fieldref,
keywords, estruturas aninhadas, wildcards/backslash, custom/pipeline/vars ou campos
sem destino. Orçamento YAML/preflight anterior ao parser continua obrigatório.
Análise estática com achados/checks omitidos bloqueia a prévia. Restringir o conjunto
suportado explicitamente; não reinterpretar ou remover partes sem avisar.

Transformar modelo novo apenas em memória, nunca a RuleVersion persistida. Retornar
antes/depois da detection normalizada, condição preservada, versões/hashes do input,
perfil/pipeline e documento. Conferir invariância dos valores/estrutura/condição sob
rename; um desvio do upstream deve falhar fechado. Prévia não é regra importável,
consulta Lucene, validação semântica completa ou aprovação de compatibilidade.

GET autenticado por versão exata `/rules/{id}/versions/{version_id}/mapping-preview`,
viewer permitido,30/min/usuário, mesma guarda SHA/ownership. Perfil desconhecido404,
integridade409, input fora do budget422 e versão core não revisada503. Subconjunto
não suportado retorna diagnóstico sem before/after nem execução do pipeline.
UI oferece ação real e mostra dados somente para regra/versão/hash/perfil corretos;
loading/erro/refetch divergente não podem preservar uma prévia aparentemente válida.

`can_convert=false`, query_generated/siem_queried/deployment_performed=false e
index_mapping_verified=false em todas as respostas. O blocker de pipeline completo
de conversão do ADR0009 continua verdadeiro; rename sozinho não o implementa.
Nenhuma migração, dependência, nova simulação real ou acesso a Wazuh.

Testar transformação oficial real, AND/OR/NOT, listas/identidades e histórico,
recusa antes do parser/pipeline, limites, versão drift, RBAC/CSRF de importações,
rate limit, integridade, ausência de mutação e processo novo com audit hook
recusando cache, backend, rede, subprocesso e gravações. UI: erro/unsupported,
versão/perfil divergentes e resposta atrasada. Firefox E2E somente Demo deve
inspecionar prévia e preservar relatório antigo, sem executar consulta.

Fontes oficiais consultadas:

- [PyPI pySigma2.0.1](https://pypi.org/pypi/pysigma/2.0.1/json)
- [PyPI OpenSearch2.0.3](https://pypi.org/pypi/pysigma-backend-opensearch/2.0.3/json)
- [PyPI Elasticsearch2.1.1](https://pypi.org/pypi/pysigma-backend-elasticsearch/2.1.1/json)
- [Processing pipelines](https://sigmahq.io/docs/digging-deeper/pipelines)
- Código instalado, fixado por hash, de sigma.processing.pipeline e
  sigma.processing.transformations.fields foi inspecionado antes da implementação.
  O módulo registra classes externas; só as classes fixas acima podem ser instanciadas.
