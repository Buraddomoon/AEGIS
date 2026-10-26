# Revisão local da prévia Sigma — 2026-10-26

Inspeção pelo agente responsável e testes executados; não é pentest independente.
Escopo: transformation module, endpoint por versão, UI e harness Demo. Não altera
contratos da engine, worker, catálogo, versões/regras ou resultados persistidos.

| Risco | Controle e evidência |
|---|---|
| Pipeline com execução/efeito externo | Instancia somente ProcessingItem/FieldMappingTransformation fixos; sem loaders/vars/templates/finalizers ou YAML de pipeline. Processo novo proíbe cache/backend, rede, subprocessos e gravações |
| Expansão antes de limites | safe_sigma_document anterior ao parser, seguido de subconjunto estrito antes de analyze/model; modificadores, fieldref, nesting e keywords recusados |
| Coerção ou semântica inventada | Strings literais e listas limitadas, sem tipos numéricos/bool/null, controles ou wildcards/backslash; rename um-para-um e invariância de valores/condição/estrutura |
| Novo parser/upstream altera comportamento | Core fixado 2.0.1 e checagem runtime; drift ou transformação divergente retorna 503 sem sucesso parcial |
| Confusão de versão ou contexto na UI | Regra/versão/hash/perfil/pipeline/flags conferidos; loading/erro primeiro e chave por contexto; testes de resposta atrasada/refetch |
| Alteração de evidências e aprovações | Modelo novo só em memória; endpoint GET com autorização e rate limit; histórico/auditoria/cobertura e relatório antigo conferidos inalterados |
| Resposta/legado inválido expõe dados | Guarda SHA/ownership, erros estáticos 422/503; unsupported sem before/after; entradas não são ecoadas em mensagens de erro |
| Confusão entre prévia e detecção | Todos os flags de query/consulta/conversão/implantação/mapping físico false; backend continua incompatível e nenhum veredicto é modificado |

O upstream registra classes de transformações externas no import; a aplicação
não usa descoberta ou instancia essas classes. A prova com audit hook cobre o
caminho fixo revisado, não representa sandbox contra código arbitrário ou root.
A flag ambiental de execução de vars foi habilitada no teste e não torna o
pipeline fixo um carregador de vars. Não a habilitar no serviço da aplicação.

A transformação opera apenas sobre detection normalizada, não exporta uma regra
importável nem valida a semântica de condições no índice. Metadados da regra não
são transformados. Igualdade de strings no modelo não define keyword/analyzer/case
sensitivity do Wazuh. SHA é integridade do documento, não assinatura externa.

Não instalado backend incompatível nem reduzido o parser. Reconsulta oficial
confirmou hashes dos wheels/METADATA iguais ao snapshot anterior; OpenSearch 2.0.3 /
Elasticsearch 2.1.1 ainda exigem core<2. Sem dependência/migração nova. Advisory
DiskCache conhecido permanece visível, sem uso do cache nesse caminho, e não há
alegação de ausência de vulnerabilidades. Não há consulta a SIEM ou novo ensaio real.

[ADR0017](../architecture/decisions/0017-sigma-mapping-preview.md) ·
[Testes e validação](../evidence/sigma-mapping-2026-10-26/README.md).

Revisão especializada adicional somente leitura de 283c544: nenhum bloqueador
concreto encontrado em rename/invariância, endpoint de versão/hash, UI ou imports
fixos. O revisor não executou testes/serviços/rede/SIEM nem leu segredos. Conclusão
limitada à inspeção estática; resultados executados acima foram verificados pelo
agente responsável.
