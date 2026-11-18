# Sigma / pySigma

Fonte: [pySigma oficial](https://github.com/SigmaHQ/pySigma). AEGIS utiliza SigmaCollection.from_dicts da versão 2.0.1, após SafeLoader, limite de 64 KiB, complexidade limitada, profundidade máxima32 e bloqueio de âncoras/aliases. Um documento/regra por importação; UUID obrigatório. Tags `attack.tNNNN(.NNN)` precisam existir no catálogo.

Nova importação do mesmo UUID cria versão imutável; conteúdo idêntico é idempotente. UI apresenta YAML, técnicas, hash e comparação visual entre versão anterior/atual. A conversão offline limitada abaixo gera consultas para revisão; não executa consultas SIEM nem implanta regras. O snapshot de execução registra versões do inventário para contextualizar comparações; isso não significa que essas regras foram implantadas.

Sintaxe válida não comprova semântica, cobertura ou compatibilidade Wazuh. Validação de consulta no índice exige prova num laboratório autorizado, independente da geração offline. Associação revisada regra/teste é operacional como metadado de planejamento, com versões fixas, retirada e histórico. [Operação e API](../operations/rule-test-reviews.md). Análise estática parcial está disponível abaixo; semântica no índice e implantação continuam em entregas próprias.

## Gate físico de consulta — #87

`integrations/sigma_index.py` acrescenta o perfil `aegis-marker-keyword/1`.
Consulta somente GET raiz, `_mapping`, `_settings` e `_alias` de um índice diário
concreto `wazuh-alerts-4.x-AAAA.MM.DD`. Exige hashes previamente revisados de mapping
e settings completos, versão anunciada exata e ausência de aliases; não aprende
confiança da resposta. O hash de settings inclui UUID/versão de criação disponíveis.
A versão da API raiz pode ser mascarada pela compatibilidade Wazuh; não comprova
a versão da distribuição. HTTP403/404, TLS inválido e drift nunca liberam busca.

Campos utilizados e `agent.id` precisam ser keyword sem normalizer, script,
null_value, divisão por espaços ou truncamento abaixo do orçamento512; `timestamp`
precisa ser date indexado. Objetos disabled/nested, aliases de campo, runtime fields
e `_source` desabilitado são recusados. Não adapta silenciosamente texto analisado
ou subcampos. [Template oficial4.14.9](https://github.com/wazuh/wazuh/blob/v4.14.9/extensions/elasticsearch/7.x/wazuh-template.json)
é referência de revisão, nunca substituto do mapping físico.

Fixtures e TLS de loopback verificam o contrato; nenhum mapping de laboratório foi
consultado nesta etapa. Não há ativação no startup nem autorização de operação.

## Conversão offline isolada — #85, 18/11/2026

O [ADR0036](../architecture/decisions/0036-isolated-sigma-converter.md) resolve
o conflito de dependências sem alterar o parser2.0.1 da API: o conversor oficial
pySigma1.5.1/OpenSearch2.0.3/Elasticsearch2.1.1 usa venv/processo separados.
`make sigma-converter-setup` instala18pins com hashes e verifica a árvore completa;
o Dockerfile prepara `/opt/aegis-sigma-converter`. Nenhuma instalação acontece
durante requisição. Lock próprio `requirements-sigma-converter.lock`, auditado
separadamente; não mesclar esse lock aos locks da aplicação. Regeneração é revisão
explícita via `scripts/lock_dependencies.py --sigma-converter`, com conferência
do hash revisado no contrato antes de adoção. Ausência/drift falham fechado.

Perfil novo **aegis-marker-lucene/1**, política literal-boolean/1. Mantém o
logsource exato product=aegis/service=marker_observer e os caminhos próprios
do marcador, exceto artifact_bytes cujo tipo não foi validado. Não altera o
candidato wazuh-aegis-marker/1 ou seu hash. Só16seleções planas,8campos/seleção,
8strings/lista e512bytes/string; condição única até256caracteres/64tokens,
AND/OR/NOT e parênteses até8níveis. Modificadores/fieldref/keywords/selectors,
números/booleanos/null, curingas/backslash e metadados executáveis/desconhecidos
são unsupported com motivo. Estimativa conservadora limita expansão da query
a8KiB antes do subprocesso; budgets YAML anteriores continuam obrigatórios.
Chaves duplicadas, merge YAML e chaves não textuais são recusadas antes do parser
Sigma, para não converter silenciosamente apenas o último valor carregado.

O processo recebe somente JSON inerte limitado, com ambiente limpo e Python-I/-B.
Classes oficiais fixas, sem desserializar pipeline; invariância da detection
após rename.3sCPU/512MiB de espaço virtual/5s de prazo, no máximo2processos
simultâneos por processo da API. Audit hook rejeita cache/discovery/validators/data,
rede, criação de processos e mutação de arquivos antes de importar o backend.
DiskCache5.6.3 ainda consta da auditoria; não é importado ou usado pelo conversor.

API autenticada, viewer permitido, somente leitura:

- GET `/api/v1/sigma/query-profiles`: contrato/perfil/pins/hashes revisados;
  configured indica presença do interpretador, não sucesso de uma conversão.60/min.
- GET `/api/v1/rules/{rule_id}/versions/{version_id}/query?profile_id=aegis-marker-lucene%2F1`:
  versão exata,30/min/usuário; ownership/SHA conferidos antes do efeito. Perfil
  desconhecido404, integridade409, conteúdo inválido/budget422, indisponibilidade/
  drift/timeout/capacidade503 e limite429. Unsupported retorna200 com motivo e
  query/hash null, sem iniciar processo.

Resposta converted contém query, hash dos bytes UTF-8, versão/regra/hash, perfil,
backend/core, pipeline, hash do lock/implementação/contrato e SHA do documento.
siem_queried/deployment_performed/index_mapping_verified=false. Não persiste cache
nem altera regras, versões, scopes, aprovações, cobertura, evidências ou veredictos.
O backend escapa strings e preserva a expressão no subconjunto revisado; isso não
comprova tipos/analisadores/subcampos, correspondência ou eficácia no índice real.

As seções históricas de preparação/análise/prévia abaixo continuam diagnosticando
o parser da aplicação e o candidato original, onde can_convert=false. Esse
diagnóstico não é a disponibilidade do novo processo de conversão isolado.

Dependência pySigma é LGPL-2.1-only e permanece biblioteca separada, sem código copiado/modificado. Regras importadas mantêm licença de seus autores. DiskCache 5.6.3 é uma dependência transitiva com advisory conhecido sem patch; AEGIS não importa nem usa seu caminho de cache. A auditoria mantém a ocorrência visível e testa essa premissa; habilitar plugins/cache exige nova revisão.

## Análise estática de versões

Em **Regras → Análise estática**, selecione uma versão salva. A API
`GET /api/v1/rules/{rule_id}/versions/{version_id}/analysis` exige sessão,
aceita viewer e limita a 60 consultas por usuário/minuto (Redis; indisponibilidade
retorna503). Não recebe comandos, destinos, plugins, consultas ou pipelines.
Confere SHA-256 antes do parser; divergência retorna409. Conteúdo legado inválido
ou além do orçamento de análise retorna422, sem exceção bruta.

Analisador `sigma-static/1`, pySigma2.0.1: resolve condições com o parser oficial
e aplica cinco checks AEGIS explícitos: referências inválidas, seleções não
referenciadas, campo com all sem contains, curingas consecutivos e caracteres
de controle. Os últimos checks sugerem revisão; valores intencionais podem gerar
achados. Não são uma avaliação completa da semântica. Se uma condição não for
resolvida, o check de seleção não referenciada é marcado como não executado.
Limites adicionais: 32 condições, 2048 caracteres por condição, 128 seleções;
limites YAML de importação continuam aplicáveis. Antes do parser, importação e
análise compartilham preflight: até 6 modificadores sem repetição por campo,
estimativa conservadora máxima de 256 KiB por valor expandido, 1 MiB total e
4096 variantes. Encodings, base64offset e windash entram na estimativa; não é
medida de RAM total. Regras legítimas com cadeias maiores podem ser recusadas. Presença de filter,
correlation ou action é recusada antes do dispatch; detection precisa ser objeto,
pois esta versão só aceita regras individuais.
Versões antigas fora dessa política permanecem armazenadas, mas análise retorna422.
A política depende dos modificadores da versão pySigma fixada e exige revisão
antes de upgrades; não executar payload grande para testar o limite.

Resposta identifica rule_id, rule_version_id, número/hash da versão, versões do
analisador/pySigma, checks executados/omitidos, fatos e achados ordenados.
Fatos são campos **declarados**, logsource, seleções e condições; não representam
campos disponíveis no SIEM. Prioridade LOW/HIGH refere-se à revisão da regra,
não a risco de negócio. `no_findings_in_selected_checks` não significa regra
correta, compatível ou eficaz. Conteúdo histórico não é alterado; uma análise é
calculada sob a versão atual identificada do analisador, sem persistir cache nem
reescrever escopos, vínculos, aprovações, relatórios ou veredictos.

A UI consulta a versão exata e confere identidade/hash da resposta. Consulta
pendente de outra versão não pode aparecer sob a seleção atual. Falha de consulta
não é apresentada como análise sem achados.

### Conversão e compatibilidade

Reavaliação da entrega#16 em **18/11/2026**: pesquisa#84 concluída, conversão#85
e UI#86 bloqueadas. Os wheels oficiais OpenSearch2.0.3/Elasticsearch2.1.1 ainda
exigem core<2; nem manter2.0.1 nem atualizar para2.1.0 resolve o par. O controle
1.5.1 resolve dependências, mas é downgrade vedado, não uma opção de instalação.
Runtime, locks e snapshot histórico22/10 foram preservados. Nenhum backend
instalado, consulta gerada ou implantação realizada. Ver
[matriz/provas](../evidence/sigma-compatibility-2026-11-18/README.md),
[ADR0035](../architecture/decisions/0035-sigma-published-backend-compatibility.md)
e [checkpoint de retomada](../development/sigma-conversion-checkpoint.md).

Esse foi o bloqueio inicial da sessão. A retomada solicitada posteriormente
adotou o ADR0036 e o conversor isolado descrito acima; a matriz histórica e os
metadados publicados permanecem corretos, sem reescrever as provas anteriores.

Estado da análise estática: `not_configured`, backend/pipeline de conversão null,
conversão/implantação false. A prévia de campos abaixo é uma etapa independente.
A [documentação oficial de backends](https://sigmahq.io/docs/digging-deeper/backends)
lista OpenSearch; [pipelines](https://sigmahq.io/docs/digging-deeper/pipelines)
tratam mapeamentos de campos/fontes. Isso não comprova compatibilidade com o schema
Wazuh, emissão de regra XML ou implantação no manager. Nenhum backend foi instalado
ou executado nesta etapa. Revisão de um pipeline e validação de sua saída são
pré-requisitos futuros; execução contra laboratório exige seu escopo autorizado.

Decisão e descoberta de importação transitiva:
[ADR0008](../architecture/decisions/0008-sigma-static-analysis.md). Não importar
`sigma.validators.core`: seu inicializador descobre módulos e carrega loaders de
dados com DiskCache. AEGIS usa diretamente o parser/modelo e checks locais, sem
copiar validadores upstream ou enfraquecer a regressão de ausência de DiskCache.

## Preparação de conversão e campos candidatos

Em **Regras → Preparação de conversão**, selecione versão e perfil. Este recurso
é um diagnóstico offline operacional; não gera consultas nem implanta regras.
Campos mapeados não equivalem a conversão disponível. A análise estática anterior
continua independente, com compatibility=not_configured.

A verificação em2026-10-22 encontrou os wheels oficiais OpenSearch2.0.3 e
Elasticsearch2.1.1 declarando pySigma<2.0.0, enquanto ÆGIS usa2.0.1. Snapshot
normalizado em `fixtures/sigma/backend-metadata.json`, após conferir SHA-256 do
wheel e ler METADATA sem instalar/executar código. Os requisitos publicados do
wheel OpenSearch diferem do pyproject atual do repositório; o diagnóstico usa o
wheel efetivamente publicado. Licença declarada de ambos: LGPL-3.0-only; nenhum
backend ou código deles é distribuído pelo ÆGIS neste estágio.

Fontes oficiais das versões revisadas:
[OpenSearch2.0.3](https://pypi.org/pypi/pysigma-backend-opensearch/2.0.3/json) e
[Elasticsearch2.1.1](https://pypi.org/pypi/pysigma-backend-elasticsearch/2.1.1/json).
Não forçar instalação ignorando dependências nem fazer downgrade do parser.
`packaging` já estava travado em26.3 e passa a dependência direta para interpretar
requisitos; nenhum pacote adicional instalado.

O diagnóstico compara requisitos do snapshot às versões realmente instaladas,
sem importar backends ou acessar PyPI durante a consulta. Exibe a data/hash do
snapshot, versões, fontes e requisitos não atendidos. Mudança do ambiente ou de
metadados revisados pode mudar esse diagnóstico; ele não é evidência histórica
imutável de detecção. Backend ausente ou versão diferente da revisada são
bloqueios explícitos. Metadados ausentes/malformados retornam503.

O único perfil é **wazuh-aegis-marker/1**, candidato local versionado por hash:
logsource product=aegis/service=marker_observer e caminhos próprios do schema
aegis-json/1, como AegisSchema→data.aegis.schema e
AegisObservation→data.aegis.observation. A associação é sustentada pelos caminhos
presentes no [alerta registrado](../evidence/wazuh-2026-10-22/alert.json), sem nova
consulta ao Indexer. Nenhum Image/CommandLine ou evento Windows é remapeado para
full_log. Logsource adicional/desconhecido e campos ausentes são sinalizados.

O alerta _source não registra tipos/analisadores/subcampos do índice; mapping
físico permanece **não verificado**. artifact_bytes apareceu como string no
JSON decodificado, o que não permite supor campo numérico no índice. Valores,
modificadores, equivalência de condição e disponibilidade atual não são validados
pelo mapeamento de nomes. Referências fieldref recebem tratamento pendente
explícito e impedem indicar mapeamento completo, inclusive quando o nome tem
caminho candidato. Palavras-chave sem destino e achados estáticos também
sinalizam pendências. Não confundir este perfil com ProcessingPipeline executado.

`can_convert`, `conversion_performed` e `deployment_performed` permanecem false,
mesmo com campos mapeados e requisitos declarados hipoteticamente atendidos:
pipeline executável e verificação do índice continuam pendentes. Não há botão
Converter/Implantar decorativo. A UI confere regra/versão/hash e perfil/hash.

API, somente leitura autenticada, inclusive viewer:

- GET `/api/v1/sigma/conversion-profiles`: perfis candidatos e diagnóstico de
  pacotes,60 consultas por usuário/minuto.
- GET `/api/v1/rules/{rule_id}/versions/{version_id}/conversion-readiness?profile_id=wazuh-aegis-marker%2F1`:
  versão exata,30/minuto; perfil ausente404, hash divergente409, conteúdo fora
  da política422 e metadados indisponíveis503. Nenhum destino/índice/plugin/
  pipeline/consulta é recebido pela API.

## Prévia de transformação de campos

Em **Regras → Preparação de conversão → Gerar prévia de campos**, a aplicação
aplica um `ProcessingPipeline` oficial pySigma2.0.1 com uma única
`FieldMappingTransformation` fixa, em modelo novo na memória. Exibe `detection`
normalizada antes/depois, preservando valores e condição sob rename. Não produz
regra importável, query Lucene, consulta ao SIEM ou alteração na versão salva.

Perfil candidato wazuh-aegis-marker/1 e hash antigos permanecem iguais. A etapa
independente `sigma-mapping-preview/1` tem política/versão/hash próprios; não é o
pipeline completo de conversão. A reconsulta PyPI de2026-10-26 verificou hashes de
wheels/METADATA inalterados: OpenSearch2.0.3 e Elasticsearch2.1.1 ainda exigem
core<2. Nenhum backend foi instalado ou parser reduzido para contornar constraints.

O subconjunto revisado aceita logsource exato do marcador, uma condição até2048
caracteres, até32seleções planas/32campos por seleção. Valores são strings literais
não vazias de até1024bytes ou listas de até16strings. Modificadores, fieldref,
keywords, nesting, wildcards/backslash nos valores e campos sem destino são
recusados antes do parser/pipeline. Custom/pipeline/vars ou metadados desconhecidos
também bloqueiam a prévia. Orçamento YAML anterior ao parser continua obrigatório;
análise estática com achados/checks omitidos exige revisão. Não há remoção silenciosa
de condições nem mapeamento genérico para full_log.

O código instancia somente classes fixas revisadas; não aceita/carrega YAML de
pipeline, templates, plugins, vars, fontes externas ou finalizers. O módulo upstream
registra classes de transformações externas ao importar; isso não as instancia.
Teste em processo novo recusa cache/backend/rede/processo/gravação durante import
e transformação real, inclusive com a flag ambiental de vars habilitada.

GET `/api/v1/rules/{id}/versions/{version_id}/mapping-preview?profile_id=wazuh-aegis-marker%2F1`:
sessão de qualquer papel,30/min/usuário, mesma guarda de ownership/SHA da versão.
Perfil ausente404, integridade409, budget/legado inválido422, core/invariante não
revisados503; falha do Redis também503. Input fora do subconjunto retorna200 com
status=unsupported/blockers e before/after null, sem rodar o pipeline.

Resposta contém IDs/versões/hashes do conteúdo/perfil/pipeline e SHA do documento
inteiro, exceto o próprio campo. `previewed` é sucesso apenas do rename; todos os
flags can_convert/query_generated/siem_queried/deployment_performed e
index_mapping_verified permanecem false. Nenhuma auditoria de escrita, scope,
evidência, cobertura ou veredicto é modificado. Hash não é assinatura externa.

A UI confere regra/versão/hash/perfil/contrato e não mostra resposta atrasada ou
sucesso cacheado depois de erro. Contexto divergente exige nova consulta. Erros e
unsupported não aparecem como transformação bem-sucedida. Valores são renderizados
como texto React, sem HTML do input. [ADR0017](../architecture/decisions/0017-sigma-mapping-preview.md).

Exemplo autoral importável: `fixtures/sigma/aegis-marker-candidate.yml`, somente
planejamento, não implantado, sem técnica ATT&CK artificial. Criar um perfil
futuro exige revisão de código/proveniência, atualização controlada de metadados,
backend oficialmente compatível e testes de saída/escopo. Operação sobre SIEM
requer infraestrutura e autorização próprias. Ver [ADR0009](../architecture/decisions/0009-sigma-conversion-readiness.md).
