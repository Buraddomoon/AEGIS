# ADR 0009 — Preparação verificável para conversão Sigma

Data: 2026-10-22. Status: contrato para implementação.

A inspeção oficial encontrou pySigma2.0.1 no ÆGIS e backends publicados
OpenSearch2.0.3/Elasticsearch2.1.1 com Requires-Dist pySigma<2.0.0. Não instalar
com --no-deps, ignorar constraints, copiar backend ou reduzir a versão do parser.
Consulta convertida e implantação permanecem indisponíveis.

Entregar diagnóstico somente leitura por versão/hash, perfil fixo e snapshot
versionado dos metadados oficiais dos wheels, sem importar ou instalar backends.
Verificar requirements com packaging e versões realmente instaladas. Capturar
Requires-Dist do wheel verificado por SHA-256, pois pyproject do repositório e
metadados publicados podem divergir. Expor versão/data/fonte do snapshot; não
prometer consulta em tempo real ao catálogo PyPI.

Perfil inicial `wazuh-aegis-marker/1`: somente logsource product=aegis e
service=marker_observer, campos próprios explicitamente mapeados aos caminhos
registrados no alerta aegis-json/1. Testes genéricos de processo/Windows não
recebem mapeamento inventado para full_log. Perfil é candidato local, não pipeline
Sigma executado. Documento _source comprova presença/tipo do valor observado,
não mapping físico/analisadores/keyword do índice. Essa validação é pendente.

GET autenticado `/sigma/conversion-profiles` lista perfil e compatibilidade;
GET `/rules/{rule_id}/versions/{version_id}/conversion-readiness?profile_id=...`
valida hash, inspeciona campos/condições, mostra mapeamentos/ausências e bloqueios
explicáveis. Rate limit por usuário. Não aceitar YAML de pipeline, destinos,
plugins, índices ou consultas arbitrárias. Sem escrita ou efeito no SIEM.

UI seleciona versão histórica, exibe contexto exato e recusa identidade/hash ou
perfil divergentes. Não criar botão converter/implantar sem capacidade real.
Não alterar histórico, scopes aprovados, evidências ou classificações. Sem novo
ensaio real, serviços ou migração. packaging passa a ser dependência direta,
na mesma versão já travada transitivamente.

Fontes oficiais consultadas:
- https://pypi.org/pypi/pysigma-backend-opensearch/2.0.3/json
- https://pypi.org/pypi/pysigma-backend-elasticsearch/2.1.1/json
- https://github.com/SigmaHQ/pySigma-backend-opensearch
- https://sigmahq.io/docs/digging-deeper/pipelines

Validar requisitos instalados, constraints conflitantes, ausência de backend,
campos não mapeados, logsource incompatível, keyword selections, condições não
resolvidas, versões históricas, RBAC, integridade, limites e comportamento offline.
Nenhum resultado desta preparação significa conversão validada.
