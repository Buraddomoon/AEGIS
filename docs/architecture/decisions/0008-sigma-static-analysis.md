# ADR 0008 — Análise estática versionada de Sigma

Data: 2026-10-22. Status: contrato aprovado para implementação.

Oferecer GET autenticado `/rules/{rule_id}/versions/{version_id}/analysis` para
analisar uma versão imutável, sem executar consultas, modificar aprovações ou
implantar regras. Resposta identifica hash, versão do analisador e pySigma.
Não criar tabela/cache: análise pura e determinística sobre conteúdo salvo.

Usar o modelo e parser oficiais pySigma2.0.1 com checks próprios explícitos:
resolução de condições, seleção não referenciada, all sem contains, curingas
consecutivos e caracteres de controle. Não importar sigma.validators.core:
seu __init__ descobre todos os módulos e importa loaders MITRE/DiskCache, mesmo
quando só um validador é solicitado. Inspeção e teste revelaram essa dependência;
não enfraquecer a revisão existente do advisory para habilitar esse caminho.
Não copiar validadores upstream; checks locais são parciais e identificados AEGIS. Severidade
do validador é prioridade de revisão da regra, não risco de negócio. Retornar
achados normalizados ordenados e detalhes mínimos (campo/seleção), sem objetos
Python, exceções brutas, plugins dinâmicos, cache DiskCache ou acesso à rede.

Exibir fatos do conteúdo (logsource, condições e campos declarados). Achado zero
significa apenas ausência nos checks listados. Não avaliar correspondência a
telemetria, semântica completa, custo da consulta ou comportamento real de teste.
UI permite selecionar versões anteriores e conserva identificador/hash ao renderizar.

Compatibilidade de conversão permanece `not_configured`: não há backend/pipeline
instalado/aprovado. O backend OpenSearch listado oficialmente não demonstra
compatibilidade com schema Wazuh nem implantação no manager. Não instalar plugins
ou anunciar suporte sem pipeline e validação próprios. Nenhuma dependência nova,
migração ou ensaio real é necessário para esta etapa.

Fontes oficiais consultadas em 2026-10-22:
- [Validadores pySigma](https://sigmahq-pysigma.readthedocs.io/en/stable/guides/rule_validation.html)
- [Backends Sigma](https://sigmahq.io/docs/digging-deeper/backends)
- [Pipelines e mapeamento](https://sigmahq.io/docs/digging-deeper/pipelines)

Validar regras com achados, condições inválidas, nested/list/keyword detections,
ordenação, versões históricas, RBAC, entradas legadas inválidas, hash e ausência
de mutação de vínculos/evidências/escopos. UI deve tratar loading/erro/vazio e
seleção histórica; fluxo de navegador apenas Demo. Limites YAML existentes mantidos.
