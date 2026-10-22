# Revisão da análise estática Sigma — 2026-10-22

Escopo: análise de versões salvas, API/UI e entrada compartilhada de importação.
Revisão especializada somente leitura e testes pelo agente principal. Nenhum
payload de expansão perigosa foi executado; nenhum laboratório real iniciado.

Achados e correções:

1. `sigma.validators.core` descobre e importa todos os validadores, inclusive
   loaders de dados com DiskCache. Verificado por inspeção e regressão de import.
   Usar parser/modelo oficiais e checks AEGIS locais explícitos. Não desativar a
   regressão de ausência de DiskCache ou ocultar seu advisory transitivo.
2. Modificadores são aplicados durante `SigmaCollection.from_dicts`, antes dos
   budgets posteriores de análise. Cadeias de encoding podem ampliar valores.
   `safe_sigma_document` agora verifica cadeias e orçamento conservador antes do
   parser, tanto na importação quanto na análise. Profundidade YAML é limitada
   antes de construir a árvore Python. Detalhes no [guia Sigma](../integrations/sigma.md).
3. `SigmaCollection` também despacha documentos `filter`, aplicando modificadores
   dentro deles. Rejeitar filter/correlation/action e detection não objeto antes
   do dispatch, porque somente regras individuais são suportadas neste marco.
   Testes incluem filtro com cadeia repetida, mas substituem o parser por função
   proibida; a cadeia nunca é expandida.

Revisão final estática não identificou bloqueador concreto restante nesses deltas.
Testes específicos comprovam recusa anterior ao parser, limites por valor/total/
variantes, encoding normal aceito e condições resolvidas pela árvore oficial.
Processo novo com audit hook recusa importação DiskCache, conexões e gravações.
API verifica sessão, papel de consulta, rate limit e integridade do conteúdo.
UI confere rule/version/hash, trata erro e não mistura resposta atrasada com outra
versão. Histórico e classificações continuam independentes desta análise.

Limites: budget estima bytes/variantes transformados e não mede RAM total do
interpretador. Política conservadora pode recusar regras legítimas complexas.
As estimativas dependem do pySigma2.0.1 fixado e precisam de revisão em upgrades.
Checks locais não validam semântica completa, mapeamento, eficácia ou implantação.
Não há backend/pipeline de conversão configurado. Zero achados significa somente
zero achados nos checks executados. Resultados e comandos em [PROGRESS](../PROGRESS.md).
