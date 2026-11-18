# Validação Sigma em telemetria — #17

18/11/2026. Escopo #87 → #88 → #89. Dependências #16 e #7 CLOSED.
**Preparação local entregue; aceite nativo bloqueado. Pai e filhos permanecem
abertos**, sem declarar concluído o que depende de autorização/ambiente.

- `66bf13d`: gate físico read-only, perfil keyword fechado; mapping/settings/
  aliases/versão e campos usados precisam coincidir com revisão prévia.
- `f8e20ee`: API administrativa de consulta gerada por versão/hash; escopo privado
  temporário, índice/agente/período fixos, limites, origem/completude e cleanup.
  Sem query livre, persistência/reclassificação histórica ou implantação de regra.
- 193testes locais pertinentes passaram com PostgreSQL/Redis15 em sequência;
  lint completo aprovado.6testes de registro histórico e checagem positiva/negativa
  sobre alerta salvo da #59 foram offline, sem executar Lucene/Indexer.
- CI finalf8e20ee44386130666 **SUCCESS**: quatro grupos Python3843passed/9skips
  existentes e115React, todos conferidos. CI anterior66bf13d também passou,
  com3809Python/9skips; não somar as duas rodadas. Demo anteriorb8 ativo preservado.

[Provas, hashes, falhas intermediárias e limites](../evidence/sigma-validation-2026-11-18/README.md).
[Contrato da API e plano da #89](../operations/sigma-query-validation.md).

Próxima operação depende de autorização específica para metadata e busca sobre
alerta existente, snapshot físico/ACL revisados e pacote novo com encerramento.
As autorizações da #59/#63 estão consumidas. Nenhum arquivo ativo foi preparado,
laboratório iniciado ou consulta externa executada. Demo/originais/PKI/qasrc e
evidências preservados. Não repetir ensaios históricos nem avançar para outra
entrega; **parar no bloqueio registrado**.
