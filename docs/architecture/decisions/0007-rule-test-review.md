# ADR 0007 — Associações revisadas entre regras Sigma e testes

Status: aceito para implementação. Data: 2026-10-22.

O inventário Sigma possui versões imutáveis, mas não permite registrar qual teste
foi escolhido para avaliar uma regra. Acrescentar essa relação ao planejamento
sem confundi-la com implantação, execução ou evidência de detecção.

- Uma associação fixa RuleVersion (incluindo hash), TestDefinition.version,
  justificativa e responsável. Apenas operador/admin pode registrar ou retirar;
  viewer consulta. A revisão é humana: não inferir compatibilidade semântica por
  tags ATT&CK. Testes sem técnica também podem ser associados com justificativa.
- Um vínculo ativo por par regra/teste, garantido por índice parcial PostgreSQL.
  Substituição exige o ID anterior e cria outro registro; encerramento preserva
  o original. Lock na regra serializa importação/revisão/retirada. Não atualizar
  justificativa, versão ou autor históricos. Runtime permite somente encerrar
  registros, sem DELETE e sem UPDATE das colunas imutáveis.
- Publicar nova versão Sigma ou mudar a versão do teste sinaliza revisão
  necessária; nunca promover automaticamente o vínculo à nova versão. Confirmação
  do hash/versão e controle otimista recusam formulários obsoletos.
- Novas solicitações e planos capturam vínculos ativos ordenados no scope/hash.
  Aprovação e início mantêm a revalidação existente. Inventário rule_versions
  continua conservador: qualquer nova versão cadastrada altera o escopo atual.
  A inclusão do novo campo invalida aprovações/planos anteriores; criar e aprovar
  novo escopo. Runs/evidências/relatórios já armazenados nunca são reescritos.
- Comparação explica mudanças de versões, vínculos, testes e ambiente usando
  apenas snapshots históricos. Ausência do campo nos scopes antigos significa
  contexto não registrado, não ausência comprovada de associações.
- Nenhum vínculo altera expected_rule, binding Wazuh, validação ou indicadores
  de detecção. Mostrar vínculos planejados na matriz separadamente de regras
  operacionais. Não implantar Sigma, converter consultas nem repetir o ensaio
  Wazuh encerrado. Não adicionar dependências.

Validar migração populada, unicidade/concorrência, RBAC/CSRF, revisão obsoleta,
preservação de escopo/evidências e comparação, UI e um fluxo Demo no navegador.
As APIs e padrões PostgreSQL/SQLAlchemy existentes dos ADRs 0001/0002 são mantidos.
