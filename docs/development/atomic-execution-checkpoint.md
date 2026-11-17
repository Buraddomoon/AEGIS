# Checkpoint #14 — Atomic de permissões

Escopo exclusivo: #14 e filhos #78/#79/#80. Dependências #13 e #5 concluídas;
suas autorizações operacionais anteriores estão consumidas.

- #78 concluída em `270e48d`: fonte/licença/GUID/hash fixados e dois testes de
  inspeção. [Dossiê](../integrations/atomic-permissions-review.md).
- #79 implementada em `7e3dde5`: adaptação própria de T1222.002,0400→0600 em
  arquivo gerado pelo runner; perfil de identidade/revisão próprio, mTLS,
  aprovação segregada, estado/worker/dispatch/recibo/cleanup existentes.
  CI integral44168295232 SUCCESS na fontee2e0277:3575Python/9skips opcionais,
  98React; quatro partições e React conferidos. #79 atendida por software/fixtures,
  sem validação nativa ou implantação. Falha inicial preservada no relatório.
- #80 retomada especificamente: imagens runner/aplicação construídas e verificadas,
  receita/PKI/proposta91de0d6f preparadas sem startup. Falta **autorização específica**
  da [proposta concreta](../../labs/linux/ATOMIC80-REQUEST-2026-11-17.md) para
  os recursos novos e uma campanha; nenhuma autorização/tentativa registrada.
  CI final da preparação4759805 em44202869465 em andamento. Pai #14 aberto.

[Provas e distinção entre testes/ensaio/implantação](../evidence/atomic-execution-2026-11-17/README.md).
[Operação e pré-requisitos](../operations/atomic-permissions.md).
[Provas da retomada #80](../evidence/atomic-execution-2026-11-17/PREPARATION-80.md).
Metadados Atomic continuam não executáveis. O novo perfil não herda binding,
allowlist ou journal dos Labs históricos. Não executar shell/YAML upstream,
iniciar Lab, migrar original ou reutilizar autorização a partir deste checkpoint.
Não avançar para outra entrega.
