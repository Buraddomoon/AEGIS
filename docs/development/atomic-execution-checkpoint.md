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
- #80 **bloqueada**: faltam imagem/ambiente nativo revisados, pacote concreto
  de uma tentativa e autorização específica. Pai #14 permanece aberto.

[Provas e distinção entre testes/ensaio/implantação](../evidence/atomic-execution-2026-11-17/README.md).
[Operação e pré-requisitos](../operations/atomic-permissions.md).
Metadados Atomic continuam não executáveis. O novo perfil não herda binding,
allowlist ou journal dos Labs históricos. Não executar shell/YAML upstream,
iniciar Lab, migrar original ou reutilizar autorização a partir deste checkpoint.
Não avançar para outra entrega.
