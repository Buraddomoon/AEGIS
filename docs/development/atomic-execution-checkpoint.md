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
  receita/PKI/proposta202afac5 preparadas sem startup. Falta **autorização específica**
  da [proposta concreta](../../labs/linux/ATOMIC80-REQUEST-202afac5.md) para
  os recursos novos e uma campanha; nenhuma autorização/tentativa registrada.
  CI4759805 passou3614Python/9skips e98React; inspeção RO real de layout Docker
  levou à correção posterior c974380. CI final44205114457 SUCCESS:
  3615Python/9skips e98React, cinco jobs/logs conferidos, coleta3624.
  Proposta91de0d6f retirada sem autorização/efeito, preservada. a4335444 expirou
  às09:07:07SP de18/11; confirmação constatada às09:27:06SP, sem autorização ou
  tentativa. Novo pacote202afac5 verificado, até21:27:54SP de18/11, mesmas imagens/
  efeito/limites, novos UUIDs/PKI. Nova confirmação necessária; pai #14 aberto.

[Provas e distinção entre testes/ensaio/implantação](../evidence/atomic-execution-2026-11-17/README.md).
[Operação e pré-requisitos](../operations/atomic-permissions.md).
[Provas da retomada #80](../evidence/atomic-execution-2026-11-17/PREPARATION-80.md).
Metadados Atomic continuam não executáveis. O novo perfil não herda binding,
allowlist ou journal dos Labs históricos. Não executar shell/YAML upstream,
iniciar Lab, migrar original ou reutilizar autorização a partir deste checkpoint.
Não avançar para outra entrega.
