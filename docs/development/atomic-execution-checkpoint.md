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
- #80 validada em ensaio nativo autorizado em18/11, pacote202afac5 consumido:
  run `a9dc99b1-921f-4d94-be1f-70525c89fb4a`, um efeito43bytes/0400→0600,
  **COMPLETED/INCONCLUSIVE/CLEANED**, synthetic=false. Aprovação segregada/mTLS,
  dispatch/recibo/cleanup e JSON/HTML da mesma run conferidos. Sem SIEM/regra
  defensiva, nenhuma alegação DETECTED/eficácia. Lab revogado, duas contas próprias
  inativas/zero sessões, zero containers/redes próprios; três volumes retidos sem
  consumidores. [Provas nativas](../evidence/atomic-execution-2026-11-18/VERIFIED-80.md).
  CI final da fonte44205114457 SUCCESS:3615Python/9skips e98React; sem mudança
  executável durante a execução. Consolidação posterior somente Markdown.
  Pacote91de0d6f retirado e a4335444 expirada preservados sem tentativa.
  Autorização202afac5 consumida, sem replay ou operação contínua.

A #80 está atendida; pai #14 permanece aberto para aceite conjunto. Esta sessão
não implementou irmãs ou outra feature. Não iniciar novo laboratório/ensaio.

[Provas e distinção entre testes/ensaio/implantação](../evidence/atomic-execution-2026-11-17/README.md).
[Operação e pré-requisitos](../operations/atomic-permissions.md).
[Provas da retomada #80](../evidence/atomic-execution-2026-11-17/PREPARATION-80.md).
Metadados Atomic continuam não executáveis. O novo perfil não herda binding,
allowlist ou journal dos Labs históricos. Não executar shell/YAML upstream,
iniciar Lab, migrar original ou reutilizar autorização a partir deste checkpoint.
Não avançar para outra entrega.
