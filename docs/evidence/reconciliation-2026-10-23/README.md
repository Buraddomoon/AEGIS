# Reconciliação offline Demo — 2026-10-23

[Recibo real](verification.json), gerado somente após restore, reconciliação,
boot restrito da API, probes, comparação final e remoção de ambos os clones.
Backup original de30tabelas/2.884linhas conferido antes da aplicação;2.885linhas
depois, pela nova auditoria. Histórico protegido e estrutura preservados.
20,578s é a medição desse ensaio, sem promessa de RTO ou benchmark.

O snapshot tinha20runsCOMPLETED,1Demoautorizado e nenhuma sessão, conta ativa,
run pendente ou grant recorrente. A autorização Demo foi revogada no clone e
sua environment_version incrementada. Histórico concluído preservado,1auditoria
recovery.demo.reconciled acrescentada. Casos não vazios de sessões/contas/filas/
grants/reservas são validados separadamente em PostgreSQL temporário nos testes;
este recibo não alega tê-los encontrado no backup utilizado.

A API verificou exatamente o ID83563951337c44ab81329019421e355d e hash do plano,
com todos os fences atuais vazios, reconciliation_applied=true e
normal_operation_permitted=false. Histórico sozinho não satisfaz a verificação.
9rotas bloqueadas/protegidas,4escritas SQL negadas por privilégio,5entrypoints
recusados e TCP administrativo negado. Nenhum login/worker/ciclo foi retomado.

Imagem própria separada local fixada por ID no recibo. DB network=none, API
somente no loopback desse namespace, sem portas/mounts/Redis/runner/SIEM; API
com usuário sem privilégio e papel SQL SELECT/SCRAM. API removida antes do DB.
Fonte Demo continua ready e não foi reconstruída/reiniciada. Não houve novo
ensaio Linux/Wazuh, consulta SIEM ou remoção de seus9volumes/journals anteriores.

O arquivo público foi comparado ao recibo privado. Dump, manifesto, plano
privado e diagnósticos não foram publicados. Intenções privadas permanecem
preservadas. Não houve cutover, retomada normal, recuperação de roles originais,
secrets, Redis ou efeitos externos. Novo ciclo Demo com identidades/aprovação
novas ainda é a próxima validação operacional.

[ADR0012](../../architecture/decisions/0012-demo-recovery-reconciliation.md),
[procedimento](../../operations/backup-recovery.md),
[revisão](../../security/review-reconciliation-2026-10-23.md).
