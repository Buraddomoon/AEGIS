# Primeiro ciclo Demo recuperado — 2026-10-23

[Recibo real](verification.json), emitido após todas as fases e cleanup. Backup
original de 30 tabelas/2.884 linhas restaurado e conferido; após reconciliação, as
2.885linhas serviram de baseline privada. Ao final,3.000 linhas no schema public,
com todas as 2.885 anteriores idênticas e estrutura public preservada. 29,147 s é
a medição desse ensaio, não benchmark ou promessa RTO.

A revisão em recovery confirmou o ID/hash da reconciliação e todos os bloqueios
anteriores (9 rotas, 4 escritas SQL, 5 entrypoints e TCP administrativo). Essa fase
permaneceu normal_operation_permitted=false. Sua API foi removida antes do ciclo
com API normal; os dois estados são fases distintas no recibo.

Conta administrativa, papel runtime, laboratório Demo inicialmente revogado,
ativo, campanha e aprovação novos. A probe autorizou explicitamente só esse lab,
verificou recusa de início sem aprovação e iniciou uma única run pelo worker:
**2bb3840f-baeb-4148-b791-93674937a9fa**, COMPLETED/synthetic=true.

Quatro testes sintéticos, uma classificação de cada: DETECTED,
OBSERVED_NOT_ALERTED, NO_TELEMETRY e INCONCLUSIVE. Evidências/eventos/hashes e
relatórios HTML/JSON conferidos; delta de indicadores 1 run/4 testes/3 válidos.
SHA256 do relatório no recibo; nenhum resultado representa validação defensiva
de endpoint Windows/Linux real, tampouco proteção geral da organização.

Lab novo revogado, sessão encerrada e conta nova desativada. Nenhuma pendência,
grant recorrente ou reserva restante. Bootstrap/fechamento auditados; nenhum
scope, aprovação, evidência, regra ou resultado anterior reescrito.

API/worker normais e Redis novo compartilharam somente o namespace do DB
network=none, sem portas/mounts persistentes/runner/SIEM. Redis loopback,
autenticado e sem save/AOF. Papel SQL sem administração/ownership, restrições
runtime preservadas e baseline privada inacessível. Imagens locais por ID,
sem pull no ensaio; senhas novas via env temporário/stdin, não recibo/argv.

Worker removido antes de API, Redis e DB; intenções privadas confirmam os três
filhos removidos. Nenhum clone remanescente. Demo18780 segue ready sem rebuild/
restart; 9 volumes/journals Wazuh anteriores preservados. Sem nova operação Linux/
Wazuh, consulta SIEM, renovação PKI ou alteração de outro serviço/rede do host.

Recibo público igual ao privado. Dump/manifesto/segredos não publicados. Não
houve cutover, failover, recuperação de roles/secrets/Redis antigos ou efeitos
externos. Cópia criptografada/off-host e guarda de imagens/configuração seguem
pendentes. [ADR0013](../../architecture/decisions/0013-recovered-demo-cycle.md),
[procedimento](../../operations/backup-recovery.md) e
[revisão](../../security/review-recovered-demo-2026-10-23.md).
