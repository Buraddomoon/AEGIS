# Boot recuperado em quarentena — 2026-10-23

[Recibo real](verification.json): backup Demo do marco anterior restaurado em
PostgreSQL17 descartável, inventário conferido, API iniciada em recovery e
inventário conferido novamente após leitura. **30 tabelas/2.884linhas** iguais.
API e banco removidos, sem portas publicadas/rede externa ou acesso aos labs.
16,321s é a medição desse ensaio, não benchmark ou RTO.

Imagem própria separada `aegis-recovery-local:0.2`, fixada por ID no recibo;
nenhuma substituição/reinicialização da API/worker do Demo em uso. API no mesmo
namespace offline do banco, loopback interno, usuário10001, read-only/cap-drop,
limites de recursos. Banco com papel SELECT/SCRAM e TCP administrativo recusado.

Probes reais:9 rotas protegidas/bloqueadas,4 tentativas SQL negadas por privilégio
(DELETE/DDL/TEMP/large object após READ WRITE),5 entrypoints recusados e conexão
TCP administrativa negada. O comando de probe recusa ambiente/destino diferentes
antes de I/O. Apenas health e revisão agregada; nenhum login ou trabalho retomado.

O snapshot contém20 runs COMPLETED,0 sessões/filas/agendamentos ativos e1 Demo
autorizado. Isso descreve esse backup, não prova que todo backup terá filas vazias.
Testes de integração separados incluem sessões válidas/expiradas, fila, reserva
e aprovação pendentes, preservadas sem reativação durante a revisão. O plano
mantém normal_operation_permitted=false/reconciliation_applied=false mesmo com
zero pendências em alguma contagem.

Revisão estática encontrou permissões residuais pg_catalog de large objects e
cleanup externo removendo DB após falha de remoção API. Corrigidos: revogação
e guard específico/probe; DB retido quando cleanup API não é confirmado, sem
recibo de sucesso. Regressores e reinspeção confirmaram as correções. O primeiro
recibo do ensaio ficou preservado privadamente; este é o ensaio final endurecido.

Dump, manifesto, intenções, tokens efêmeros e diagnósticos não são publicados.
Este recibo contém só dados agregados da operação. O Demo usa evidências
sintéticas: verificar backup não é validar uma detecção real. Não houve novo
efeito Linux, consulta Wazuh, remoção de evidências/journals/volumes ou cutover.

Não foram recuperados roles/ACLs originais, Redis, PKI, secrets ou journals do
runner. Não foram testados reativação normal, reconciliação aplicada ou failover.
[Procedimento](../../operations/backup-recovery.md),
[ADR0011](../../architecture/decisions/0011-recovery-quarantine.md).
