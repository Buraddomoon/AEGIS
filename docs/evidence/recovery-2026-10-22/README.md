# Ensaio de recuperação do Demo — 2026-10-22

[Recibo operacional](verification.json) obtido executando a CLI do checkout local,
com dump real do Demo em uso e restauração em PostgreSQL17 efêmero offline.
**30 tabelas,2.884linhas**: inventário e hashes internos conferidos; clone removido.
A medição9,488s pertence somente a esse ensaio, não é RTO nem benchmark.

O arquivo público contém apenas resultado/identificadores/hash do arquivo/limites.
Dump, manifesto de linhas e logs privados permanecem em .local/backups e
.local/recovery-errors, fora do Git. Dados do Demo incluem cenários sintéticos;
o recibo comprova a operação de recuperação de dados, não detecção defensiva.

A primeira tentativa expôs conflito do schema public vazio do initdb. Corrigido
somente no clone. Depois, quatro constraints tiveram casts de arrays literais
reescritos pelo PostgreSQL. Foi implementada normalização restrita e testada com
valores válidos/inválidos; nenhum resultado foi declarado verificado antes da
comparação integral passar. Backup experimental anterior foi preservado.

Não houve troca do banco ativo, reinício de API/worker, efeitos de laboratório,
consulta Wazuh, novos alvos ou exclusão de evidências/volumes. Papéis globais,
ACLs, secrets, PKI e journals externos não foram recuperados. Não foi testado
reinício da aplicação restaurada ou failover; jobs/agendamentos ficaram inertes,
sem workers. Ver [procedimento](../../operations/backup-recovery.md) e [decisão](../../architecture/decisions/0010-demo-backup-rehearsal.md).

Após revisão estática, o ensaio final incluiu configuração Docker vazia/ambiente
saneado, intenção privada antes do create, fsync dos diretórios e inventário de
typmod/collation/flags de índices. Backup de ID e689… foi verificado com essas
correções. A CLI não herda configuração global de proxies. Recibos anteriores
continuam privados/preservados; este arquivo público registra a rodada final.
