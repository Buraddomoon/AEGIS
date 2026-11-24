# Tentativa interrompida e limites adicionais — #66

O usuário aprovou o plano d8665fed após apresentação do escopo de volumes RO e
custódia privada. A aprovação foi registrada no host antes da execução, não
inferida dos flags da CLI. Pedido consumido em24/11/2026 às18:18:53UTC;
run `ad5296218be74a0ca94b27283b7ea8f5`. Não repetir esse pedido.

Custódia copiada; apenas o primeiro helper tar do PostgreSQL Linux completou:
69.713.920bytes, SHA256
`704e9dda1bbf32781fe726a0c90bd341fd70eb0dee4139d3a3881df29d120ab9`.
O helper foi removido por ID confirmado. Nenhum PostgreSQL de cópia/restore ou
Wazuh foi iniciado nessa tentativa. O log terminou em cleanup_unconfirmed;
não houve recibo verificado, comparação final ou aceite histórico.

O usuário relatou travamento do PC; a sessão retomada constatou reboot às18:38UTC.
Journal do boot anterior registra interface Wayland travada e healthchecks Docker
com timeout. Consulta aos registros do kernel não encontrou OOM/erro de disco;
isso não determina nem descarta a causa. Não atribuir o incidente a um componente
sem prova. A latência do host já era elevada durante a custódia e o tar.

Cleanup separado, vinculado ao begin SHA
`707fcc294a1e69789b0ba4dda1e02bafafd608732195a6e852e17f34f0c19964`,
confirmou ausência dos recursos próprios e gravou
**CLEANED_WITHOUT_VERIFIED_RESTORE**. Sem apagar arquivos/tentativas/volumes.
Cleanup em serviço privado limitado: pico83,6MiB, swap0, CPU376ms.

Antes de nova tentativa, acrescentados tetos de CPU/disco nos containers e no
coordenador, cgroup obrigatório e piso de RAM disponível elevado de1536MiB
para4GiB. CPU0,25,384MiB, swap0, disco2MiB/s por direção e um container por vez;
host limitado a32tasks, nice15 e IO idle. O precheck real confirmou os controles
sem Docker effects, pico51,1MiB. Testes negativos cobrem limites ausentes/alterados.

A aprovação do usuário permanece para concluir a recuperação com esses limites
mais restritos. Nova execução exige novo plano/inventário/hash; o pedido e os
registros anteriores permanecem consumidos e preservados. #66/#9 continuam abertas
até prova dos dois perfis e encerramento. Nenhuma operação normal autorizada.

## Retomada limitada e custódia em pack

Fonte5edaf6f teve CI45462987138 SUCCESS:4083Python/9skips e154React/21arquivos,
quatro partições e React conferidos. Testes unitários locais dos limites:
40passed, pico153,1MiB/swap0. A rodada ampla local foi interrompida deliberadamente
para manter a suíte integral nos runners remotos; não é rodada aprovada.

Plano0d448be9518e4246b360be476ad59923 teve um preflight UNCONFIRMED antes do
pedido; causa não exposta pela CLI genérica. Diagnóstico seguinte de código e
metadados passou sob os mesmos limites. A retomada com registro privado de erros
consumiu o plano na run b1a9e8f9c6b14e6ab16c29c49abcf241. O monitor interrompeu
durante a custódia (2355arquivos presentes), por PSI global de I/O sustentado.
Sem diretórios de perfis, leitura de volumes ou PostgreSQL. failed.json mantém
UNCONFIRMED e closed.json CLEANED_WITHOUT_VERIFIED_RESTORE; zero recursos próprios.
O retorno zero do serviço após SIGINT não foi confundido com prova de restore.

Verificação limitada do arquivo frio retido confirmou novamente seu SHA acima:
6,31s, pico64MiB/swap0, ocupação NVMe máxima14,5% na amostragem de1s. Isso não
estabelece a causa dos travamentos anteriores. Medidas de PSI e ocupação física
são registradas separadamente; o monitor passa a observar também o cgroup gráfico.

Para reduzir operações síncronas de metadados, custódia `/2` grava os mesmos bytes
em um único pack USTAR0600, com hashes por arquivo e do pack, manifesto durável por
último. Verificador streaming, sem extração/execução de configuração; `/1` retido
continua verificável. Não reescrever tentativas anteriores. Extração PostgreSQL
permanece no scratch `/tmp`, confirmado tmpfs nesta estação.

57testes locais de arquivo/limites/plano passaram sob os tetos, pico154,6MiB/swap0;
incluem legado, corrupção, membros inválidos e manifesto ausente após falha.
Novo código exige nova CI e novo plano, antes de outra leitura original.
