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
