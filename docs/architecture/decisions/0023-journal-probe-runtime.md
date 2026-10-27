# ADR 0023 — Runtime fixo e encerramento do probe de continuidade

Data: 2026-10-27. Status: implementação incremental; não autoriza ensaio.

O primeiro componente de lifecycle será restrito a journal-before/journal-after.
Não iniciar o servidor Runner para inspecionar seu diário. Compilar argumentos
Docker a partir de um catálogo fechado: imagem local por ID, Python isolado,
entrypoint/módulo fixos e somente hash do bundle em argv. O bundle segue por stdin,
nunca em env, arquivo montado, log do Docker ou linha de comando.

Usar UID/GID10001, root read-only, drop ALL, no-new-privileges, namespaces privados,
network=none, sem portas/devices/secrets/socket, sem restart/healthcheck automático.
Limitar memória192MiB sem swap adicional, CPU0,5, pids16, shm1MiB e scratch tmpfs64MiB
noexec/nosuid/nodev/0700. Montar apenas o volume journal original em /state read-only,
volume-nocopy. Imagem com VOLUME declarado bloqueia antes de create, para não gerar
volumes anônimos. Conferir volume existente imediatamente antes do efeito; Docker
pode criar volumes nomeados ausentes, logo a consulta não é uma garantia atômica
contra root/daemon/outro escritor. Não remover volumes nem usar --rm/--force.

Antes de start, exigir observação de ownership e projeção fechada da configuração
real, mount configurado e efetivo, imagem, entrypoint/argumentos, UID, limites,
namespaces, opções de segurança e ausência de recursos adicionais. Depois, repetir
a revisão e ownership. Nunca imprimir Config.Env, inspect bruto ou Source físico
do volume. Consultas e processos locais têm limites de tempo/saída e recolhem seus
filhos; falha não vira ausência nem autoriza próximo gate.

Intenção durável deve preceder create e start. Retomada nunca repete start ambíguo.
Cleanup próprio continua possível com plano expirado: conferir nome/labels/ID exatos,
registrar remoção antes de stop/rm, remover só container identificado e confirmar
ausência por consultas repetidas. Erro de cleanup impede recibo de sucesso e mantém
artefatos para retomada. Não executar kill/rm de alvos livres nem apagar histórico.

Este componente não prova origem do banco, proveniência da imagem, autorização
humana ou mTLS/registro do novo binding. O coordenador completo ainda precisa ligar
esses gates ao plano atual e ao escopo específico. Sem CLI apply/Make lifecycle,
sem início implícito em testes/CI, sem marcador ou autorização reutilizada.

Fontes oficiais consultadas:

- [Docker create](https://docs.docker.com/reference/cli/docker/container/create/).
- [Volumes e volume-nocopy](https://docs.docker.com/engine/storage/volumes/).
- [Tmpfs](https://docs.docker.com/engine/storage/tmpfs/).
- [Network none](https://docs.docker.com/engine/network/drivers/none/).
- [Limites e segurança de containers](https://docs.docker.com/engine/containers/run/).

Complementa [ADR0021](0021-runner-journal-continuity.md) e
[ADR0022](0022-activation-resource-intents.md). Testes com projeções e processos
temporários não demonstram esses controles no volume Linux real.
