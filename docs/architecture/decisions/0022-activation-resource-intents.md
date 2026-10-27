# ADR 0022 — Intenção e ownership antes de efeitos de ativação

Data: 2026-10-27. Status: armazenamento implementado; executor ainda não disponível.

O executor futuro precisa registrar intenção durável antes de create/start e
reconciliar falhas ambíguas por nome exato e labels, inclusive quando o Docker não
retorna ID. Não usar down global, exclusão por prefixo ou remoção de volumes.

Implementar armazenamento host-only de eventos imutáveis em diretório0700, arquivos
0600 exclusivos, fsync de arquivo e diretórios. Uma trava cooperativa global impede
duas operações desse harness. Histórico não encerrado ou artefato parcial/inesperado
bloqueia uma nova operação; retomada explícita exige ID/hash independente da origem
do registro. Não apagar resíduos para contornar esse bloqueio.

Catálogo fechado de recursos para Linux integrado: DB/cache/API/runner, probes
journal-before/journal-after e três redes. Nenhum volume, worker, migrate, controller,
Wazuh ou serviço externo é recurso gerenciado. Nomes/labels são derivados do ID e
do perfil fixo, nunca recebidos como alvo livre. IDs observados precisam ser hashes
completos; o journal só permite remoção de recursos com intent próprio.

Transições: create_requested → observed (opcional em erro ambíguo) →
removal_requested → absence_recorded. Não registrar ausência sem pedido prévio de
remoção, nem encerrar enquanto houver recursos sem ausência registrada. API incerta
retém DB/cache/runner; redes permanecem enquanto houver container próprio incerto.
Novos dependentes são recusados durante e depois da remoção das dependências,
inclusive após retomada. Observação tardia de ID após erro ambíguo não desfaz o
pedido de remoção já durável. Comparar replay persistido ao estado em memória.
Hash do comprovante de consulta é obrigatório ao registrar ausência/fechamento.

Eventos encadeados por hash/índice e schema exato; carregamento revalida todas as
transições. Falha de publicação torna o objeto em memória inutilizável; retomada
reconfere e sincroniza os artefatos antes de novas gravações. Nenhuma retomada
repete create/start, libera reservas ou corrige registros automaticamente.

Este armazenamento não chama Docker, não confirma sozinho presença/ausência, não
verifica autorização humana nem converte SHA de escopo em permissão. O executor
terá de consultar o daemon e comparar nomes/labels/IDs/mounts antes de cada efeito
e após encerramento. Flags de ativação/autorização/operação normal continuam falsas.
Root/daemon/usuário proprietário são fronteiras de confiança; hashes locais não
são assinaturas. Locks não impedem outro software de alterar o daemon.
O executor futuro terá root fixo .local/pki-activation-intents; locks de diretórios
diferentes não são uma trava distribuída. Verificar plano/TTL/escopo antes de todo
novo efeito; expiração não deve impedir reconciliação/cleanup dos próprios recursos.

Testes somente em diretórios temporários, cobrindo interrupções, replay, ownership,
concorrência e retenção de dependências. Complementa
[ADR0020](0020-runner-activation-plan.md) e
[ADR0021](0021-runner-journal-continuity.md).

## Reconciliação somente leitura implementada

`runner_activation_ownership.py` observa somente o catálogo. Consulta nome,
label composta exclusiva `io.aegis.activation-resource=ID:PAPEL` e ID histórico
quando conhecido; exige concordância e inspect por nome com ID/nome/cinco labels
exatos. Uma label composta evita depender de AND/OR para filtros label repetidos.
O filtro name usa substring documentada; nomes semelhantes bloqueiam, nunca
autorizam remoção aproximada. Projetar só identidade/imagem/estado ou contagem de
membros da rede, sem Config.Env, mountpoints, inspect bruto ou nomes de membros.

Repetir as listas ao final; falha, ambiguidade, recurso renomeado/duplicado ou
IDs/labels divergentes bloqueiam. Recurso sem ID após create ambíguo é localizado
pelo nome/owner; nunca interpretar erro de inspect como ausência. Ausência exige
listas vazias, inclusive ID anterior quando conhecido. Snapshot não impede corrida
do daemon depois da consulta; executor deve reconferir antes/depois de seus efeitos.

Reutilizar Unix local/config vazia/env mínimo/10s/64KiB do executor de consultas,
somente ps/network ls/container inspect/network inspect projetados. Sem lifecycle,
SQL ou chamadas ao runner. `stopped_or_empty_snapshot` é observação parcial,
sem provar mounts/isolamento/proveniência ou autorizar efeito. Testes desse novo
reconciliador usam fixtures; ainda sem validação em objetos reais de ativação.

Fontes oficiais consultadas:

- [Docker container ls](https://docs.docker.com/reference/cli/docker/container/ls/).
- [Docker network ls](https://docs.docker.com/reference/cli/docker/network/ls/).
- [Docker container inspect](https://docs.docker.com/reference/cli/docker/container/inspect/).
