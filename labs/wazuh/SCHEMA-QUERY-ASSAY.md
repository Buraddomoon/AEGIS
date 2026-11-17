# Consulta nativa de perfil — #63

O usuário retomou explicitamente a #63 após o bloqueio de autorização registrado
na issue. Escopo desta retomada: um ensaio novo de consulta do alerta preservado
da #59, sem nova campanha. Pacotes anteriores permanecem consumidos.

Perfil selecionado: `wazuh-4.14.9/1`, `timestamp`, agente001/regra100200, lab/ativo/
job/marcador originais de16/11. `scripts/wazuh_schema_probe.py` fixa a referência
e o hash canônico já publicado em
[CAMPAIGN](../../docs/evidence/wazuh-cycle-2026-11-16/CAMPAIGN.md).
O intervalo de consulta é delimitado ao redor desse timestamp; não substitui
recibo de execução nem cria resultado defensivo novo.

Somente Indexer4.14.9 existente por ID fixado e leitor pela imagem local por ID,
com pacote Python atual montadoRO. Rede nova própria, interna/isolada, faixa
ADR0034 `192.168.253.16/29`; Indexer `.18`, leitor `.19`, nenhuma porta publicada.
PKI de serviços vigente montadaRO; sem renovação de certificados ou contas.

Indexer1536MiB/heap512MiB e leitor192MiB, swap adicional zero; exigir512MiB
de reserva além dos tetos, CPU/disco/map_count compatíveis e preflight de redes
imediatamente antes do startup. Supervisor de memória/OOM/restart/deadline.
Esse perfil de dois componentes não altera o piso padrão8GiB da stack completa.
Somente volume `aegis-wazuh-lab_indexer-data`, externo/nocopy; inicialização pode
escrever estado/logs normais. Demais oito volumes sem consumidores.

Leitor somente `aegis_reader`, senha em uma linha JSON terminada por newline no
stdin; credenciais transmitidas ao Indexer após verificação CA/SNI/fingerprint.
Compose mantém `StdinOnce=false`; o leitor não aguarda EOF da conexão de attach.
Prontidão espera TLS e HTTP200/401 (HTTP503 transitório), até90s; GET raiz sem
credenciais, com CA/SNI/IP verificados. Saída final vem de `docker logs` do ID
original: `docker start -ai` pode retornar sem os bytes de stdout nesse runtime.
Logs privados são capturados antes de remover containers, inclusive em falha.
Consultas: identidade/ACL já fixadas pelo probe TLS; Search/Scroll do alerta
original; marcador diferente sem hits; leitura opcional de archives com registro
do status/shards/disponibilidade efetivos, sem supor403 ou ausência de índice.
Resposta200 com zero shards continua incompleta. Não habilitar archives ou ingestão. Preservar `_id`, `_index`,
`_source`, timestamp/timezone e conferir total/shards/cursor/DELETE de cleanup.
Sem requisição de escrita de documento ou teste destrutivo de ACL.

Operador host-only novo registra manifesto/hash, autorização e INTENT duráveis
antes dos efeitos, verifica runtime e faz cleanup apenas de seus IDs/labels.
Máximo15min por tentativa. Falha exige registrar/reconciliar e encerrar recursos;
não reutilizar pacote para obter verde. Uma continuação de consulta idempotente
exige diagnóstico, confirmação de cleanup e pacote/intent novos sob a autorização
atual da #63. Isso não autoriza replay de execução, marcador ou campanha.
Conservar volumes/configuração/PKI/intents antigos e recursos de terceiros.

Sem manager, agente, runner, observador, banco/API/worker da plataforma, marcador,
binding, approval, conta nova, migração, build/pull, sysctl ou mudança em qasrc.
Validação deste perfil não valida `@timestamp`, archives ou eficácia defensiva.

`make test-wazuh-schema` exercita fixtures locais e recusas do leitor; nunca
inicia o ensaio. O resultado nativo deve ser registrado separadamente na #63
e em `docs/evidence`, incluindo cleanup e diferenças de fonte/imagem/implantação.
