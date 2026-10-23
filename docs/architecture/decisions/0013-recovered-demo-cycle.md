# ADR0013 — Primeiro ciclo Demo após recuperação

Data: 2026-10-23. Extensão opt-in dos ADR0010–0012. Os comandos anteriores
continuam somente leitura/reconciliação e não iniciam workers ou Redis.

Adicionar verify-recovered-cycle: restaurar novo clone, conferir inventário,
reconciliar e validar a API em quarentena antes de iniciar operação normal
**somente nesse destino descartável**. Sem cutover ou mudança do Demo em uso.

Provisionar novo papel SQL runtime com os mesmos privilégios limitados da
implantação normal, nova conta administrativa, novo laboratório Demo inicialmente
revogado e ativo sintético novo. Não reaproveitar senha, sessão, laboratório,
campanha, aprovação ou grant restaurados. Exigir revisão/schema/fences e catálogo
Demo fixo antes de preparar esse contexto.

API e worker normais, além de Redis novo sem persistência, compartilham apenas o
namespace network=none do PostgreSQL. Sem portas, mounts persistentes, socket
Docker, runner/SIEM, credenciais externas ou download de imagens no ensaio.
Imagens próprias/Redis já locais fixadas por ID, segredos efêmeros em env privado
durante create ou stdin, nunca argv/recibo. Redis bind loopback e autenticação.

Probe autentica a conta nova, confirma autorização Demo nova pela API, cria
campanha com os quatro testes sintéticos revisados, solicita/aprova/inicia uma
única run, espera o worker real e verifica evidências, quatro classificações,
indicadores e HTML/JSON. Depois revoga o lab e encerra a sessão. Desativar a
conta e conferir zero pendências antes de concluir. Sem novo agendamento.

Uma baseline privada dentro do DB, inacessível ao papel runtime, registra hashes
de todas as linhas reconciliadas antes do bootstrap. Após o ciclo, exigir que
todas permaneçam idênticas, que só dados novos tenham sido adicionados e que a
estrutura public permaneça igual. Não reescrever resultados/evidências antigas.

Intenções duráveis antes de cada create e cleanup por nome/label próprios,
inclusive após resposta ambígua. Remover worker antes de API, Redis e DB; falha
de cleanup retém dependências e impede recibo final. Recibo do ciclo separado,
somente após bootstrap, probes, fechamento, integridade e cleanup confirmados.

Não prova failover, recuperação de efeitos externos/Redis antigo/roles originais,
RPO/RTO ou produção pronta. Nenhuma autorização Linux/Wazuh é renovada.

Fontes: [Docker run/rede](https://docs.docker.com/engine/containers/run/#network-settings),
[Redis security](https://redis.io/docs/latest/operate/oss_and_stack/management/security/).
