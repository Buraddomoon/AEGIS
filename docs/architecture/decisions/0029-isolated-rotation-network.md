# ADR 0029 — Contrato da rede isolada da rotação

Estado: compilador fechado e inspeção somente leitura implementados; lifecycle,
gates do coordenador e criação/validação nativa ainda pendentes. Não é ativação.

## Decisão

O diagnóstico dos volumes originais foi validado e encerrado em2026-10-29.
A futura rotação precisa de uma rede para mTLS entre runner e controlador, mantendo
o IP172.30.88.2 já fixado pela identidade/SAN. Primeiro implementar o contrato da
rede e sua conferência, sem expor um comando que crie rede ou inicie o laboratório.

`runner_activation_isolated_network` usa somente o papel network-isolated do
catálogo de intents, nome reservado aegis-linux-lab_isolated e as cinco labels de
ownership. Compilador exige intent REQUESTED novo e operação aberta; não recebe
subnet, nome, driver, gateway ou opções do usuário. Não faz RPC de criação.

Receita fixa: bridge/local, internal, IPv4 ligado/IPv6 desligado, sem Swarm/
attachable/config-only/config-from; IPAM default172.30.88.0/29, gateway reservado
172.30.88.1, gateway_mode_ipv4=isolated. O IPAM reservado não é prova de que existe
um endereço de gateway no host. Driver isolated exige internal e evita atribuir
endereço à bridge segundo a documentação; isso ainda precisa de revisão nativa
no executor futuro. Não alterar Docker daemon, roteamento/sysctl ou redes alheias.

Inspeção concreta só network inspect por ID completo já OBSERVED no intent.
Cruza ownership antes/depois, campos projetados, driver/opções/flags/IPAM exatos,
zero endpoints e estado durável inalterado. Rejeita opções externas, subnets,
IPRange/AuxiliaryAddresses, labels/membros e tipos divergentes. Flags de alcance,
autorização, ativação e operação normal permanecem falsos: conferir configuração
não comprova tráfego, ausência de acesso ao host ou handshake mTLS.

Não ampliar active_metadata nem permitir runner/API nessa etapa. O futuro gate
ainda precisa de autorização própria, plano atual, PKI/imagens conferidas,
quiescência, disponibilidade/colisões do subnet e fechamento por ownership.
Sucesso histórico do diagnóstico não substitui esses requisitos. Cleanup continua
possível por ID/labels exatos, sem force/prune ou remoção de volumes.

## Verificação e limites

Testes usam intents em temporários e fixtures adversariais. Teste opcional aplica
o formatter a uma rede Demo já existente, apenas network ls/inspect; não valida ou
adota a rede Demo como alvo de rotação. Nenhuma rede Linux foi criada por esses
testes, e ainda não há evidência de create ou isolamento de tráfego nativos.

Referências oficiais:

- [Bridge driver](https://docs.docker.com/engine/network/drivers/bridge/).
- [Gateway mode isolated](https://docs.docker.com/engine/network/port-publishing/#gateway-modes).
- [Network create e flags](https://docs.docker.com/reference/cli/docker/network/create/).
