# ADR 0029 — Contrato da rede isolada da rotação

Estado: compilador, inspeção, lifecycle interno, preflight de subnet e composição
de gates implementados. Coordenador completo e criação/validação nativa ainda
pendentes. Não é ativação.

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

## Lifecycle interno de criação única

`runner_activation_network_lifecycle` registra request durável antes da única RPC
de create, com callback interno confiável de gates frescos (não JSON/API). Gates
fixam operação/plano/escopo/receita/nome e exigem autorização específica, candidato
PKI válido, perfil revisado, projeto quiescente/owned, subnet disponível e worker
parado. O futuro coordenador ainda deve computá-los, nunca fornecer flags constantes.

Gate/contexto são rechecados antes do efeito. ID retornado, ownership e inspeção
física da configuração precisam concordar; sucesso retém somente a rede vazia
para o chamador. Não verifica tráfego, mTLS nem ativa PKI. Sem CLI ou ampliação dos
gates active_metadata nesta unidade, não invocar nativamente antes do executor.

Falha/ambiguidade/interrupção tenta cleanup selecionado pelos mecanismos existentes,
sem replay ou fechamento do pai. Colisão anterior à tentativa vira CONFLICT sem
adoção/remoção; endpoint estrangeiro ou cleanup incerto retém rede. Dependente
inesperado REQUESTED impede declarar ausência no intent mesmo sem create: resolver
dependência primeiro, sem relaxar o armazenamento para fabricar sucesso. Retomada
da operação não remove o papel já solicitado nem permite outro create.

Testes usam daemon fixtures/intents temporários e cobrem gates negados/expirados,
contexto mutado, RPC ambígua, ID errado, configuração insegura, interrupção e retenção.
Driver concreto compilado/testado com transporte falso; nenhuma RPC real de create
ou alteração de rede do host foi feita por esse incremento.

## Preflight de colisões, somente leitura

`runner_activation_subnet_review.review` observa duas vezes as subnets locais do
Docker e as rotas IPv4 de todas as tabelas do kernel. Destino é somente a constante
172.30.88.0/29. Não recebe rede/interface/URL/comando do usuário, não exclui redes
por labels de ownership e não cria/altera/remove rede ou rota. Uma rede existente
com o mesmo pool bloqueia, inclusive se alegar ser própria; esta verificação é
anterior ao create, sem autorização implícita para etapas posteriores.

Docker usa transporte fechado/config vazia existente, somente ls/inspect com
ID completo e projeção sem nomes de redes. Drivers bridge/local/IPAM default,
host e null sem pools são reconhecidos; configuração/plugin/escopo incompletos
ou desconhecidos bloqueiam. IPv6 é lido como pool distinto, não ampliando IPv4.
Máximo128redes/16pools por rede. Mudança de membros/pools entre snapshots bloqueia.

Rotas usam somente `/usr/bin/ip -json -4 route show table all`, ambiente mínimo,
sem shell/DNS/overrides e sem modificar o kernel. stdout+stderr64KiB, até5s por
filho e20s no review integral; timeout/excesso/falha mata e recolhe só o próprio
filho. Até2048rotas, sem truncar sucesso. Ferramenta ausente gera erro explícito,
sem instalar ou procurar fallback arbitrário.

Somente default /0 é ignorado para colisão; qualquer prefixo/host específico
sobreposto, em qualquer tabela, bloqueia conservadoramente. Snapshot normaliza
destino/tabela/tipo; expiry/cache contadores voláteis não representam mudança de
CIDR. Isso não verifica integralmente roteamento, conectividade, firewall ou todos
os meios de acesso ao host. Saída só contagens/hash e subnet constante, sem nomes,
interfaces, gateways ou endereços de outras redes/rotas. Flags de autorização,
ativação e alcance permanecem falsos; resultado não é lease nem gate pronto.

Review nativo somente leitura de2026-10-29 examinou15redes/46rotas, ignorando um
default, sem sobreposição observada; recibo privado rotation-subnet-readonly-preflight.json.
Não foi criado recurso nem emitido tráfego de teste. Testes com fixtures e filhos
Python reais cobrem colisões, drift, limites, tool ausente, deadline/reap e sigilo.

## Recheck em operação para rede solicitada/vazia

active_metadata/active_plan aceitam network-isolated somente nas fases create
(REQUESTED/ausente) e created (OBSERVED/vazia). Não existem start/running de rede;
backend/ingress, runner e API não ganham contextos novos. API/Redis ativos bloqueiam
esse contexto de preparação; qualquer endpoint na rede atual também bloqueia.
Inventário, IDs/labels, consumidores e ownership são reconferidos duas vezes.

O plano ainda revalida PKI, Compose, metadata e prazo após IO. Os retornos mantêm
authorization_granted/activation_performed/network_isolation_verified falsos.
Essa extensão não calcula todos os gates nem cria recurso: o plano /2 já fixa a
versão do executor e escopo único, mas falta compor fatos de subnet/perfil/aprovação. O
formato público atual continua não operacional; nenhum v1 vira permissão implícita.

## Composição concreta do gate anterior ao create

`runner_activation_network_gates.NetworkGates` combina o plano /2 com a confirmação
local do operador de seu scopeSHA exato e validade UTC de até300s, vinculada ao ID
da operação. Essa afirmação local não é assinatura humana nem aprovação por API.
Não instanciar contra recursos reais sem o escopo especificamente autorizado.
Expiração, relógio anterior à confirmação e orçamento monotônico vencido bloqueiam.

O callback aceita somente create e a receita fixa. Faz recheck ativo de PKI,
Compose, main limpa, imagens, volumes e ownership antes e depois do preflight de
subnet, que é invocado novamente, sem cache ou JSON salvo. Mudanças no inventário,
intent ou receita bloqueiam. Membership inclui todos os containers do projeto;
worker nunca é papel permitido. Não é atestado de ausência de processos arbitrários
com acesso de root ao daemon, prova de conteúdo das imagens ou eficácia do firewall.

checked_at é o início das observações; terminar IO lento não renova a idade dos
fatos. Revisão acima de20s é recusada; o consumidor exige idade<=10s e reconfere
validade imediatamente antes da RPC. Validade do gate é limitada também pela
confirmação e pelo plano. Os leitores internos mantêm seus próprios limites de IO;
o limite composto recusa o resultado, sem prometer interrupção de todo código
Python exatamente no vigésimo segundo. Cleanup não depende de lease válido.

Evidência em memória contém só hashes do gate e das duas revisões/contagem de subnet;
o futuro coordenador deverá persistir esses vínculos. Nenhuma flag pública de
autorização/ativação é ligada; candidato válido não autoriza instalar certificados.
Sem CLI, chamada nativa de create, PKI nova ou binding alterado nesta unidade.
Testes usam PKI/Git temporários e daemon fixtures, incluindo consumo pelo lifecycle
de criação única, colisão após review antigo, fonte/intent/metadata alterados durante
IO, budget/clock e bloqueio de worker/consumidor inesperados. Não provam rede real.

## Orçamento vinculado à origem durável

ConfirmedPlan centraliza a confirmação de escopo/plano/operador antes dos gates.
Além do limite de300s desde a confirmação, a expiração não pode ultrapassar300s
desde o evento begin original. ID e hash do begin são fixados após conferir o
hashchain. Construir outro objeto de gate mais tarde não concede nova janela;
um plano de15min ainda válido não renova uma operação já vencida.

Relógio anterior à confirmação ou ao último evento durável bloqueia novos efeitos;
orçamento monotônico também é conferido no mesmo processo. Não é atestado de
relógio externo ou assinatura humana. Futuro coordenador deve manter resume
restrito a reconciliação/cleanup, sem usar reconstrução de gates como renovação.
Cleanup existente não depende dessa lease. Diagnóstico histórico não é alterado
nem recebe nova autorização por esse componente. Testes só arquivos temporários.
