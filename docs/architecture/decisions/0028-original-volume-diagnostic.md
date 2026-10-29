# ADR 0028 — Diagnóstico dos volumes originais separado da ativação PKI

Estado: planejamento implementado e testado; coordenador/ensaio pendentes.

## Decisão

Um diagnóstico de continuidade precisa consultar o PostgreSQL e o diário Linux
originais sem iniciar worker, runner de execução ou uma nova campanha. Ele não
usa candidato PKI nem exige renovar certificados antigos só para ler identidade
histórica. A inspeção pública existente valida cadeias, usos e identidade sem
aceitar esses certificados expirados numa conexão TLS. Não há handshake nesse
planejamento e nenhuma chave privada antiga é lida.

O novo perfil `linux-original-volume-diagnostic/1` é independente do plano de
ativação PKI. Prepara plano privado com validade24h e escopo/hash próprios. Fixa
commit da ferramenta/main limpa, código e dependências da imagem conferidos,
recibo independente do build, quatro imageIDs, daemon, nomes/metadados de criação
dos dois volumes existentes, identidade pública e descritor antigo. O arquivo de
plano não é uma autorização. CLI oferece somente prepare/recheck, sem apply/run.

Metadata consulta duas vezes membresia completa (incluindo containers parados),
redes reservadas e consumidores de volumes, inclusive de outros projetos. Drift,
novo consumidor, worker ou imagem/código fora do contexto conferido bloqueiam.
Recheck relê todos os inputs e o prazo após o último IO. Não abre interior de
volume, banco, SQLite ou arquivo de credenciais. Nenhuma adoção/criação de volume.

## Escopo futuro explicitado

Cinco papéis máximos, sequenciais, com dois containers simultâneos: servidor PG,
leitor SQL antes, probes do diário antes/depois, leitor SQL depois. Até300s de
operação, sem portas publicadas; networknone ou namespace do próprio DB. SQL
fixo READONLY, diário RO. **Startup PostgreSQL precisa do volume RW e altera
metadados/WAL operacionais**: não descrever o diagnóstico inteiro como read-only.
Não autoriza marcador, worker, Wazuh, migração, concessão de grants, reset de
credenciais, mudança de binding/PKI ou exclusão/criação de volumes.

A execução ainda precisa de coordenador concreto, gates derivados de inspeções,
intenção durável única, orçamento absoluto, captura privada e cleanup por
ownership. O profile registra executor_implemented=false até essa implementação
ser concluída. Antes de invocar runtime original é necessária nova autorização
humana específica sobre o procedimento concreto; os ensaios antigos terminaram.

## Verificação

Testes usam repos Git main temporários, PKI própria descartável, FakeBuildKit e
metadados nativos em fixtures. Cobrem plano/recheck, drift de volume/daemon/código,
imagem desatualizada, consumidor parado, worker/redes extras, policy adulterada,
flags inteiros, TTL/expiração durante IO e identidade histórica com certificado
expirado. Não são evidência de SQL ou runtime no laboratório original.

## Recheck durante ownership implementado

`runner_diagnostic_recheck` é interno, sem CLI ou efeitos. Não reutiliza o candidato
PKI antigo: confere plano/escopo exatos no intent, código/main limpa, recibo da
imagem e identidade pública histórica; inventário ativo relê daemon/volumes e
membership/consumidores exatos duas vezes. Apenas os cinco papéis do diagnóstico
são aceitos, sem rede/API/Redis/runner adicionais. Probes exigem start/runtime do
DB já registrados, além de sua inspeção física futura. Revalida identidade/código,
intents e expiração após o último IO, com limite30s para publicar o resultado.

O resultado é evidência de inputs/metadados, não autorização nem prova de SQL,
diário, grants, autenticação ou isolamento físico. Esses gates permanecem separados.
Planejamento público continua exigindo quiescência; não adota recursos só porque
um intent diz que pertencem à operação. Testes das11combinações role/phase, contexto
errado, consumidor extra e mutações/expiração durante IO usam somente fixtures.
