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

## Origem PostgreSQL por digest

`runner_postgres_origin` inspeciona somente a imagem local já existente e exige
perfil Linux/amd64/PG17 e referência oficial postgres@digest. Perfil desta ferramenta
é explicitamente containerd/index: ID nativo e Descriptor.digest precisam ser o
mesmo índice, com mediaType conhecido; não converter um config digest por palpite.
Consulta TLS anônima apenas auth.docker.io e library/postgres no registry oficial,
por aquele digest fixado, nunca tag/URL/credencial do usuário. SHA dos bytes de
índice/manifesto filho e headers é conferido, plataforma precisa ser única, schema2,
config/layers limitados e sem URLs alternativas. Não baixa blobs/layers.

Timeout absoluto30s inclui as três chamadas, corpo até1MiB/sem compressão, sem
proxies/redirects; token fica só na memória. Inspeção local é repetida ao final.
Recibo público sem token distingue registry_manifest_verified e referência nativa
conferida de publisher_signature_verified/local_layer_bytes_verified, que ficam
false. Confia no host/daemon para vincular o conteúdo local ao digest; não equivale
a assinatura/atestado ou à verificação criptográfica de todos os layers locais.

A ferramenta tem somente captura de metadados e review offline, sem pull/build,
containers, SQL ou volume. Cache de recibo para o plano e ligação aos gates ainda
pendentes nesta unidade. Testes nativos/HTTP fixtures cobrem hash/redirect/schema/
limites/plataformas, receipt adulterado, deadline absoluto e import sem efeitos.
Fontes: [Registry API](https://distribution.github.io/distribution/spec/api/),
[token authentication](https://docs.docker.com/reference/api/registry/auth/) e
[Docker image inspect](https://docs.docker.com/reference/cli/docker/image/inspect/).

## Plano /2 vincula recibo independente de origem PostgreSQL

prepare agora exige postgres-origin (arquivo privado0600 com schema fechado) e seu
SHA canônico independente. O recibo completo e SHA ficam no snapshot/escopo; o
recheck público e o ativo validam novamente esse receipt e os metadados da imagem
PG17 por inspeções locais, sem outra consulta ao registry/pull. Não renovar receipt
em cada gate nem aceitar token, assinatura inventada ou ID diferente no registro.
Formato do plano/escopo sobe para /2; planos /1 permanecem preservados e não são
convertidos/adotados implicitamente. A verificação de bytes dos layers/assinatura
do publicador continua explicitamente false, conforme o modelo de confiança local.

## Gates concretos internos

`DiagnosticGates` calcula os três contratos dos lifecycles a partir do plano /2,
recheck ativo, fonte/imagem e política física do DB. Não recebe dicionários de
checks fornecidos por API. Create do servidor identifica volume/política; start e
readiness também precisam passar inspeção física de mounts/config/rede. Leitores
exigem DB networknone/portas ausentes/HBA fixo e namespace derivado do ID próprio.
Probes do diário só aceitam bundle privado capturado e conferido, leitor inicial
removido, identidade/descritor originais e hash de receita correspondente.

Gate `image_provenance_verified` legado significa aqui vínculo local de fonte/
inputs do runner e manifesto oficial do PostgreSQL sob confiança no host/daemon;
não é assinatura de publicador ou verificação dos bytes de todos os layers. Esses
limites continuam explícitos nos receipts de origem. Nenhum resultado é detecção
SIEM ou autorização de operação normal.

A confirmação do escopo pelo operador host-only deve coincidir exatamente com o
plano/intent e expirar em no máximo300s; prazo monotônico impede estender a operação
com ajustes do relógio. Gates são emitidos por até20s, depois de todas as consultas,
e passam de novo nos validadores dos lifecycles. A confirmação local não é uma
assinatura/autenticação de aprovação humana; o agente só poderá fornecê-la depois
de autorização específica real do usuário. Este módulo não possui CLI/lifecycle.

22 testes exercitam os gates reais sobre daemon fixtures, PKI/Git temporários e
captura privada/decoder reais, incluindo volume errado, rede host, HBA adulterado,
receita livre, consumidor extra, fonte alterada, escopo e orçamento inválidos.
Nenhum PostgreSQL/diário original foi aberto por esses testes.
