# Retomada específica da #80 — preparação verificável

Após pedido explícito para trabalhar a #80, a preparação saiu do bloqueio de
imagem/ambiente indefinidos. Não houve startup, banco/journal original aberto,
efeito em endpoint ou consulta defensiva. Autorização do ensaio continua separada.

## Fonte e controles

`atomic_assay.py` compila somente a receita desse GUID e coordena a tentativa
com fence durável, autorização por hash, expiração, memória mínima, colisões,
imagem/configuração/runtime e cleanup/quarentena. `atomic_assay_service.py`
separa bootstrap explícito de banco novo, gate RO, API/worker e desativação das
contas. `atomic_assay_client.py` usa a API/domínio atuais, duas contas segregadas,
preflight mTLS e um start; UUID/escopo ficam no volume próprio antes do efeito.
Nenhuma alteração de contrato/worker/allowlist da #79 ou do gate histórico b7.

Procedimento: [atomic80-assay](../../operations/atomic80-assay.md).
Proposta atual: [pacote202afac5](../../../labs/linux/ATOMIC80-REQUEST-202afac5.md).

## Imagens construídas de verdade

Runner: build `ab1a61c053a840e98dfae1415a1749ee`, plano SHA256
`15319544d23ae8db59bfb30677b309c8ff266f8135e5c662918c56d66fc2a284`,
recibo SHA256 `b9c39d69610263e06e9fb9b820ac105ff4d384811177abbcd1d562ec4a6ddcf6`.
Imagem `sha256:c0fb88c5cf97ab20b41e6f4d45a7647c98161dd29d0408d296c11a4b6bb38e5f`.
Driver revisado confirmou78fontes Python instaladas,45dependências de runtime,
3ferramentas de build e imports; saída0, digests OCI e ID nativo coerentes.
Fonte selada7e3dde5 já validada na #79; pacote/APIs do runner inalterados depois.

Aplicação: build `04510bea79ea4ca5a1033518f8ad4da1`, fonte8b4678e,
recibo SHA256 `bb6ec305df2596f4bc8b4fd6c67389897401b0e02c4b0a99aa88948f157b19fb`,
contexto SHA256 `a5093a41c76d73d4e1f3218f8bd670b1e0e4a82ed4ea8ee49bf524b1b63c3c1c`.
Imagem `sha256:3ae40c8ce7c93f0a1b40c91ecc84facaf1ecb6d8ee74e841765f81a0aa5a81c7`.
Base própria9e3488c retida sob tag nova; wheels/locks fixados e conferidos,
RUNs sem rede, sem push e pull=false. Novo check da imagem confirmou78fontes,
45dependências/3tools, imports API/worker/probes e16assets (incluindo as cópias
de runtime dos helpers), migrations e fonte/licença ATT&CK versionadas.
SPA não é servida nesse perfil; prova de UI não é atribuída a esse build.

Cache de48wheels verificado,30.384.557bytes, sem instalação no host:
`a52ebe52a84840f8962e554f53cd50ac`, SHA256
`abdbc507a91e35fbe74d155c1142f5066ed07284f3f62bf2b4be9f7df85c5ce0`.
Builds/tagging são preparação local, não criação/start de laboratório. Sem
alterar tags antigas ou apagar resíduos/cache/imagens históricas.

## Falhas preservadas

1. Leitura inicial do catálogo1,3MiB excedeu o limite de1MiB do perfil de código,
   antes de qualquer build. Asset ATT&CK agora tem perfil separado≤2MiB, com
   tipo/tamanho declarados conferidos antes de ler; limite do código inalterado.
2. Build892a446e falhou na resolução FROM sha256:ID pelo Docker29, interpretado
   como repositório remoto. Nenhuma etapa foi construída. Corrigido com tag
   local exclusiva e confronto do ID imutável antes/depois; sem substituir base.
3. Buildeb94ac06 passou pacote/versões/imports/assets, mas um NameError na saída
   do checker impediu aceite/exportação. Corrigido o checker e acrescentado teste
   real em processo isolado, com rede/subprocessos adicionais proibidos e
   negativas de alteração de asset/cópia runtime. Não apresentar esse build como
   sucesso. Contexto/log/tag retidos; novo build ID para a repetição.
4. Candidato offline1ed87ba8 parou na leitura de Config.User omitido em imagens
   oficiais de PG/Redis consultadas por ID. Projeção usa index para esse campo;
   UID10001 continua obrigatório para aplicação/runner. Candidato/PKI preservados,
   sem efeito, sem sobrescrever/usar seu pacote incompleto.
5. A projeção foi exercitada somente em metadados reais do Demo já existente,
   sem volumes/SQL/startup. Docker também omitia Tmpfs vazio no DB. O template
   usa index para esse campo; parsing de DB/API real passou depois, sem imprimir
   valores. Isso valida layout do transporte, não o isolamento/runtime do perfil
   novo. O layout sem portas do worker existente também foi lido RO, sem dados.
   Novo coordenador c974380; pacote91de0d6f retirado sem autorização/efeito,
   preservando integralmente sua proposta/PKI. Pacote novo a4335444, sem converter
   ou rehash do pacote anterior para fazer o guard passar.

Várias runs intermediárias da CI foram substituídas/canceladas após os commits de
correção; não são agregadas como workflow verde. Logs/receipts/segredos somente
em `.local`, sem upload de conteúdo privado. Não houve tentativa de laboratório
consumida por essas falhas de preparação.

## Testes e CI

Rodadas locais sobrepostas:54passaram na integração inicial;83passaram incluindo
readiness histórica;29passaram nas últimas guardas/client;30/33/36/37nos ciclos
de assets/retention/checker/metadata. Não somar rodadas como casos únicos.
Módulos testados: `test_atomic_assay`, `test_linux_campaigns`,
`test_linux_campaign_preparation`. Fixture usa schemas PG/Redis15 próprios,
sequenciais; processos próprios apenas em temporários, nenhum Docker/Lab.
Mais38testes passaram após o guard de metadata runtime; sem somar rodadas.
Aviso conhecido Starlette/httpx preservado. Lint/tipos/formato aprovados.

CI integral da fonte4759805:
[44202869465](https://github.com/Buraddomoon/AEGIS/actions/runs/44202869465),
SUCCESS, quatro Python937/868/942/867aprovações,9skips opcionais e98React;
3623coletados igual à coleta local. Cinco jobs/logs conferidos. Python1finding
revisado/npm0. Correção posterior de metadata em c974380; CI final
[44205114457](https://github.com/Buraddomoon/AEGIS/actions/runs/44205114457):
**SUCCESS**, fonte `c9743800176950305c408daf969d3e1b6638d241`, cinco jobs/logs:

| Job | Resultado |
| --- | --- |
| Python0 |937passaram/2skips |
| Python1 |869passaram/2skips |
| Python2 |942passaram/1skip |
| Python3 |867passaram/4skips |
| React |98passaram/16arquivos; lint/tipos/formato/build/auditoria aprovados |

Total único **3615Python passaram/9skips opcionais**,3624coletados igual à
coleta local. Skips existentes por metadata opt-in/objetos Demo/ferramentas locais
ausentes; não criar recursos para obter green. Python1finding explicitamente
revisado/npm0. Sem filtros/exclusões/partições/timeouts relaxados. Consolidação
posterior somente Markdown; inputs executáveis iguais à fonte aprovada.
Não confundir testes ou RUNs de build com ensaio nativo/mTLS/telemetria.

## Preparação histórica a4335444 — expirada

Pacote a4335444 preparado, SHA256
`1d765beae77041733963db23304965d10839f0384f27ee0d309429d4513314af`.
Receita Compose renderizada sem create/start. PKI nova conferida offline:
OpenSSL verify serverAuth/clientAuth e IP192.168.253.2 OK; folhas até
20/11/2026 às00:07:07UTC. Proposta expira18/11 às12:07:07UTC; revalidar tudo
antes de operar. Hash de executáveis prende o coordenador c974380, permitindo
somente consolidação Markdown posterior, sem mudar autorização/escopo histórico.
Comparação independente de HEAD com o manifesto da aplicação construída confirmou
78fontes de pacote e16assets byte a byte/SHA256 idênticos. Consulta RO de recursos
no host observou3915MiB MemAvailable/385GiB livres; isso não reserva recursos,
e o gate exige3072MiB novamente antes de qualquer create.

`authorization.json` e `attempt.json` ausentes; efeitos não autorizados.
Os bloqueios de preparação foram resolvidos. Falta confirmação humana específica
da proposta antes de iniciar os recursos novos, inicializar seu banco/contas e
executar uma única campanha. Não fechar #80/#14 com este relatório de preparação.

## Substituição após expiração — 18/11/2026

A confirmação humana “sim” foi constatada às12:27:06UTC (09:27:06SP), após o
prazo12:07:07UTC do pacotea4335444. Seu conteúdo/PKI permanecem preservados;
recebimento registrado separadamente em `approval-received-expired.json`, com
`effects_authorized=false`. Sem `authorization.json`, `attempt.json`, recursos
ou efeito nativo. A confirmação tardia não foi transferida para outro pacote.

Novo pacote `202afac50f69432681adabf07baaaaed`, SHA256
`21e4cad0f9287de38861cc9e0aa903e0f7ccd5c4c5b4affd7c647675f6ab068b`,
gerado às12:27:54UTC, até19/11 às00:27:54UTC (18/11 às21:27:54SP).
Coordenador a19257f, executáveis idênticos à c974380 da CI integral verde acima.
Mesmas quatro imagens, efeito único, limites de1728MiB e3072MiB disponíveis,
sem volumes originais. UUIDs/PKI e projeto novos, detalhados na proposta atual.
Não houve rebuild, migração, startup ou campanha durante essa substituição.

Comandos efetivamente executados: `atomic_assay.py prepare` com o mesmo build
de aplicação e recibo fixados, seguido de `verify --package-id 202afac50f69432681adabf07baaaaed
--expected-sha256 21e4cad0f9287de38861cc9e0aa903e0f7ccd5c4c5b4affd7c647675f6ab068b`,
saída0/`proposal_verified_not_authorized`. OpenSSL `verify -purpose sslserver
-verify_ip 192.168.253.2` e `verify -purpose sslclient` passaram com as respectivas
CAs novas; duas folhas válidas até20/11 às12:27:54UTC. Isso não prova mTLS nativo.
Fences/autorizações ausentes no pacote novo. Aguardando confirmação específica
do novo hash, conforme procedimento sem renovação silenciosa. #80/#14 abertas.
