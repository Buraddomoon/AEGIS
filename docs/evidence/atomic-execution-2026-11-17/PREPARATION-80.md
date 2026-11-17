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
Proposta concreta: [pacote91de0d6f](../../../labs/linux/ATOMIC80-REQUEST-2026-11-17.md).

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

As runs intermediárias da CI foram substituídas/canceladas após os commits de
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
Aviso conhecido Starlette/httpx preservado. Lint/tipos/formato aprovados.

CI integral da fonte4759805:
[44202869465](https://github.com/Buraddomoon/AEGIS/actions/runs/44202869465),
em andamento; conferir quatro Python e React antes do aceite da preparação.
Não confundir testes ou RUNs de build com ensaio nativo/mTLS/telemetria.

## Proposta sem autorização

Pacote91de0d6f preparado e `verify` real aprovou SHA256
`b99e3ac0e9f0e644333431c31da640f75a3ac0f467dbd9d02f62a5559d24cf05`.
Receita Compose renderizada sem create/start. PKI nova conferida offline:
OpenSSL verify serverAuth/clientAuth e IP192.168.253.2 OK; folhas até
19/11/2026 às23:51:20UTC. Proposta expira18/11 às11:51:20UTC; revalidar tudo
antes de operar. Hash de executáveis prende o coordenador4759805, permitindo
somente consolidação Markdown posterior, sem mudar autorização/escopo histórico.

`authorization.json` e `attempt.json` ausentes; efeitos não autorizados.
Os bloqueios de preparação foram resolvidos. Falta confirmação humana específica
da proposta antes de iniciar os recursos novos, inicializar seu banco/contas e
executar uma única campanha. Não fechar #80/#14 com este relatório de preparação.
