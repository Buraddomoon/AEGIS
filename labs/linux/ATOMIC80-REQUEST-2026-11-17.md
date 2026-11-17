# Proposta específica #80 — uma campanha Atomic adaptada

**Preparada/verificada; não autorizada nem executada.** Não reutiliza pacotes
ou autorizações dos ensaios anteriores. Não iniciar recursos apenas por ler
esta proposta. [Procedimento e controles](../../docs/operations/atomic80-assay.md).

## Identificação

- Pacote `91de0d6f018348159c1cf8635404c3b2`.
- SHA256 canônico da proposta privada:
  `b99e3ac0e9f0e644333431c31da640f75a3ac0f467dbd9d02f62a5559d24cf05`.
- Tentativa exclusiva `30164c96-0b89-4b6c-9a11-415f1a559eb5`.
- Criada17/11/2026 às23:51:20UTC; válida até **18/11/2026 às11:51:20UTC
  (08:51:20 em São Paulo)**. Expiração/drift bloqueiam; não renovar silenciosamente.
- Coordenador `4759805cfff4fc31ac5231220d0440fed6594019`; aplicação construída
  de `8b4678ed6dcb75a84841308f45a9c3f76dadd887`. Helpers da imagem são idênticos
  aos do coordenador; sua diferença posterior trata leitura de metadata/pins.
- Proposta/PKI/segredos/receita privados em
  `.local/atomic80-packages/91de0d6f018348159c1cf8635404c3b2`.
  Não existem `authorization.json` ou `attempt.json` nesta preparação.

## Alvos e recursos novos

Projeto exclusivo `aegis-atomic80-91de0d6f0183`:

| Identidade | UUID |
| --- | --- |
| Laboratório |`d71cd521-15f0-470b-9cd1-e22ca130342c` |
| Ativo |`00871896-d6c9-488b-9457-17371ed7da97` |
| Runner |`f35bc5e6-9728-4eb0-b29c-be3cb18ab333` |

Três volumes **novos**: sufixos `_database`, `_journal`, `_evidence` desse
projeto. Nenhum original/backup/clone/journal antigo é montado. Duas redes novas
internas isolated, `192.168.253.0/29` e `192.168.253.8/29`, sem IPv6/portas no
host, sem ligação com qasrc ou outras redes. Preflight RO de redes/rotas passou
na preparação e será repetido antes de criar recursos; não reserva a faixa.

PKI nova e separada: cadeias, EKUs e SAN/IP conferidos offline por OpenSSL.
Folhas válidas até19/11/2026 às23:51:20UTC. Isso não comprova handshake nativo.
Somente folhas/chaves de endpoint e CAs públicas são montadas; CAs privadas
ficam no host. API acessível apenas pelo controlador na rede própria.

| Serviço | Imagem local imutável |
| --- | --- |
| API/worker/helpers |`sha256:3ae40c8ce7c93f0a1b40c91ecc84facaf1ecb6d8ee74e841765f81a0aa5a81c7` |
| Runner |`sha256:c0fb88c5cf97ab20b41e6f4d45a7647c98161dd29d0408d296c11a4b6bb38e5f` |
| PostgreSQL |`sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24` |
| Redis |`sha256:3811787313eba226a2ef38658c6ccb91cd5e110edc89c37767de373120a0e5a0` |

Builds de runner/aplicação passaram com fontes/versões/imports/assets conferidos;
tags exclusivas e imagens anteriores retidas. São verificações locais, sem
assinatura/atestado do publicador ou autorização de laboratório.

Pico previsto1728MiB, exigindo MemAvailable≥3072MiB antes de iniciar. Limites por
serviço e isolamento no procedimento; sem alterar swap/sysctl ou outros projetos.
Operação≤15min, run≤60s, efeito≤5s, lease2s. Falha não autoriza replay.

## Intervenção solicitada

Autorizar **somente este pacote e uma tentativa** neste host:

1. Criar os recursos novos acima; inicializar explicitamente o banco novo
   `atomic_assay` com owner próprio, c8/36tabelas, seed versionado e grants mínimos.
   Não abrir/migrar/semear/resetar banco original ou contas históricas.
2. Criar duas contas temporárias próprias, administrador e operador distintos;
   registrar somente o lab novo, verificar prontidão e mTLS real, autorizar lab,
   solicitar pelo operador e aprovar pelo administrador com scope hash exato.
3. Executar **uma campanha**, somente `atomic-file-permissions-v1`, GUID
   `34ca1464-de9d-40c6-8c77-690adf36a135`, revisão
   `9e283889776cbd42ebf9b7b25bc1ebfbad452157398ecbe0ab77415136c35673`:
   arquivo próprio de43bytes,0400→0600 por fchmod, sem shell/chmod/YAML upstream,
   elevação, outro GUID, caminho livre, credenciais ou dados de terceiros.
4. Verificar execução/recibo/modos/hash/cleanup e JSON/HTML da mesma run. Sem
   fonte/regra defensiva configurada: resultado esperado **INCONCLUSIVE**,
   synthetic=false, sem inventar alerta, DETECTED ou eficácia de T1222.002.
5. Revogar lab, inativar as duas contas e remover suas sessões; encerrar apenas
   containers/redes próprios após cleanup confirmado. Preservar três volumes,
   diário/fences, imagens, PKI e provas. Se ambíguo, manter quarentena e reconciliar
   a tentativa original; não criar outra campanha nem limpar desconhecidos.

O fence exclusivo é persistido antes do primeiro create. UUID/escopo da run são
persistidos antes de approve/start. A autorização humana deve referenciar esta
proposta; hash identifica conteúdo, não é assinatura ou aprovação por si só.
#80 e pai #14 permanecem abertos até o ensaio/aceite reais.
