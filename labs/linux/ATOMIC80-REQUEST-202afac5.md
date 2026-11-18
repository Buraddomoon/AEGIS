# Proposta específica #80 — uma campanha Atomic adaptada

**AUTORIZADA, CONSUMIDA E ENCERRADA em18/11/2026.** Uma campanha real
COMPLETED/INCONCLUSIVE/CLEANED, run `a9dc99b1-921f-4d94-be1f-70525c89fb4a`.
Lab revogado, contas próprias inativas, recursos encerrados; três volumes retidos.
[Provas](../../docs/evidence/atomic-execution-2026-11-18/VERIFIED-80.md).
A proposta privada original e os registros posteriores permanecem preservados.
O texto abaixo registra a preparação apresentada; não permite replay.

**Preparada/verificada; não autorizada nem executada.** Não reutiliza pacotes
ou autorizações dos ensaios anteriores. Não iniciar recursos apenas por ler
esta proposta. [Procedimento e controles](../../docs/operations/atomic80-assay.md).

Esta proposta substitui a [a4335444 vencida](ATOMIC80-REQUEST-a4335444.md).
A confirmação anterior chegou após o prazo e não foi convertida em autorização
deste novo hash. Imagens, efeito e limites mantidos; PKI, UUIDs e prazo novos.

## Identificação

- Pacote `202afac50f69432681adabf07baaaaed`.
- SHA256 canônico da proposta privada:
  `21e4cad0f9287de38861cc9e0aa903e0f7ccd5c4c5b4affd7c647675f6ab068b`.
- Tentativa exclusiva `077333c3-7294-48a9-9169-d56a15e91408`.
- Criada18/11/2026 às12:27:54UTC; válida até **19/11/2026 às00:27:54UTC
  (18/11 às21:27:54 em São Paulo)**. Expiração/drift bloqueiam; não renovar silenciosamente.
- Coordenador `a19257fb4c96afcbf5982884e032d2bdcae32fa4`; aplicação construída
  de `8b4678ed6dcb75a84841308f45a9c3f76dadd887`. Helpers da imagem são idênticos
  aos do coordenador. Fonte executável igual à c974380, cuja CI integral passou;
  a19257f consolidou somente Markdown.
- Proposta/PKI/segredos/receita privados em
  `.local/atomic80-packages/202afac50f69432681adabf07baaaaed`.
  Não existem `authorization.json` ou `attempt.json` nesta preparação.

## Alvos e recursos novos

Projeto exclusivo `aegis-atomic80-202afac50f69`:

| Identidade | UUID |
| --- | --- |
| Laboratório |`216fd641-6cc9-4244-abea-ae3434605118` |
| Ativo |`54468877-4bed-45eb-ada6-fe8cefb7accb` |
| Runner |`23227d22-f814-42a8-be53-93789e6ed00b` |

Três volumes **novos**: sufixos `_database`, `_journal`, `_evidence` desse
projeto. Nenhum original/backup/clone/journal antigo é montado. Duas redes novas
internas isolated, `192.168.253.0/29` e `192.168.253.8/29`, sem IPv6/portas no
host, sem ligação com qasrc ou outras redes. Preflight RO de redes/rotas passou
na preparação e será repetido antes de criar recursos; não reserva a faixa.

PKI nova e separada: cadeias, EKUs e SAN/IP conferidos offline por OpenSSL.
Folhas válidas até20/11/2026 às12:27:54UTC. Isso não comprova handshake nativo.
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
