# Proposta específica #83 — dois comportamentos fixos, uma tentativa por teste

**PREPARADA/VERIFICADA, NÃO AUTORIZADA NEM EXECUTADA.** O pedido de iniciar a
#83 foi usado para preparar esta proposta concreta; não há `authorization.json`
ou `attempt.json` em nenhum dos dois pacotes. Autorizações #5/#14 consumidas,
originais/PKI/volumes/journals/fences preservados. [Controles](../../docs/operations/linux83-assay.md).

## Pacotes concretos

| Campo | Processo | Shell fixo |
| --- | --- | --- |
| Perfil | `linux83-process` | `linux83-shell` |
| Pacote | `0a85302e48bc4ecb9f854ba3881f89c0` | `22431af466174de6ab37ae9261d1c672` |
| SHA256 canônico da proposta privada | `49b5c8080df6ee962ee99cd44f7cc5ef1bd219bf3f62763d093b553214d66fb1` | `d376eafc1ed3f3edf3549e27367ba0e402ab75db134fbed8c9c97d9235046352` |
| Tentativa | `7832bf68-ce2a-4d52-87e0-132a7d42f369` | `5a687cac-8245-47fe-bf3d-983db6356fb7` |
| Projeto | `aegis-linux83-0a85302e48bc` | `aegis-linux83-22431af46617` |
| Lab | `579607a5-e5c5-4649-aeae-c634d76e88d4` | `4fce0689-eee5-4dff-9eed-b1e47a69cc75` |
| Ativo | `2d408ac0-4b59-4bdf-b18d-d8277f6f6949` | `c2d87134-16fb-4221-a1e2-da65d96926a5` |
| Runner | `a9ba8e9c-4d97-499a-90bd-fc0a6abf2388` | `80f959e5-df7e-4f75-94a1-5200904dee45` |
| Validade UTC | 18/11 13:51:43 a19/11 01:51:43 | 18/11 13:51:45 a19/11 01:51:45 |

Prazo comum conservador: **18/11/2026 às22:51:43 em São Paulo**. Expiração/drift
bloqueiam; não renovar silenciosamente. Cada proposta privada/receita/PKI fica
em `.local/linux83-packages/<id>`, protegida. Hash é integridade, não assinatura
ou autorização por si só. Coordenador/aplicação construídos da fonte
`1dcff254b7af0e699676cdfcbfd1508e9f747cec`; consolidação posterior só documental.

## Imagens locais fixadas

| Serviço | ID imutável |
| --- | --- |
| API/worker/helpers | `sha256:b25b2bc0fdc4483c0cd940fa4dc4d2b66ae2d53c643166e979a6b2782003c062` |
| Runner | `sha256:8b173422b000caa26b95b1c2ecd557fae14ef4e49a108f1588115067d48e46d0` |
| PostgreSQL | `sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24` |
| Redis | `sha256:3811787313eba226a2ef38658c6ccb91cd5e110edc89c37767de373120a0e5a0` |

Builds offline passaram, usando48wheels/30.384.557bytes conferidos por hash e
blobs fixados de main. Runner em tag exclusiva
`aegis-runner-review:ebc43ab5a9964efcb54f9b84cfdb1726`, aplicação em
`aegis-atomic80-application:bc9b13a62eee4d0f9e27b5eebddff9a2` (nome legado do
builder compartilhado). Tags/base anteriores retidas, sem pull/push de imagem.
Check fresco no build conferiu pacote instalado/versões/imports e assets dos
helpers; não é assinatura/atestado do publicador nem implantação de laboratório.

## Recursos, isolamento e pré-condições

Cada projeto criará somente seus três volumes novos `_database`, `_journal`,
`_evidence`. **Seis volumes próprios no total, todos retidos ao encerrar.** Na
verificação da proposta não havia container/rede/volume de nenhum desses projetos.
Não há montagem de original/backup/clone ou acesso a contas históricas.

Cada tentativa usa duas redes novas internas isolated192.168.253.0/29 e
192.168.253.8/29, sem IPv6/portas host/qasrc. API só pelo controlador em
192.168.253.4:8080; runner mTLS em192.168.253.2:8443; DB/Redis só no backend.
Preflight RO de redes/rotas passou e será repetido antes de create.

As duas tentativas são **sequenciais**: a segunda só começa após a primeira
confirmada CLEANED, lab revogado/contas inativas/sessões removidas e recursos
próprios encerrados. Reserva/quarentena da primeira bloqueia a segunda; não
criar rede alternativa ou ampliar alvo para contornar o bloqueio.

PKIs separadas, SAN/IP/EKU/cadeias conferidos offline por OpenSSL. Folhas do
primeiro pacote válidas até20/11 às13:51:43UTC e do segundo até13:51:45UTC.
Somente folhas/chaves de endpoint e CAs públicas entram nos serviços; CAs
privadas ficam no host. Handshake mTLS nativo ainda não foi executado.

Pico1728MiB por tentativa, MemAvailable mínimo3072MiB. Leitura inicial2819MiB
bloqueava; leitura posterior3574MiB passou naturalmente, sem intervenção em outro
projeto/host. Rechecar antes de cada início; não reduzir piso. Limites/runtime
no procedimento: app/runner UID10001/rootfs RO/caps ALL removidas/no-new-privileges,
Redis999:999/rootfs RO/tmpfs; PG usa entrypoint oficial/rootfs gravável para seu
volume novo. Limites de CPU/PIDs e tmpfs próprio. Operação≤15min por tentativa, run≤60s,
efeito≤5s/lease2s; falha não concede replay ou operação contínua.

## Intervenção solicitada — somente estes dois hashes

1. Criar somente os recursos novos descritos, um projeto por vez; inicializar
   explicitamente cada banco vazio `linux83_assay`, owner novo `linux83_owner`,
   c8e4a6d21f90/36tabelas, seed versionado e grants mínimos. Não abrir/migrar/
   semear/resetar original ou contas históricas.
2. Criar duas contas UI próprias por projeto, administrador e operador distintos;
   registrar apenas o lab novo inicialmente revogado, verificar prontidão RO,
   isolamento e mTLS nativos, autorizar lab e solicitar/aprovar escopo exato por
   usuários distintos. Persistir tentativa/UUID/escopo antes de qualquer start.
3. No pacote de processo, uma campanha `linux-process-canary-v1`, identidade
   `linux-process-canary/v1@5d16dd8867b4f8f06163311cfbdd1d754a03784c7c53212cb1709d29738b52e3`:
   um `/bin/true <marker>` sem técnica, exit0/stdout0 e43bytes próprios.
4. Depois do encerramento seguro do primeiro, no pacote de shell, uma campanha
   `linux-shell-canary-v1`, identidade
   `linux-shell-canary/v1@1baab18c75ad4a6ce8534962582fd61ae490eef1240ea8db9245af1c092438cb`:
   um `/bin/sh -c <printf fixo> <marker>`, stdout43 e artefato43bytes. Código
   literal `printf '%s\n' "$0"`, marcador UUID separado, sem comando/entrada livre,
   rede externa, descoberta, privilégio, persistência ou execução Atomic/YAML.
5. Conferir cada run/recibo/PID/exit/stdout/hash/cleanup e JSON/HTML da mesma
   execução. Sem sensor/regra defensiva: esperado **COMPLETED/INCONCLUSIVE/CLEANED**,
   synthetic=false, sem eventos/alertas fabricados ou eficácia ATT&CK alegada.
6. Revogar cada lab, inativar suas duas contas/remover sessões e encerrar somente
   containers/redes próprios após cleanup confirmado. Reter seis volumes, PKI,
   imagens, diários/fences e provas. Se ambíguo, preservar/quarentenar e recuperar
   somente a tentativa original; não criar nova run nem avançar ao segundo pacote.

[CI integral44317530894](https://github.com/Buraddomoon/AEGIS/actions/runs/44317530894)
SUCCESS na fonte fixada:3733Python/9skips opcionais justificados e98React; quatro
grupos e React conferidos. [Provas da preparação](../../docs/evidence/linux83-2026-11-18/PREPARATION.md).
Até aprovação específica, não criar autorização/fence, iniciar laboratório ou
executar efeito. #83 e #15 continuam abertas.
