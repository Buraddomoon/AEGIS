# Proposta específica da campanha — 12/11/2026

**Pacote confirmado pelo usuário e consumido. Não reutilizar.**
O [relatório nativo](CAMPAIGN-2026-11-12.md) registra backup/upgrade original
concluídos e tentativa encerrada antes de qualquer campanha por catálogo
versionado ausente. As seções seguintes preservam a proposta original.
Detalhamento: [CAMPAIGN-ASSAY](CAMPAIGN-ASSAY.md), etapas1–8.
Este arquivo também é o checkpoint curto da entrega #5.

## Identificação do pacote (#53)

- SHA256 canônico do escopo:
  `8999d77a57f481318b7f421960d4a0424d41abe1a1d1cb159bfca2c07c443619`.
- Tentativa exclusiva: `9380cd05-c9a7-4881-8cc3-12152d3ac551`.
- Preparado em12/11/2026 às13:51UTC; válido até **15:51UTC (12:51Brasília)**
  do mesmo dia. Revalidar TTL/recursos antes de operar; expiração exige outro
  pacote/aprovação, sem reutilizar o anterior.
- Fonte executável: `ad6079394b5a7171a6729188625ad97c73a83b8c`.
- Configuração/binding esperado:
  `5cfe848b5c47b3fb31694e348b68c768c79216defb646506f16467d619e18ecd`.
- PKI: candidato atual `81826566e88e4c9ebc8b9aa09c8a8d02`; folhas válidas
  até13/11/2026 às21:37:25UTC, cadeia/SAN/EKU/validade offline conferidos.
  Isso não comprova novo handshake nativo.
- Aplicação nova em tag exclusiva `aegis-linux-campaign:ad60793`, ID
  `sha256:7a931890d91b8cceca1f12f265a8ff1c179e1c8663f7a2efb94b0b9d4e76e6e3`.
  Build inclui SPA atual e gate de schema. O Demo continua na imagem b8 retida.
- Runner, PostgreSQL e Redis: IDs completos no runbook; todos existem localmente.
- Manifesto privado: `.local/linux-campaign/proposal.json`; imagens em
  `.local/linux-campaign/images.env`. Manifesto inclui hashes de arquivos,
  configuração renderizada, metadados dos volumes, IDs e orçamento de recursos.
  Nenhuma chave/credencial foi adicionada ao Git. Hash identifica conteúdo;
  não representa assinatura/aprovação.

## Aprovação solicitada

Autorizar neste host, sob o pacote acima, **backup frio novo e validação em
clone; upgrade explícito do PostgreSQL original d446→b7 com grants mínimos e
senhas existentes preservadas; duas contas temporárias; e uma única campanha
Linux de43bytes**, com solicitante/aprovador distintos, filho≤5s, lease2s,
run≤60s e supervisão global≤15min. Confirmar API/UI/relatórios/cleanup e encerrar
revogando lab, desativando contas/sessões e removendo só containers/redes próprios.

Recursos: somente projeto `aegis-linux-lab`, seus dois volumes originais,
rede runner192.168.253.0/29 e API loopback18785. Sem Wazuh, seed/bootstrap,
reset de contas antigas, nova tentativa, alteração de qasrc ou remoção de
backups/volumes/diário/fences/PKI. Qualquer divergência bloqueia antes do efeito.

O upgrade original é uma intervenção nova: a #48 só migrou clones. O snapshot
da #48 precede a mudança de binding; por isso se exige backup fresco. Não
executar o antigo comando `migrate` que também fazia seed e mudava senha runtime.

## Estado das subissues

| Subissue | Resultado desta preparação |
|---|---|
| #52 | Configuração atual, imagens fixadas, render/inspeção offline, gate sem migração implícita e testes locais entregues |
| #53 | Pacote concreto preparado; aprovação específica ainda ausente |
| #54 | Bloqueada pela #53; nenhuma run real nova, migração original ou startup |
| #5 | Aberta até aprovação, ensaio real e aceite conjunto |

Validação local da fonte:36testes de preparação/campanhas/schema e127do runner,
**163casos distintos aprovados**; upgrade/dump/restore efetivos somente no schema
aleatório da fixture, sem skip local. Render real do Compose aprovado com os
quatro IDs finais; sete mutações inseguras recusadas. Ruff lint/format, mypy,
build SPA/imagem e checks staged/release/diff aprovados. Nenhuma nova suíte
PG/Redis15 foi executada em paralelo.

A rodada intermediária encontrou três erros no uso de `Path.open(opener=...)`,
corrigidos com o `open` da biblioteca padrão. Encontrou também comparação de ACL
owner explícita versus implícita após restore; o inventário de teste passou a
comparar ACL canônica ordenada, sem ignorar grants/revogações. A rodada final
completa dos três arquivos passou36/36; falhas intermediárias não são verdes.
Aviso existente de Starlette/httpx continua.

CI integral da fonte:
[43230983327](https://github.com/Buraddomoon/AEGIS/actions/runs/43230983327),
**pendente na preparação deste checkpoint**. Source-review
[43230983214](https://github.com/Buraddomoon/AEGIS/actions/runs/43230983214)
aprovada. Não declarar workflow verde antes de conferir quatro partições Python
mais React. Documentação posterior não altera a fonte executável da imagem.
