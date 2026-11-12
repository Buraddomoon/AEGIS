# Escopo adicional: registro do catálogo e campanha única

**Pacote aprovado pelo usuário (“pode”), consumido e encerrado. Não reutilizar.**
[Resultado final](CAMPAIGN-VERIFIED-2026-11-12.md): uma campanha real, cleanup
confirmado, UI/relatórios conferidos, lab revogado e contas próprias inativas.
As seções seguintes preservam a proposta original.
A [tentativa anterior](CAMPAIGN-2026-11-12.md) terminou sem campanha/marker, com
backup/upgrade original concluídos e cleanup confirmado. O pacote anterior
continua consumido e não autoriza o bootstrap abaixo.

## Pacote fixado

- Escopo SHA256:
  `3c6f96b1fa86d1c5773d5f66996ffdd5e3b264fdcd01b5fafc47e6cc1fd7aca3`.
- Tentativa nova exclusiva: `c657ef60-51c9-44b1-aa82-cbd75f87758e`.
- Válido até **12/11/2026 16:10UTC (13:10Brasília)**; revalidar antes dos efeitos.
- Fonte executável: `752ad29ffef979ce2a846df986d2381afd7a7d01`, com gate que
  recusa catálogo não inicializado antes de API/worker/contas.
- Imagem em tag exclusiva `aegis-linux-campaign:752ad29`, ID
  `sha256:ba50a78c97556d562ad550fc05b4c76803f1c89c8e8bb886cc06fb7ca700a49a`.
  Build concluído; imagens anteriores e Demo b8 preservados.
- Runner/PG/Redis, PKI e IDs: os mesmos revisados no pacote anterior. Folhas
  expiram13/11 às21:37:25UTC. Render novo com quatro IDs aprovado sem startup.
- Original esperado **b7/33tabelas**, lab revogado, ambiente4, zero reservas;
  uma run/um dispatch históricos. Duas contas da tentativa anterior inativas,
  zero sessões próprias; duas sessões históricas preservadas.
- Manifesto privado `.local/linux-campaign-next/proposal.json`, imagens e helper
  no mesmo diretório0700. Hash identifica conteúdo, não representa assinatura.

## Intervenção proposta

1. Fazer backup frio fresco e validar em clone isolado, preservando fontes,
   backups anteriores, histórico e todas as contas encerradas. Não repetir a
   migração original, que já terminou; não fazer restore/downgrade no original.
2. Conferir novamente a projeção legada, os hashes do snapshot distribuído e
   licença e a ausência de registros nas duas tabelas de versão. A comparação
   nativa em leitura confirmou **706técnicas idênticas** ao snapshot; hash da
   projeção:
   `3a35b701a40b6ca92c34df9b7e37f2eff2679cd0115cc7858774376dc100527d`.
3. Inicializar **somente os metadados de versão do catálogo** por
   `aegis.catalog.store.initialize`: primeiro no clone e, após conferir, no
   original. Helper fechado exige schema b7, lab revogado/sem reservas,
   tabelas de versão vazias e projeção não vazia exatamente igual ao snapshot.
   Resultado permitido: **uma release, um ponteiro de catálogo e auditoria**.
   As706técnicas existentes não são reescritas. Qualquer divergência bloqueia;
   não adaptar/remover técnicas para fazer a igualdade passar.
4. Iniciar a configuração revisada e executar **uma única campanha de43bytes**,
   usando duas **novas** contas temporárias (administrador e operador distintos),
   preflight mTLS vigente, aprovação nova e scope hash exato. Não reativar as
   contas da tentativa anterior nem apagar seu registro/fence.
5. Conferir efeito/recibo/cleanup físico, API/UI e relatórios do mesmo UUID;
   sem SIEM, INCONCLUSIVE e synthetic=false. Encerrar com lab revogado, contas
   próprias inativas/zero sessões próprias e recursos próprios removidos.

Os demais limites do [procedimento](CAMPAIGN-ASSAY.md) continuam: projeto
`aegis-linux-lab`, volumes originais preservados, runner192.168.253.0/29, API
loopback18785, filho≤5s, lease2s, run≤60s, supervisão≤15min; sem Wazuh, acesso a
qasrc, seed geral, reset de senhas, shell remoto, nova tentativa automática,
reescrita de históricos ou remoção de PKI/backups/volumes/diário/fences.
O bootstrap **restrito de metadados do catálogo** é a única autorização técnica
adicional solicitada; não inclui `python -m aegis.cli seed`.

## Verificação da preparação

38testes focados de preparação/campanhas/schema passaram em40,02s, incluindo
recusa de catálogo ausente sem bootstrap e inicialização explícita em fixture
sem modificar técnicas existentes.127testes do runner passaram na preparação
anterior; runner não mudou. Não somar rodadas sobrepostas. Ruff lint/format,
mypy, build e render aprovados; nada disso comprova campanha nativa.

CI original ad60793 [43230983327](https://github.com/Buraddomoon/AEGIS/actions/runs/43230983327)
SUCCESS:3196Python/9skips opcionais e91React, quatro partições conferidas.
CI da correção752ad29 [43234227462](https://github.com/Buraddomoon/AEGIS/actions/runs/43234227462)
está em andamento; source-review43234227204 aprovada. Não chamar a workflow
nova de verde antes de conferir todos os jobs. #53/#54/#5 permanecem pendentes
do novo escopo e do ensaio real, sem avançar para outra entrega.
