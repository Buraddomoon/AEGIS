# Pedido de ensaio histórico — #66, plano d8665fed

**PREPARED_NOT_AUTHORIZED.** Código/testes e plano concretos; nenhum conteúdo dos
volumes originais foi aberto. Aprovação humana específica ainda necessária.

- Plano: `d8665fed78e349cea4080b2519157d85`.
- SHA256 canônico: `17d63858350c61f1ebcbe4a167b8c8e9f046bfd422cbefcbc262b760bf765f5e`.
- Fonte: `bce1f874bf111923267eb522cd015e30d508de2c`.
- Código do coordenador: `f7b087c2b5f8683764c0723ce4d846b450f020369c6a58306f6d45cd5b228936`.
- Preparado24/11/2026 às18:01:33UTC; expira25/11/2026 às18:01:33UTC.
- Plano completo privado:
  `.local/lab-recovery/plans/d8665fed78e349cea4080b2519157d85/plan.json`.

## Leitura autorizável

Somente os volumes históricos abaixo, parados, com mounts **RO/nocopy**:

| Projeto | Volumes |
| --- | --- |
| Linux histórico | `aegis-linux-lab_postgres-data`, `aegis-linux-lab_journal` |
| Wazuh histórico | `aegis-wazuh-lab_postgres-data`, `aegis-wazuh-lab_journal` |

Também copiar localmente o perfil de custódia definido no
[procedimento](../../operations/lab-recovery-native.md): **3689arquivos,
20.457.443bytes**, no checkout principal e no legado `~/codes/aegis`, incluindo
`.env`, PKI/chaves privadas, configurações e JSON/JSONL/locks de planos, intents,
candidatos expirados e autorizações consumidas dos prefixos AEGIS declarados.
O plano enumera paths/atributos; preparação consultou apenas metadados. Conteúdo
é privado,0700/0600, sem Git/upload, sem copiar de volta aos caminhos ativos.

## Efeitos exatos

- Até16containers próprios sequenciais, no máximo um simultâneo; somente imagem
  PostgreSQL17 já existente por ID
  `sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24`.
- Helpers tar leem os quatro originais em RO. PostgreSQL roda **somente em cópias**
  privadas e em dois clusters novos de restore, sem rede/portas, API, worker,
  runner normal, scheduler ou SIEM. Originais não são iniciados ou montados RW.
- Verificar fonte b7/33tabelas e provas CLEANED/diário; dump real, banco novo,
  restore transacional e comparação completa, locale/encoding e custódia.
- Repetir leitura RO dos originais para igualdade byte a byte, encerrar/remover
  somente os recursos próprios e publicar recibo apenas após cleanup confirmado.
- CPU1/até384MiB/64PIDs, rootfsRO/cap-drop/no-new-privileges; prazo900s para novos
  efeitos, cleanup após prazo permitido. Preflight1536MiB RAM disponível/4GiB disco.
  Não parar terceiros, reduzir gates ou modificar host/rede para passar.
- Reter backups/artefatos/tentativas privados. Sem marcador, campanha, cutover,
  migração, renovação PKI/binding, alteração de contas/grants originais ou exclusão.
  Qasrc e demais volumes/imagens/serviços preservados. Operação normal permanece false.

O plano é de uso único. Hash não é assinatura ou aprovação. Divergência/ambiguidade
impede declarar sucesso; não reutilizar pedido consumido nem editar histórico.
O aceite do plano autoriza apenas esse ensaio de recuperação, não outra entrega.

[Implementação/provas da retomada](RESUMPTION.md). A CI final deve estar aprovada
antes do ensaio. Depois de aprovado e executado, registrar resultados reais,
encerramento, aceite conjunto e fechar #66/#9 somente se todos os critérios passarem.
