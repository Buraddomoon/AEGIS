# Ensaio nativo fechado da #104

Esta preparação atende somente #23/#104. Não é execução automática de CI, nem
autoriza um laboratório por si só. O workflow manual `scheduling-native.yml`
prepara um pacote em uma VM Linux nova do GitHub Actions. Não usa este Windows,
nenhum host ou volume original, PKI histórica ou configuração do Demo.

## Preparação sem efeito

`scripts/scheduling_assay.py prepare` exige workflow_dispatch, `main`, tentativa1
e fonte limpa igual ao SHA da execução. Faz build dos Dockerfiles existentes em
tags exclusivas e contexto de blobs commitados; fixa IDs imutáveis de aplicação,
runner, PostgreSQL17 e Redis8. Não cria redes, volumes ou serviços de laboratório.
Gera três identidades UUID novas, PKI mTLS separada e duas contas próprias; os
segredos ficam somente na VM, sob diretórios0700. Nenhuma chave/credencial é
publicada. O artefato de proposta contém manifesto, fingerprints públicos,
compromissos SHA256 dos arquivos privados e instrução de aprovação. Hash não é
assinatura nem atestado de origem da imagem.

O pacote identifica workflow/host, código, imagens, identidades, redes, receita,
fingerprints, prazo UTC e escopo fechado. Validade30min; a autorização deve chegar
com pelo menos5min restantes. Não renovar pacote/PKI/prazo silenciosamente.

## Escopo a autorizar

- Laboratório novo `aegis-scheduling104-<workflow_run>`, sem volumes originais.
- Exatamente **duas ocorrências** de `linux-file-marker/v1`, uma por vez, intervalo
  60s, duração máxima30s por run. Cada efeito produz43bytes próprios no tmpfs,
  máximo5s, lease2s e supervisor do runner existente.
- Janela de cada agenda: início futuro25s após proposta na UI, fim até180s após
  essa proposta, sempre dentro do prazo UTC do pacote. Sem ampliar orçamento,
  reaprovar, emitir campanha manual ou recuperar por replay.
- Rede runner interna isolated `192.168.253.0/29`; backend interno
  `192.168.253.8/29`. Browser da própria VM acessa somente API nova em
  `192.168.253.12:8080`. Nenhuma porta publicada no host, host networking ou
  socket Docker dentro da aplicação. Colisão de rede/rota/nome bloqueia.
- Runner/API/worker UID10001, rootfs RO, caps removidas, no-new-privileges,
  64PIDs e1CPU cada. Memória192/512/256MiB. DB384MiB/128PIDs/1CPU com entrypoint
  oficial; Redis128MiB/64PIDs/1CPU, configuração secreta e sem persistência.
  Helper administrativo256MiB em fase separada. Exigir MemAvailable≥3072MiB;
  não alterar memória/swap/sysctl/host para passar.
- Banco novo `schedule104`, owner próprio e grants mínimos `aegis_app`.
  Migração explícita e2a/36tabelas somente se vazio; seed versionado e duas contas
  próprias distintas. Resposta ambígua de bootstrap não é repetida.
- Sem SIEM/EDR/Wazuh, shell ou Atomic. Resultado esperado **INCONCLUSIVE** e
  `synthetic=false`; recibo não equivale a detecção.
- Provas públicas apenas desse ensaio novo: manifesto, IDs/recibos/cleanup,
  snapshots JSON/HTML/PDF e screenshots sem senhas. PKI, credenciais, dumps,
  diário bruto e logs privados não são artefatos de upload.
- Revogar agenda/lab, desativar duas contas e remover suas sessões; confirmar
  cleanup e workspace vazio antes de encerrar containers/redes próprios.
  Não executar `down -v`: os dois volumes próprios ficam sem consumidores até
  o descarte automático da VM efêmera pelo provedor. Nenhum dado original é
  transportado ou descartado. Essa característica do ambiente deve constar
  expressamente da aprovação do pacote.

## Barreira humana e tentativa única

Depois de publicar a proposta, `wait` não cria laboratório. Aceita somente um
comentário posterior do usuário GitHub que iniciou a preparação, na #104, com o
texto exato fornecido no resumo do workflow. Ele inclui SHA256 integral do pacote,
run de preparação, duas ocorrências, perfil fixo, ausência de originais e aceite
de provas sanitizadas/descarte do host efêmero. Comentário antigo, outro ator,
hash/host diferente ou mudança de orçamento é recusado. O assistente não deve
criar esse comentário sem aprovação humana específica do pacote apresentado.

`run` revalida o comentário na API GitHub e os arquivos/imagens/receita, redes e
memória. Consome fence exclusivo/fsynced antes do primeiro create. O mesmo pacote
não pode ser executado duas vezes; rerun de workflow também é recusado. Se a
aprovação não chegar no prazo, a tentativa encerra com **zero efeitos**, sem
concluir #104. Não converter timeout ou falha em autorização.

## Prova nativa e recuperação

O browser Firefox usa API real, dois contextos de sessão independentes e UI de
proposta/aprovação. Nenhum endpoint é interceptado e o relógio não é alterado.
Só o worker emite as duas ocorrências. Conferir mesmo grant, pedidos distintos,
dispatch/receipt/cleanup,43bytes, completude e duas runs COMPLETED/INCONCLUSIVE,
sem evento defensivo fabricado. Snapshots baseline/comparação e três exports são
da mesma recorrência; revogação não altera os documentos congelados.

Helper de owner revoga exclusivamente o lab/agenda/contas novos, mesmo se a UI
falhar. Cleanup não confirmado mantém quarentena e status de falha; nenhum novo
efeito é usado para corrigir a prova. A VM possui lifecycle limitado pelo
workflow; o lease/supervisor e o orçamento persistido limitam o efeito mesmo se o
controlador morrer. Só `NATIVE_RECURRENCE_VERIFIED_CLEANED`, com artefatos
revalidados e aceite conjunto, permite fechar #104 e depois #23.

Testes de preparação usam projeções/temporários e não iniciam Docker:

```sh
.venv/bin/pytest tests/test_scheduling_native_preparation.py tests/test_linux_scheduling_policy.py -q --tb=short
```

No Windows, somente a primitiva POSIX de fsync do diretório é simulada nos testes
unitários; CI Linux a exerce de verdade. Isso não torna o Windows capaz de operar
o ensaio. O workflow nativo permanece manual e separado da CI integral.
