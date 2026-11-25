# Pacote nativo #104 — 28de3e3f

**Preparado, não autorizado e não executado.** Retomada da #23 após pedido de
concluir todo o escopo. Não iniciar efeitos sem aprovação específica deste pacote
e CI da fonte aprovada. Autorizações históricas continuam consumidas.

- SHA256 integral: `28de3e3f53ad79c39651feec2dd3f3d6013acf0ac63ff3b3ed71ca347fe2d65d`.
- Fonte: `178e7df14e14e58ad2b2db2b480b07fbfcd340bc`.
- [Preparação45514289124](https://github.com/Buraddomoon/AEGIS/actions/runs/45514289124).
- [Manifesto público14975638954](https://github.com/Buraddomoon/AEGIS/actions/runs/45514289124/artifacts/14975638954).
- SHA256 do ZIP baixado: `2f498c8307beda1a3488763cdf736a7456c3cd5017b6911106c96bc41136f51a`.
- Preparado em `2026-11-24T23:59:20.471957Z`; expira em
  `2026-11-25T00:29:20.471957Z`. Aprovar antes de `00:24:20Z` de25/11
  (`21:24:20` de24/11 em Brasília), mantendo margem de5min. Sem extensão automática.
- Ator GitHub que pode autorizar: `Buraddomoon`; comentário posterior e exato.

## Identidade e imagens concretas

| Campo | Valor |
| --- | --- |
| Projeto novo | `aegis-scheduling104-45514289124` |
| Lab novo | `75d0bf38-94d8-46f9-b00c-eda3eded7556` |
| Ativo novo | `5fd60372-8d20-4c46-948b-025a670f9add` |
| Runner novo | `6844e378-a59d-44cd-9601-dc467b7a1582` |
| Aplicação | `sha256:1db2c7f96a871ec936a5cc380140a4af1b22a297012e6ca1927a2f3e141fbc1c` |
| Runner | `sha256:ae2463db55c61d6618625bafd355199c2d738f54c6f699220d511905fd1c7ddd` |
| PostgreSQL17 | `sha256:fa7e2700e906190f900a3c9d47e87f9032cfa38b60d9ac25129a357f85c2da8c` |
| Redis8 | `sha256:78195281e51dbd6fe9bb58e1d804282afa7092b7f6eaa2312423729f56276c10` |

Imagens Linux/amd64 construídas/puxadas na VM nova, fixadas por ID; nenhuma tag
histórica do usuário foi reutilizada. Build usa blobs commitados, sem .env,
node_modules, PKI ou dados locais. O manifesto não é assinatura/atestado da imagem.

## Confiança e receita

| Fingerprint SHA256 | Valor |
| --- | --- |
| CA servidor | `f9cf551219059c436170eeae7eedff0354fd710a58eff00a60de2fd4fe2bbeff` |
| CA cliente | `6d7a9f9e9d287f7cc398d322f54d370f0fc0790c59890aafb56887b1f76b4ae0` |
| Certificado servidor | `1b96b62ac88d6ed9f129d94fb49a58dec145fdadfebeb44a7575d1cb8193a9b1` |
| Certificado cliente | `8fc518909a602782281e9320db410a63c26587c12fdfd6796bcc4302a324df16` |
| Receita | `f571ddb02b92af4d8f140fcd0de2f45adcfcae46502d1956e29cf518310f46a3` |
| Helper | `5123aa832e176cffe5042a7ab19df1fda14242c8ad639bc864397031c1d5b041` |
| Browser | `b05d5b16af0d1f19f9f96ca00d19a8ffdb650c7061f43cab004d795383628251` |
| Metadados de rede antes | `c2f6df68e6302de10774cad1aeccd0cb878b46d705e88d05ec5c712887f15ab5` |

PKI/credenciais ficam somente na VM, diretórios0700; nenhum material privado foi
baixado/publicado. Manifesto público contém apenas fingerprints/compromissos de
integridade. Não copiar chaves, banco, dumps ou diário bruto como artefatos.

## Efeito autorizado proposto

Exatamente **duas ocorrências** do marcador benigno original
`linux-file-marker/v1`, definição `linux-file-marker-v1`. Cada uma cria43bytes
próprios no tmpfs `/work`, com lease2s/supervisor e efeito≤5s. Intervalo60s,
concorrência1 e run≤30s. UI propõe início futuro25s e fim≤180s após a proposta,
ambos dentro do prazo do pacote. Um único grant, solicitante e aprovador em contas
ativas distintas; sem campanha manual extra, reaproveitar grant, replay ou ampliar
orçamento durante o ensaio.

Banco novo `schedule104`, schema explícito e2a/36tabelas e grants mínimos; seed e
duas contas novas somente se o banco estiver vazio. Opt-in real ligado apenas
nessa implantação nova. Sem acesso ao Demo ou Linux/Wazuh originais. Sem SIEM,
shell, Atomic ou técnica ATT&CK. Resultado esperado
`COMPLETED/INCONCLUSIVE/CLEANED`, `synthetic=false`; recibo não prova detecção.

Redes próprias internas192.168.253.0/29 (runner isolated) e192.168.253.8/29
(backend). Firefox da VM acessa a API privada192.168.253.12:8080; nenhuma porta
publicada, socket Docker na app ou host networking. O host alcança a bridge
interna do backend conforme [Docker network internal](https://docs.docker.com/reference/cli/docker/network/create/#network-internal-mode---internal);
o runner não recebe gateway de host no modo isolated. Qualquer colisão/drift
bloqueia, sem alterar qasrc ou redes de terceiros.

Limites/mounts/UIDs e memória seguem o
[procedimento fechado](../../operations/scheduling-native.md). Antes do efeito,
inspecionar metadados nativos de imagem/comando/mounts/redes/limites. Exigir
MemAvailable≥3072MiB, sem mudanças de swap/sysctl/processos de outros projetos.

## Prova, encerramento e descarte da VM

Conferir autorização, dois UUIDs/runs, dispatch/recibo/cleanup/43bytes, mesmo
grant, intervalos reais e snapshots baseline/comparação JSON/HTML/PDF. Publicar
somente essas provas sanitizadas novas e screenshots sem senhas, não logs brutos,
segredos ou dados de laboratórios originais.

Revogar agenda/lab, desativar duas contas próprias e zerar suas sessões.
Confirmar cleanup e workspace vazio antes de encerrar containers/redes próprias;
não usar `down -v`. Dois volumes próprios ficam sem consumidores até o descarte
automático da VM efêmera pelo GitHub. Esse descarte do host novo integra o escopo
que precisa de aprovação; nenhum volume/PKI/journal original é transportado.

Fence exclusivo/fsynced antes do primeiro create, comentário humano revalidado,
uma tentativa e nenhum rerun do workflow. Em ambiguidade, revogar/cancelar e
preservar status de quarentena; não repetir efeito para obter prova positiva.
Sem aprovação ou com prazo vencido: zero efeitos e #104 continua aberta.

## Texto exato de autorização posterior

Somente após o usuário aprovar o pacote concreto, registrar na #104:

```text
AEGIS-104-AUTHORIZE 28de3e3f53ad79c39651feec2dd3f3d6013acf0ac63ff3b3ed71ca347fe2d65d
workflow_run=45514289124
occurrences=2
profile=linux-file-marker/v1
fresh_isolated_lab=true
originals=false
public_sanitized_evidence=true
ephemeral_host_disposal_after_cleanup=true
```

Esta proposta e o pedido genérico de concluir a issue não geram esse registro.
O comentário só pode refletir aprovação humana específica, nunca inferida de
silêncio, tempo decorrido, build, fixture ou CI.
