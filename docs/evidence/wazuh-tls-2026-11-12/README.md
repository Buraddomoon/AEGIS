# Renovação TLS Wazuh — tentativa autorizada de12/11/2026

**Resultado: INCONCLUSIVE / CLEANED.** #57 e #6 permanecem abertas. Ensaio real,
sem marcador, banco, runner/observador ou nova evidência defensiva. Não é prova
completa do coletor nem implantação/operação normal do laboratório.

O usuário autorizou explicitamente um único ensaio do pacote5175cd2f: somente
Indexer, manager/Filebeat, agente001 e leitor, até15min, após CI/preflight, com rede
isolada e volumes existentes, preservando dados/configuração antiga no cleanup.
A CI integral do código executável `db403e2` passou nos quatro jobs Python e React:
[run43286076586](https://github.com/Buraddomoon/AEGIS/actions/runs/43286076586).
Gates de recursos/rede, imagens, volumes, fonte e candidato/plano foram refeitos
antes do primeiro efeito. Não houve download/build ou alteração de terceiros.

## Escopo e identidade da tentativa

- ID/plano: `5175cd2f7c0f4ef68a1ef52f8d124df5`.
- Pacote aprovado SHA256:
  `e9dc8359181f5474aa85a1a50dd539901d848baa3a077956fcc194be9fa34f97`.
- Candidato: `0dfb54bbe5c54423ad37ef2309ae369d`; manifesto
  `c38691e29f46429e230bcdb73a528b74164ced98275ce54932ba98ea192e1a6d`.
- Rede própria de telemetria192.168.253.16/29; Indexer.18, manager.19, agente.20.
  Sem portas publicadas. Três imagens oficiais4.14.9/amd64 fixadas por digest.
- Apenas seis volumes originais externos selecionados; os nove volumes e a
  configuração antiga foram preservados. Nenhum volume foi criado/substituído.
- Intenção e autorização duráveis antes dos efeitos; provas privadas em
  `.local/wazuh-pki-plans/5175cd2f7c0f4ef68a1ef52f8d124df5-assay/native-state`.

## Observado de fato

Indexer iniciado às20:19:50UTC. Certificado remoto observado às20:20:21UTC,
DER SHA256 `25886205a3f589a9bd8393493d442bb38e79a75809d6c34874e5126854656957`,
igual à folha do candidato previamente validado contra CA/SAN/DN/pares/prazo.
Esse primeiro handshake/fingerprint não substitui a consulta CA/SNI do coletor.

Manager/Filebeat iniciado às20:20:21UTC. `filebeat test output` passou às20:20:26UTC,
retorno0, TLSv1.3, verificação da cadeia do servidor explicitamente habilitada e
configuração efetiva `full`/destino/CA/par esperados. Nenhum fallback de trust antigo.

Agente001/aegis-marker iniciou às20:20:26UTC. Foram salvas35consultas de
`agent_control -i 001 -j`;25 informaram `Active`, de20:20:50 a20:21:27UTC.
A condição conjunta de estado local do agente e listener de gestão não foi
confirmada em60s; o executor não preservou essas duas entradas intermediárias,
portanto **não é possível atribuir a causa ao agente ou à API de gestão**.
O leitor não chegou a ser criado/executado; nenhuma ACL do coletor foi aprovada.

Às20:21:28UTC iniciou o cleanup, sem repetir startup. Containers próprios foram
parados/removidos e a rede própria vazia foi removida por ID/labels. Duas consultas
posteriores confirmaram zero containers/consumidores, mesmos metadados de imagens
e dos nove volumes e mesmo snapshot da configuração original. Origem pública
mantém SHA256 `eb3e7008f8bc0fffcf56c7f126409c0b9d99dd6b4cc933f8a0be491550a9f85b`.
Cleanup usa intenções duráveis por recurso antes das paradas/remoções; confirmações
agregadas posteriores do diário não são tratadas como intenção anterior ao efeito.

## Integridade, limites e retomada

SHA256 dos bytes privados de `outcome.json`:
`aca9f89c32dd84ae6a65d4e77346c30717caf9e00f4355da301e989a7aa664c4`.
SHA256 de `cleanup-verified.json`:
`e7878a84ee60b897426df3af7a9c8470cc47d32c0f8ee83fd4b9efa10e2bfcb2`.
Hashes não são assinaturas. Nenhum segredo, log integral ou conteúdo de alerta
foi publicado. O resultado e os intents não são reescritos para obter aceite.

A autorização única foi consumida; não reiniciar este pacote nem apagar o estado.
A preparação corrigida separa identidade/Active, estado conectado e ausência de
exposição LAN, e preserva cada observação. API de gestão ausente é diferente de
API verificada em loopback: não se exige disponibilidade de um serviço que está
fora do coletor, mas qualquer listener55000 externo continua bloqueando aceite.
Essa correção de instrumentação não resolve retroativamente a lacuna desta prova.
Um novo ensaio exige candidato/plano/identidade de tentativa novos, gates atuais
e autorização específica própria. Não avançar para campanha ou outra feature.
