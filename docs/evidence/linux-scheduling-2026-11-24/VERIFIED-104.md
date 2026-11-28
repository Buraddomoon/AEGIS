# Recorrência nativa verificada e encerrada — #104

Ensaio em27/11/2026 America/Sao_Paulo (28/11 UTC), restrito à #23 e duas
ocorrências do marcador benigno original. Fonte executada:
`4812780c90c9f8aead155de5fe9fe17bef070d40`, sobre main5e5feb9.
[Workflow46090496469](https://github.com/Buraddomoon/AEGIS/actions/runs/46090496469)
**SUCCESS**, status `NATIVE_RECURRENCE_VERIFIED_CLEANED`, cleanup confirmado,
`synthetic=false`. Não é fixture ou execução Demo.

## Autorização e ambiente

O usuário autorizou concluir toda a #23 preservando seu computador e reiterou a
continuação. Mantido o orçamento total de duas ocorrências reais do escopo
apresentado. [Contexto7231321370](https://github.com/Buraddomoon/AEGIS/issues/104#issuecomment-7231321370)
explicita a retomada/fonte atual, sem atribuir revisão manual dos hashes ao usuário;
[comentário operacional7231321513](https://github.com/Buraddomoon/AEGIS/issues/104#issuecomment-7231321513)
identifica o pacote novo, antes de iniciar serviços. Os pacotes anteriores não
foram renovados nem reexecutados; [incidentes](INCIDENTS-104.md) preservam zero
efeitos nas tentativas anteriores.

- Pacote: `caa9078dae564c4aa2ba5270a4589609768a3b24ca4469d65770f7133e8ce2ce`.
- [Manifesto15241116395](https://github.com/Buraddomoon/AEGIS/actions/runs/46090496469/artifacts/15241116395),
  preparado00:57:32UTC, válido até01:27:32UTC de28/11; autorização posterior,
  sem extensão da janela. Fence exclusivo antes do primeiro create.
- Projeto Docker novo `aegis-scheduling104-46090496469` em VM Linux nova do GitHub
  Actions; sem portas publicadas, sem host networking ou Docker socket na app.
- Lab `b3790763-1b19-4f0e-a382-9e9b5e0c7971`, ativo
  `cdfbe990-6247-4244-8885-5460d6d8b701`, runner
  `46f4e938-fad8-4c1e-922e-ef42c1019324`; PKI mTLS nova, sem originais.
- Imagem aplicação `sha256:9f1ae1b75e076c77c7a02d98453c7a836dc50c907931dbdd3bc287d45e6d0e53`;
  runner `sha256:16e4c58d4933ab313b1e1cacb626d541a2ceab3dc205c0a634e4cf6bde6c1516`.
  IDs PostgreSQL/Redis, fingerprints públicos, receita e compromissos dos arquivos
  privados estão no manifesto. Nenhuma chave/senha/dump/journal bruto publicado.
- Schema explícito `f3b28c5d901a`,36tabelas, somente no banco novo vazio
  `schedule104`; duas contas novas e grants mínimos de runtime.
- Redes internas192.168.253.0/29 e192.168.253.8/29; isolamento, UID10001,
  rootfs RO, caps removidas, no-new-privileges, CPU/memória/PIDs e ausência de
  mounts externos conferidos por inspeção independente em `runtime.json`.
  Ver [limites completos](../../operations/scheduling-native.md).

Nenhum serviço do ensaio foi iniciado no Windows. Nenhum Docker/sysctl/rede,
volume, PKI, conta ou histórico original foi alterado. O opt-in foi habilitado
somente na implantação descartável; o padrão do produto continua desligado.

## Autorização recorrente e efeitos

Firefox usou API real, sem interceptações, relógio artificial ou fixtures.
Operador propôs o plano na UI; outro administrador revisou/confirmou escopo,
hash e limites. Só o worker emitiu as ocorrências.

- Agenda `001a9f27-456a-481a-8328-05a78928c6de`; plano SHA256
  `dea35837860756754962bec80584c4d647a4d14e756022ddbdaeae7c37cbfd37`.
- Mesmo grant `22ef609b-b0dc-466a-9d4d-6fcbcd78c1b5` nas duas ocorrências.
- Solicitante `b90a8acf-c144-4095-bc56-1bd221aa9039`; aprovador distinto
  `44245737-e64c-42be-8619-af310f332012`, ambos ativos durante o ensaio.
- Exatamente2slots, intervalo60s, duração máxima30s, concorrência1 e ativo fixo.
  Nenhuma reaprovação, ampliação, execução manual ou retry de efeito.

| Run | Horário previsto UTC28/11 | Término UTC | Resultado |
|---|---|---|---|
| `1339b10a-9a81-4b89-83d4-34d66616ba44` | 00:58:46 | 00:58:48.592599 | COMPLETED / INCONCLUSIVE / CLEANED |
| `66215820-16d3-46ea-a747-c2e08a2b556e` | 00:59:46 | 00:59:48.348116 | COMPLETED / INCONCLUSIVE / CLEANED |

Cada run tem uma execução real, marcador próprio43bytes, dispatch persistido,
recibo e cleanup correspondentes ao mesmo spec/hash. Conferência independente
recalculou hashes de escopo, spec, receipt e cleanup; confirmou grant, segregação,
cadência exata e ausência de terceira run. SHA256 dos comprovantes JSON internos:

| Run | Recibo | Cleanup |
|---|---|---|
| 1339b10a | `eac6eb082867836ae58166c6bac99daf085dacc754e03525b7cb1e3030189625` | `ebb52559326ca1a2dae7344dd816e988dc65f670cec580550dcb7bc34fca66a9` |
| 66215820 | `20426e63ab886c5d8c0a6c9297b27b7ab1b2d010a6d1083c63c5290d2c1ad2d2` | `93b9773d9de9c88146dea1b0493cd2a18ec136c5f9e3d11d3ab8ab2f450de62a` |

Zero eventos/evidências defensivas, sem SIEM/EDR/Wazuh ou regra esperada.
INCONCLUSIVE é o resultado esperado; recibo comprova efeito, não detecção.
Denominador elegível zero, sem taxa/delta de detecção ou alegação ATT&CK.

## Relatórios e UI

Dois snapshots READY, BASELINE e COMPARISON, política `scheduled-linux-report/1`,
`synthetic=false`, mesmo grant e par de runs. JSON/HTML/PDF baixados com hash
esperado; downloads não geraram testes. Browser confirmou documentos idênticos
depois de revogar agenda/lab. Conferência local dos arquivos recalculou todos os
hashes registrados pelo cliente e a integridade dos documentos.

| Snapshot | SHA256 do documento JSON canônico | PDF |
|---|---|---|
| BASELINE `761178b1-eb39-43a7-bc51-a448538628c0` | `3d8094289b2afd54e5944e9b9bf4a19d289cf88826af59ce6f3aceab5a6371eb` | 8páginas |
| COMPARISON `7e009bae-831c-4266-a012-db04bc84431f` | `205c5df044a1da1c83735961d0bd66a2b4303d7aad439a8bed5411f5144491b1` | 15páginas |

As23páginas foram renderizadas e inspecionadas em folhas de contato; capas e
apêndice de recibo também em escala maior. Conteúdo identifica laboratório real,
limites das fontes, INCONCLUSIVE e IDs das runs, sem truncar o apêndice. Escapes
Unicode do exportador permanecem explícitos; JSON é a referência para automação.
Não houve regeneração dos snapshots congelados para alterar apresentação.

Capturas1440/390px registram modo Linux real, orçamento2/2, limite encerrado,
duas ocorrências e dois documentos; zero erros JS e sem overflow da página.
Tabelas móveis têm scroll próprio. As capturas full-page incluem barra fixa na
posição de scroll e o modal durante sua transição; não são uma avaliação estética
integral. Revisão/limites também são comprovados pelo plano e aprovação persistidos.

## Encerramento e prova preservada

Agenda e lab revogados; duas contas próprias inativas e zero sessões próprias.
`runs=dispatches=tests=cleanups=2`, `safe_to_stop=true`, workspace vazio. Compose
down somente do projeto próprio; nenhum container ou consumidor dos dois volumes
novos permaneceu. Não foi usado down-v. O job hospedado terminou; descarte da VM
pelo provedor é parte autorizada do ambiente, sem atestado de apagamento físico.

[Artefato15240144941](https://github.com/Buraddomoon/AEGIS/actions/runs/46090496469/artifacts/15240144941)
contém18arquivos sanitizados; retenção configurada7dias, cópia privada local em
`.local/scheduling104-requests/46090496469/`. ZIP SHA256
`ca507773991b8a063c23a3cc209abc7434b133868e34ac485e19edc289353555`.
Hashes de arquivos de controle:

| Arquivo | SHA256 |
|---|---|
| manifest.json | `a11ab76a176d59f44ff7c594fe28c9ce7321adb7b95bfe5b0308b67c8377bacc` |
| summary.json | `1ebdc83e38b290fe17534c563fb93cd4b0427679b21465f973685a92c69422c1` |
| browser.json | `31797b467ae85cbcc65a8859eda1fc0fd67d02083f53c9c4a2a494d9be2b2608` |
| disabled.json | `9e579059510c6beb9079cd921d6c3bcfb191ba49e4d917a10d6e7ddf52e238b5` |
| workspace.json | `8295d45195b092ea9560d982e67d4cec61b0cca658161d1c6b2eda2629c86d37` |
| runtime.json | `bfcd34914519e8e7ca73feb5a3d62b1e13e89615fc82e0a243873d16bbeb4ab0` |

Hash não é assinatura. Fonte, CI e ensaio descartável são distintos de implantação
no Demo/originais. Não houve tag/release ou operação contínua. Orçamento e pacote
consumidos; não repetir efeitos. Aceite conjunto em [ACCEPTANCE-23.md](ACCEPTANCE-23.md).
