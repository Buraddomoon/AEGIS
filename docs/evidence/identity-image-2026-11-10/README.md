# Preparação da imagem identity-only — 2026-11-10

Parte da subissue #45, entrega #3. Novo build de desenvolvimento concluído e
revisado, sem iniciar o laboratório. O código do servidor/probe/coordenador já
existia; esta etapa prepara a imagem correspondente à fonte atual e corrige o
procedimento que ainda apontava o build antigo e o bloqueio histórico de rede.

| Referência | Valor |
| --- | --- |
| Fonte testada | `f0c95b2f6cdb62fb7da219cbe93a18807838758d` |
| Fonte selada, SHA256 canônico | `1b1b0f69ee358a75a4ef7ff24a6e848e4f004c5d34dbda93ac0aa0b447a65492` |
| Build ID | `d5ec67c458cd4553bafc4e9aeee6bb4a` |
| Plano de build, SHA256 canônico | `7aeffb3551ffe321e58a458d1e00a7a253be12557b1fffd9a680dcd63194833e` |
| Recibo de build, SHA256 canônico | `6b68d3e97c4150b4afd5dc6218c20f21aa7bf66f0bf28654b2c65bdf076fefac` |
| Imagem nativa, manifest digest | `sha256:b5ae5340f417ef3fce7ce25f8ec07d2dd92545b3a34d6db1982ac37fb108c593` |
| Config digest | `sha256:f7f69e1927665e19ca7eb2793b380c89a70cebbd52837f4709a4134992c9ce82` |
| Base local oficial por digest | `docker.io/library/python@sha256:aaf08c5490d52cd92bc27142a5215b1e47355a5eaf9adfad2a0fbc022d0b5490` |

Exportados72 arquivos versionados;69 pertencem ao pacote Python. Download
verificou48 wheels por hash,30.384.478 bytes, sem instalação no host. Contexto
privado/allowlist e tag exclusiva `aegis-runner-review:d5ec67c458cd4553bafc4e9aeee6bb4a`;
build com base local, pull=false, RUN com rede none e pip sem índice externo.
O checker confirmou69 arquivos instalados,45 versões de runtime,3 de build e
imports dos probes. Cliente de build terminou com código0. Revisão posterior
somente por metadados confirmou novamente o recibo e o perfil da imagem.

A imagem histórica526267ad e a imagem Demo b8abe5e mantiveram os IDs e as tags
anteriores. Nenhum runner de laboratório, DB, Redis, API, worker ou Wazuh foi
iniciado por esta preparação; nenhum volume original foi montado ou migrado.
Logs, contexto, wheels e recibo completo ficam somente em `.local`, fora do Git.

Validação remota da fonte: [Validate AEGIS42873241181](https://github.com/Buraddomoon/AEGIS/actions/runs/42873241181),
quatro jobs Python e React concluídos com sucesso. Revisão documental da base:
[source delivery42871147694](https://github.com/Buraddomoon/AEGIS/actions/runs/42871147694)
em e4b7f31; a diferença até f0c95b2 contém somente `tests/test_wazuh_tls.py`.
Alterações desta preparação são documentais; igualdade executável deve ser
reconferida no pacote privado com o commit final limpo.

Validação local:253 testes de fonte/build/imagem/plano/subnet passaram:

```bash
.venv/bin/pytest tests/test_runner_activation_image_source.py tests/test_runner_image_assert.py tests/test_runner_image_registry.py tests/test_runner_image_wheels.py tests/test_runner_image_base.py tests/test_build_review_runner.py tests/test_runner_activation_identity_image.py tests/test_runner_activation_plan.py tests/test_runner_activation_subnet_review.py -q
```

Outros111 testes passaram, incluindo TLS real em loopback e contratos da CLI,
classificação, revisão de recibos e cleanup:

```bash
.venv/bin/pytest tests/test_runner_identity_server.py tests/test_runner_identity_probe.py tests/test_runner_identity_assay.py tests/test_runner_identity_cleanup_cli.py tests/test_runner_identity_review.py -q
```

Esses testes usam artefatos temporários e metadata simulada; o build acima é
real, mas não comprova TLS nativo. Não há assinatura de publisher, ativação PKI,
binding, continuidade de diário, telemetria ou DETECTED. A conclusão de #45 exige
também candidato/plano novos e pacote vigente, com recheck temporal/subnet/ownership.
Os hashes/validade desse pacote ficam na revisão da issue #46; autorização humana
e ensaio #47 são etapas posteriores. Nenhum recibo de runtime foi fabricado.
