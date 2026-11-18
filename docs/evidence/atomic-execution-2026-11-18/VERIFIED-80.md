# Ensaio Atomic de permissões — #80, 18/11/2026

**VERIFIED_CLEANED**. Após autorização humana específica, uma única campanha
real executou a adaptação própria revisada: **COMPLETED / INCONCLUSIVE / CLEANED**,
`synthetic=false`. O ensaio está encerrado. A autorização/tentativa foi consumida;
não permite replay ou operação contínua. A sessão ficou restrita à #80.

## Autorização, fonte e identidade

A resposta humana “sim” confirmou a [proposta202afac5](../../../labs/linux/ATOMIC80-REQUEST-202afac5.md)
dentro de sua validade. Registro privado exclusivo/fsynced às12:38:58UTC;
fence exclusivo/fsynced às12:39:00UTC, antes do primeiro create. Não foram
reutilizados o pacote91de0d6f retirado nem a4335444 expirada; conteúdos/PKI e o
recebimento tardio anterior continuam preservados. Não houve renovação silenciosa.

| Identificação | Valor |
| --- | --- |
| Pacote |`202afac50f69432681adabf07baaaaed` |
| Proposta SHA256 canônico |`21e4cad0f9287de38861cc9e0aa903e0f7ccd5c4c5b4affd7c647675f6ab068b` |
| Tentativa |`077333c3-7294-48a9-9169-d56a15e91408` |
| Projeto próprio |`aegis-atomic80-202afac50f69` |
| Laboratório |`216fd641-6cc9-4244-abea-ae3434605118` |
| Ativo |`54468877-4bed-45eb-ada6-fe8cefb7accb` |
| Runner |`23227d22-f814-42a8-be53-93789e6ed00b` |
| Run |`a9dc99b1-921f-4d94-be1f-70525c89fb4a` |
| Execução/job |`08850254-6c29-4e2e-93d3-ceed3bd75756` |
| Escopo SHA256 |`c6a56dedbfb28228356131a1d2c25978a9bc6815244b6ba67243d79d937cff26` |

HEAD na execução `d2de23b3c4b160e71543e29a1efd560971c63f58`; coordenador fixado
na proposta `a19257fb4c96afcbf5982884e032d2bdcae32fa4`. Inputs executáveis
idênticos à fonte c974380 da CI integral verde. Aplicação construída de8b4678e,
runner de7e3dde5; os manifests de fonte/imports/locks/assets foram conferidos na
[preparação](../atomic-execution-2026-11-17/PREPARATION-80.md), sem rebuild aqui.

| Componente | Imagem local imutável usada |
| --- | --- |
| API/worker/helpers |`sha256:3ae40c8ce7c93f0a1b40c91ecc84facaf1ecb6d8ee74e841765f81a0aa5a81c7` |
| Runner |`sha256:c0fb88c5cf97ab20b41e6f4d45a7647c98161dd29d0408d296c11a4b6bb38e5f` |
| PostgreSQL |`sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24` |
| Redis |`sha256:3811787313eba226a2ef38658c6ccb91cd5e110edc89c37767de373120a0e5a0` |

## Caminho efetivamente exercitado

1. `atomic_assay.py verify` passou antes da autorização. Imagens/receita/PKI/
   inventário/expiração e fonte fixados; main limpa. MemAvailable observado4052MiB
   na checagem inicial; gate≥3072MiB e preflight RO de subnets passaram novamente
   antes de consumir a tentativa. Não se alterou swap/sysctl ou outro projeto.
2. `atomic_assay.py run --package-id 202afac50f69432681adabf07baaaaed
   --expected-sha256 21e4cad0f9287de38861cc9e0aa903e0f7ccd5c4c5b4affd7c647675f6ab068b`
   foi invocado **uma vez**, saída0; stderr vazio. Inicialização explícita somente
   do banco/volume novos, Alembic c8/36tabelas, seed versionado, grants mínimos e
   duas contas próprias segregadas. Bootstrap e gate RO separados passaram,
   sem execução/dispatch anterior ou agendamento/relatório pendente.
3. Metadados nativos dos cinco serviços passaram: IDs imutáveis, mounts próprios,
   redes internas isolated `192.168.253.0/29` e `.8/29`, IPv6 desativado, sem
   portas no host. Runner/API/worker UID10001, rootfs RO, ALL caps removidas,
   no-new-privileges e limites conferidos. Pico configurado1728MiB é limite do
   perfil; não foi medido como pico de RSS.
4. Controlador usou a API real interna, registro do lab novo, **preflight mTLS
   real**, autorização do lab, solicitação por operador e aprovação por outro
   administrador ativo, scope hash idêntico. UUID/escopo da run foram persistidos
   no volume próprio antes de approve/start. O worker persistiu dispatch antes
   do efeito; não houve bypass de domínio/worker/RBAC nem execução direta no host.
5. Run iniciada às12:39:16.288200UTC e concluída às12:39:17.679479UTC
   (09:39 em São Paulo). Um filho executado, programa fixo com exit0: arquivo
   próprio de43bytes, modo0400 observado e alterado para0600 por `fchmod`.
   Cleanup retornou SUCCEEDED/CLEANED com recibo idêntico e hashes coerentes.
6. JSON e HTML foram solicitados pelo controlador para a mesma run, HTTP sucesso.
   JSON sem synthetic e com integridade conferida; HTML com seção de comprovantes
   do executor, bytes identificados pelo hash abaixo. Não houve SPA/browser/PDF
   neste escopo. O conteúdo HTML não foi preservado, somente o hash dos bytes
   retornados; JSON/detail completos estão no recibo privado do controlador.
7. Lab revogado; helper owner confirmou duas contas próprias inativas, nenhuma
   sessão própria e binding-review sem bloqueadores (`safe_to_stop=true`).
   Coordenador encerrou apenas containers/redes próprios, sem `down -v`.
   Resultado final persistido às12:39:23UTC.

A única definição foi `atomic-file-permissions-v1`, GUID
`34ca1464-de9d-40c6-8c77-690adf36a135`, revisão
`9e283889776cbd42ebf9b7b25bc1ebfbad452157398ecbe0ab77415136c35673`.
Fonte/programa/configuração continuam os do [dossiê revisado](../../integrations/atomic-permissions-review.md).
Não foram executados shell, processo chmod, comandos/setup/cleanup upstream,
inputs livres, elevação ou outros GUIDs. Metadados importados seguem não executáveis.

## Resultado e limites defensivos

Não havia SIEM/regra defensiva configurados. `provider=unavailable`, tentativas de
coleta0, eventos0 e evidências defensivas0; resultado **INCONCLUSIVE**. O recibo
comprova o efeito, sem substituir telemetria defensiva. Não declara DETECTED,
ausência global de telemetria ou eficácia de T1222.002/EDR/SIEM. A adaptação não
reproduz detecções de shell/command line do Atomic upstream.

Relatório:1planejado,1COMPLETED,1INCONCLUSIVE excluído,0testes válidos para a
taxa,0DETECTED; porcentagem `null`, não0%. JSON/report.run e detail são equivalentes
considerando a representação UTC `Z`/`+00:00`; a integridade foi calculada sobre
o conteúdo original, sem normalizar ou reescrever snapshots/escopo/recibos.

| Prova | SHA256 |
| --- | --- |
| Artefato43bytes, marcador mais newline |`1f9f51c8a499eb1650502551d3707babbf9b090407947c03b2ddfe43a14cb251` |
| Recibo canônico |`5f34e309a4ad8de4e6bccd9d2650bee2aa10bd0a4a10845ad1a845c062300936` |
| Cleanup canônico |`dbb6e9a6232f52eadce5954343f0437105f6a716fb46613e0dd4c4b9385e0e8e` |
| JSON: integridade do report.run |`82c920c5bb9db9f1cf98915d84545a8357ac4dd7a4f4aeb68b83ce6c176c5b99` |
| HTML: bytes retornados |`2f4b05d3fddee1c7f9b77b1161c0e85093d07d2f989bb4690d9f37e9524ff4db` |
| Postcheck privado: bytes do arquivo |`eea83f36d841cbcc4094abe60f7d1a8d87b10c1498693a81d03ed1ee5b981064` |

Hashes identificam conteúdo; não são assinaturas/atestados do publicador.

## Estado final e custódia

Postcheck independente RO às12:42:25UTC: POSTCHECK_VERIFIED_CLEANED, IDs/escopo/
aprovação segregada/dispatch/recibo/cleanup/integridade JSON conferidos; projeções
nativas dos cinco serviços revalidadas. Zero containers/redes próprios. Exatamente
três volumes retidos, cada um sem consumidores:

- `aegis-atomic80-202afac50f69_database`
- `aegis-atomic80-202afac50f69_journal`
- `aegis-atomic80-202afac50f69_evidence`

Proposta, autorização consumida, PKI, senhas, intent/fence, runtime-review,
bootstrap/readiness/controller/disable/result e postcheck ficam exclusivamente
em `.local/atomic80-packages/202afac50f69432681adabf07baaaaed`, protegidos no host;
logs de execução em `.local/atomic-assay-prep/97dd150ca7ad4c08a0c76fb02897c5a6`.
Nada privado foi enviado ao Git/GitHub. Imagens/tags e pacotes anteriores retidos.
Sem montagem/migração/reset de original, backup ou diário histórico. Não se
operou qasrc; o Demo anterior permaneceu ativo/ready, HTTP200 no postcheck.

## Verificações e ocorrências

Ensaio nativo acima e postcheck são novos. A fonte executável não mudou: CI
integral [44205114457](https://github.com/Buraddomoon/AEGIS/actions/runs/44205114457)
SUCCESS, quatro partições3615Python/9skips opcionais e98React, cinco jobs/logs
já conferidos. CI documental anterior
[44304856122](https://github.com/Buraddomoon/AEGIS/actions/runs/44304856122) SUCCESS.
Suítes não foram repetidas por consolidação somente Markdown; checks staged/
segredos/whitespace/release e source-review final constam no comentário da #80.

Sem falha do ensaio nativo. Duas checagens manuais suplementares falharam por
pressupostos do próprio verificador: hash sem newline e igualdade textual de
UTC `Z`/`+00:00`. Corrigida somente a comparação; provas originais intactas e
postcheck final passou. A consulta inicial de status Docker também usou `.Name`
em vez de `.Names`; corrigida apenas a projeção RO. Nada disso repetiu run/start,
bootstrap ou efeito. Falhas de preparação anteriores permanecem documentadas.

A #80 tem prova do seu aceite. O pai #14 permanece aberto para aceite conjunto;
não foi implementada outra subissue/feature. Esta autorização está consumida.
