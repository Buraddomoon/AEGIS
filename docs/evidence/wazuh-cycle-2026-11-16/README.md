# Reinspeção da entrega #7 — 16/11/2026

**Preparação verificada; ensaio integrado bloqueado.** Revisão das subissues na
ordem #58 → #59 → #60, partindo de `b634c52`. As dependências #5 e #6 estão
fechadas. O banco Wazuh foi atualizado sob autorização específica em 13/11;
não repetir essa manutenção ou transferir sua autorização para a campanha.

## Observações atuais, somente leitura

O primeiro `make wazuh-lab-preflight` recusou o início com
5.243.822.080 bytes disponíveis (~4,88 GiB). A reinspeção às
15:04:13 UTC encontrou **4.660.727.808 bytes (~4,34 GiB)**. O mínimo continua
8.589.934.592 bytes (8 GiB), sem contar swap. Os demais recursos observados:
16 CPUs, 416.336.396.288 bytes livres no armazenamento Docker e
`vm.max_map_count=1048576`. Nenhum processo de terceiros foi encerrado e nenhum
limite foi reduzido. O preflight recusado é resultado esperado de um gate,
não falha dos testes automatizados.

`make wazuh-network-preflight` e uma segunda consulta verificaram 20 redes e
61 rotas, sem sobreposição IPv4 observada nas faixas ADR0034
`192.168.253.8/29` e `192.168.253.16/29`. Snapshot:
`54541744b12db50e008675e426716dd5349f6d6fa282762c1c893a89519caf96`.
Isso não reserva redes nem comprova conectividade.

Os nove volumes originais mantêm os metadados da proposta de manutenção
`f202657f619840c99d0ff13f3438acb8`. Zero containers do projeto e zero consumidores
de cada volume, inclusive fora do projeto, foram observados. Nenhum volume foi
montado e nenhum conteúdo foi lido. O schema b7/33 e os grants continuam sendo
o resultado documentado da [manutenção de 13/11](../wazuh-database-2026-11-13/UPGRADE-ORIGINAL.md),
sem nova verificação SQL nesta sessão.

As cinco imagens locais foram reencontradas por ID, todas linux/amd64:

| Componente | ID local |
|---|---|
| Indexer 4.14.9 | `sha256:9c43f316f0a4a15951b8667c0a0f97fc945a9e1ac55035b1be22c95d2b9a04e3` |
| Manager/Filebeat 4.14.9 | `sha256:3561b33f8d1edf3d3b05e1819fa9a47fd28d6536787793d1840bfdf1172359ff` |
| Agente 4.14.9 | `sha256:538ce3efc9bb097fad25e7b189d02e7e831f71faa750e2733b6011ea2070de08` |
| API/worker preparados em 13/11 | `sha256:64112646c663933a81a3777adbac03ea439ee6ae923a74418996d8d370fba0fe` |
| Runner/observador preparados em 13/11 | `sha256:0440049a28cb8799d350d1a646f470e6eed26cc0893384ab6cc211050cfaba54` |

`git diff a2378b1 -- apps/api apps/web fixtures requirements.lock` não apresenta
diferenças: não há motivo identificado para reconstruir essas imagens nesta
revisão. A presença e a arquitetura foram conferidas por metadados, sem executar
imagens ou repetir a verificação interna de 73 arquivos/45 versões de 13/11.
Não houve build, pull ou implantação.

A origem continua em `/home/IVPTER/codes/aegis/.local/wazuh-lab`. Os inventários
públicos e o intent histórico conservam os hashes anteriores:

| Artefato | SHA256 |
|---|---|
| Inventário público do runner, canônico | `981036ea265c1cbc09e1a25f6823419195a2f70ec3656fe606f04779197e5357` |
| Inventário público dos serviços, canônico | `eb3e7008f8bc0fffcf56c7f126409c0b9d99dd6b4cc933f8a0be491550a9f85b` |
| Intent de outubro, bytes | `283c2a14f31d5503c2c17b7e653c2c81211655baf5ac46b3b50fec5ac3f778b4` |

Todos os certificados históricos continuam expirados. O runner ainda aponta
para o endereço legado na origem preservada. IDs de runner/lab/ativo e política
de agente `001`, regra `100200`, janela/espera 60s, poll 2s, timeout 3s e skew 5s
coincidem com o pacote anterior. Não foram lidas chaves privadas, gerados
candidatos expirantes ou alteradas identidades, credenciais e aprovações.

## Testes efetivamente executados

| Comando | Resultado |
|---|---|
| `make test-wazuh` | 60 passaram |
| `make test-wazuh-preparation`, primeira suíte | 114 passaram |
| `make test-wazuh-preparation`, segunda suíte | 96 passaram |
| `.venv/bin/pytest tests/test_wazuh_recorded_assay.py -q` | 6 passaram |

As suítes foram sequenciais. As credenciais já existentes do desenvolvimento
foram selecionadas somente no ambiente do processo; nenhum arquivo, conta ou
grant foi alterado. Os conjuntos se sobrepõem, portanto não são um total de
casos únicos. O aviso conhecido Starlette/TestClient/httpx permanece visível.
Os seis testes da gravação de outubro verificam bytes, normalização e correlação
do documento preservado; não são uma nova consulta ao Indexer ou campanha real.

## Situação de cada subissue

- **#58 aberta:** os bloqueios de recursos e PKI foram reproduzidos. Ainda faltam
  continuidade do journal/log de observação, revisão controlada do catálogo
  versionado, candidatos/overlays vigentes, inspeção efetiva do runtime e
  coordenador de uso único compatível com o histórico existente. O harness de
  outubro continua exigindo banco vazio/intent ausente e não deve ser usado para
  a retomada. Não apagar registros, trocar IDs ou inicializar a origem ausente
  neste checkout para contornar isso.
- **#59 pendente por #58:** não existe tentativa defensiva atual. O pacote de
  [efeito único](../../../labs/wazuh/CYCLE-ASSAY.md) continua exigindo revisão e
  autorização operacional específica, além dos gates técnicos; uma solicitação
  genérica da issue não substitui esse requisito. Sem novo marcador ou alerta.
- **#60 pendente por #59:** faltam o resultado atual e seus documentos para a
  leitura autenticada e os parsers JSON/HTML/PDF. O ensaio de outubro e o TLS de
  novembro não foram apresentados como esse resultado. Nenhuma campanha foi
  repetida para produzir screenshots.

Pai e filhos permanecem abertos. Liberar RAM atende somente um dos pré-requisitos;
não autoriza startup ou efeito. As etapas pequenas de banco já concluídas não
exigiram 8 GiB e não precisam ser repetidas. Não houve operação Linux/Wazuh,
abertura de journal, catálogo publicado, novos usuários, binding, marcador,
evidência defensiva atual ou validação de UI/exports nesta sessão.

O recibo selecionado fica protegido em
`.local/wazuh-cycle-review/9a66e28d5d6741c2a1c63cad4958c8c5/review.json`, SHA256
canônico `1eabb2b9b7f580393d25901e6d802d6706cb09524b43f63bafde379ba61d738f`.
Hash verifica alterações; não é assinatura ou autorização. Somente este resumo
foi versionado. Commit, checks staged/release e sincronização constam nos
comentários das issues; a sessão não avança para outra entrega.
