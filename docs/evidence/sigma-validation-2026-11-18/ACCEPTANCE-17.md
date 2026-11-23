# Aceite conjunto — #17

23/11/2026. Escopo exclusivo #87 → #88 → #89; dependências #16/#7 concluídas.
**Aceite técnico do conjunto atendido.** Revisão a partir da fonte, testes e
[ensaio nativo verificado/CLEANED](VERIFIED-89.md), sem repetir efeitos.

| Critério | Evidência e limite |
| --- | --- |
| #87: mapping físico/perfil | Mapping/settings/aliases reais de um índice diário concreto, keyword nos três campos literais usados e timestamp date; mesmos hashes antes/depois. TLS1.3/CA/SNI/IP/fingerprint e principal reader. Outras colunas/perfis não são presumidos compatíveis. |
| #87: acesso mínimo/drift | Grants temporários limitados a três leituras de metadata em um índice, sem escrita de documentos ou acesso Security para o reader. Role original restaurada. Fixtures recusam aliases, texto/analisador/normalizer/nested/source filtrado, hash e contexto divergentes. |
| #88: artefato revisado | Conteúdo/UUIDs/hash das versões salvas/exportadas de schema descartável, backend/core/pipeline/lock/implementação fixados; query regenerada e comparada antes da rede. API não recebe query ou destino livre. |
| #88: limites e origem | Índice/agente001/período±5s fechados; timeout/bytes/100hits×10páginas; total eq, shards, cursor corrente e DELETEs confirmados. Hit positivo idêntico em índice/id/source/hash ao alerta original da #59. Negativas/erros/incompletude não se tornam ausência de telemetria. |
| #88: banco/API | Testes PostgreSQL/schema descartável/Redis15, RBAC/CSRF/integridade/rate limit, preservação de versões/auditoria/cobertura. Serviço de integração consultou o Indexer no ensaio; nova API não foi implantada no Demo. |
| #89: positivo/negativo nativos | Duas queries oficiais no Indexer4.14.9: uma correspondência original e negativa0, ambas completas, mapping antes/depois e cleanup de dois cursores. Um alerta de marcador próprio; não mede recall/eficácia geral ou implantação Wazuh. |
| Integridade e autorização | Autorizações específicas de consulta e manutenção com reversão registradas; pacotes novos/inputs fixados. Tentativas anteriores e erros403/400 preservados, sem reuso. Sem alterar scopes/approvals/recibos/relatórios/veredictos históricos. |
| Encerramento | Role original igual ao snapshot, zero recursos próprios, nove volumes retidos sem consumidores,150inputs/configuração/PKI preservados; sem novo marcador/run. Pacotes/autorizações consumidos. |

O helper administrativo exige isolamento de um único escritor, GET exato
antes/depois e reversão somente da entrada própria. A API nativa não aceita
JSON Patch test; não se declara CAS no servidor. O grant/reversão escreveu Security
no volume original sob autorização adicional; startup pode escrever estado/logs.
Preservação de política/dados históricos não significa igualdade física do volume.

Validação local final:207passed/31,92s e lint completo. O CI da fonte final
13ff3d8/[45192506887](https://github.com/Buraddomoon/AEGIS/actions/runs/45192506887)
concluiu **SUCCESS**:3857Python/9skips existentes e115React, quatro grupos Python e
React conferidos. Commits finais documentais mantêm os inputs executáveis idênticos
à fonte validada; hash/mensagem final e sincronização ficam no comentário de fechamento.

Fonte13ff3d8, imagem do leitor8787f04 com código montadoRO e Demo anteriorb8abe5e
são artefatos distintos. Sem implantação permanente, release, tag Git, branch/PR,
build/pull de imagem ou mudança de visibilidade. Código do produto permanece0.2.0.

Provas e CI conferidos; o fechamento registra #87/#88/#89 antes da #17 e reconfere
sincronização. **Parar após esse aceite**, sem outra entrega, laboratório ou operação
contínua. Histórico das tentativas e artefatos privados permanecem preservados.
