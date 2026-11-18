# Consulta Sigma limitada — #17 / #87 / #88 / #89

Estado18/11/2026: implementação e testes locais. **Ensaio nativo bloqueado** por
ausência de autorização específica, snapshot físico revisado e pacote operacional
novo. As autorizações das #59/#63 estão consumidas. Este documento não autoriza
startup Wazuh, leitura de volumes originais, consulta externa ou novo marcador.

## Contrato implementado

POST `/api/v1/rules/{rule_id}/versions/{version_id}/query-validation`, administrador
ativo, sessão/CSRF/origem exata e limite2/min por usuário. Corpo único:
`{"confirm_scope_sha256":"<SHA-256 canônico do escopo revisado>"}`. Campos extras
são recusados. Integridade/ownership da versão salva são verificados antes do
efeito. Não recebe query, índice, agente, período, credenciais ou destino do cliente.

Opt-in de implantação `SIGMA_VALIDATION_SCOPE` aponta um JSON privado, regular,
sem symlink/hardlink, proprietário do processo, modo0600 e até16KiB. Ausente,
expirado, alterado ou modo recovery bloqueia a consulta. Não há instalação, ativação
ou consulta no startup. Escrever um arquivo não substitui autorização humana.
O modelo `Scope` em `apps/api/aegis/integrations/sigma_validation.py` rejeita extras:

| Campo | Revisão obrigatória |
| --- | --- |
| format | `aegis-sigma-validation/1` |
| index_profile | `aegis-marker-keyword/1`, índice diário concreto, versão anunciada e hashes dos JSONs completos de mapping/settings |
| connection_sha256 | Digest de URL/IP/CA/principal configurados; exige CA explícita; nunca inclui senha |
| rule_id / rule_version_id / content_sha256 | Versão efetivamente salva e seu hash, incluindo normalização de whitespace da importação |
| contract_sha256 / query_sha256 | Contrato atual do conversor isolado e bytes da query oficial revisada |
| agent_id | Identidade externa exata, diferente do manager000 |
| start / end | Período histórico com timezone, positivo e até5min; encerrado antes da aprovação |
| approved_at / expires_at | Janela ativa até30min; revalidada entre requisições/chunks |

Hash do escopo: `digest(Scope.model_validate_json(bytes).model_dump(mode="json"))`.
Não é assinatura. Nenhum arquivo ativo ou pacote operacional foi criado nesta
entrega. Credenciais e escopos reais permanecem host-only, fora do Git/issue.

A API regenera a query da versão exata usando o backend/pipeline/pins fixados na
#16 e compara os hashes revisados antes da rede. Literais com `<`/`>` são recusados
no perfil de execução, preservando o conversor offline anterior:
[Lucene/OpenSearch documenta limites de escape desses sinais](https://docs.opensearch.org/latest/query-dsl/full-text/query-string/).
Não há query livre nem conversão de YAML de pipeline em instrução.

## Transporte, mapping e resultado

Reutiliza `WazuhIndexerProvider`: IP pinado, CA/SNI/hostname, sem proxy/redirect,
timeout integral, resposta8MB e orçamento agregado16MB. Prazo total de rede15s,
até5s por request (servidor2s de busca),100hits/página,10páginas, um slot por
processo. Não há retries automáticos. Escopo e conexão são rechecados entre IOs.
O slot é local a cada processo; não constitui lock distribuído nem autorização
de repetição operacional.

GETs de raiz/mapping/settings/aliases precisam satisfazer o gate físico antes da
primeira busca e novamente depois. Só keyword literal nos campos usados, `agent.id`
keyword e `timestamp` date; sem aliases ou adaptação silenciosa. Hash de metadata
deve ser previamente revisado. Template e `_source` não substituem essa coleta.
GETs bem-sucedidos comprovam acesso de leitura, não ausência de privilégios de
escrita; a ACL mínima requer revisão operacional separada.

Busca POST usa somente o índice concreto, `agent.id`, período fechado e query
gerada. Scroll utiliza o cursor mais recente, com DELETE limitado ao cursor próprio
no final, inclusive após revogação. Limites, shards falhos/zero, timeout, total
inexato/instável, schema inesperado ou drift impedem completude. Resposta perdida
pode deixar cursor desconhecido: cleanup permanece não confirmado, mesmo com
DELETE bem-sucedido de cursor anterior; aguardar expiração/reconciliar, sem replay.

Cada hit preserva `_index`, `_id` e `_source`. Um verificador literal independente
confere agente/tempo, seleções/listas e AND/OR/NOT; falsos positivos e duplicatas
conflitantes não viram evidência válida. Não mede recall de documentos omitidos.
Resposta traz total/retornados/páginas/completude/cleanup, escopo/conversão e hashes,
metadata antes/depois, horários e digest do documento. Diagnósticos não incluem
corpos/URLs/exceções do Indexer. Hits brutos são dados autorizados da consulta;
revisar/redigir antes de qualquer publicação, preservando os originais host-only.

Sem persistência automática de resultados: o operador deve preservar o JSON
retornado como novo artefato, sem substituir provas históricas. Não altera banco,
classificações, scopes, aprovações, relatórios ou regras implantadas. Um zero completo
vale apenas para esse índice/agente/período/query; não comprova ausência de
telemetria. Flags do conector real em testes de fixture não constituem prova nativa.

## Próximo ensaio da #89 — pendente, sem executar

1. Obter autorização específica para coleta read-only de metadata e consulta ao
   alerta existente da #59, com negativa controlada, sem novo marcador/run.
   Fixar imagens/IDs/PKI/redes/volumes, principal de leitura e recursos limitados
   em pacote novo, conforme os procedimentos de laboratório. A #17 não concede
   essa autorização. As receitas históricas não podem ser repetidas por inferência.
2. Coletar mapping/settings/aliases físicos do índice autorizado com TLS e ACL
   revisados. Conferir tipos, analisadores, UUID e versão de criação. A versão
   anunciada7.10.2 pode estar mascarada; conferir distribuição/imagem separadamente.
   Se incompatível, parar e preservar a resposta; não alterar índice para passar.
3. Revisar query positiva e negativa geradas pelo backend oficial e versões salvas.
   Cada consulta deve ter escopo/hash próprio, incluindo a mesma janela/agente.
   Só então preparar arquivo privado temporário; autorização cobre quantidade e
   finalidade das consultas, sem retries/reuso implícitos.
4. Confrontar os hits positivos com `_index/_id/_source` e hash do alerta original;
   preservar negativos e completude, metadata antes/depois e cleanup. Não inferir
   implantação Wazuh ou eficácia geral da correspondência do marcador próprio.
5. Encerrar recursos próprios, remover configuração de ativação temporária,
   conferir zero consumidores dos volumes retidos e preservar pacotes/erros/histórico.
   Registrar provas na #89 e somente então avaliar aceite das #87/#88/#89 e do pai.

Preparação offline não concede permissão de iniciar o Indexer ou montar volumes.
O Demo ativo, os laboratórios, a rede qasrc e a PKI permanecem preservados.
