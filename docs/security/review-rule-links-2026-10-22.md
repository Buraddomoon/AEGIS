# Revisão de associações Sigma/teste — 2026-10-22

Escopo: ADR0007, modelo/migrações, API/serviço de vínculos, snapshots,
comparação e UI. Revisão especializada somente leitura, seguida de correções e
testes executados pelo agente principal. Nenhum ensaio real foi autorizado por
esta revisão. O Wazuh encerrado permaneceu parado, com volumes preservados.

Achados corrigidos:

1. Privilégio UPDATE das colunas de retirada permitia anular ou reescrever a
   primeira retirada via SQL. Migração977fd0c42ae8 acrescenta trigger monotônico,
   incluindo recusa de exclusão. Teste real PostgreSQL tenta reativar, alterar
   justificativa e excluir; todas as operações são recusadas. Runtime também
   não tem UPDATE nas colunas imutáveis ou DELETE.
2. O título atual do inventário podia ser confundido com título da versão antiga.
   DTO chama o campo `current_rule_title`; conteúdo revisado fica identificado
   pelo ID/versão/hash imutáveis. Relatórios guardam snapshot, sem reconsulta
   posterior ao inventário para reescrever contexto histórico.
3. Confirmação booleana podia sobreviver a atualização dos dados de versões ou
   do vínculo anterior. A UI confirma o payload serializado exato, invalida ao
   mudar dados e envia esse payload. Testes de cache verificam mudança de versão
   e revisão concorrente depois de marcar a confirmação.
4. Resposta atrasada de comparação podia reaparecer sob outros filtros.
   Seletores de modo e execuções ficam bloqueados durante consulta; IDs do
   resultado aparecem no painel. Teste mantém resposta pendente e confere o
   bloqueio até sua chegada.

Verificados: RBAC/CSRF, validação/limites de entrada, lock de regra compartilhado
com importação, índice parcial ativo e FK composta de versão/regra. Revisão
concorrente retorna409; substituição requer replaces_id. Retirar registro antigo
não retira seu substituto. Backend mantém expected_rule, binding Wazuh e lógica
de classificação independentes dos vínculos.

Testes preservam relatório e cobertura após revisão e comparação histórica após
novas edições do inventário. Mudança de vínculo invalida início aprovado e plano
recorrente, sem emitir ocorrência. Migração em banco populado conserva campanha
e versão Sigma. Smoke do Compose consulta privilégios/trigger do papel runtime.

Limites: revisão humana não comprova semântica, compatibilidade, implantação ou
eficácia. Banco continua sob controle de seu administrador privilegiado; trigger
e hash não equivalem a assinatura ou armazenamento externo inviolável. Não há
expurgo automático dos vínculos. Inventário global continua afetando scope/hash,
conforme comportamento conservador existente e documentado. Ver
[operação](../operations/rule-test-reviews.md) e [progresso](../PROGRESS.md).
