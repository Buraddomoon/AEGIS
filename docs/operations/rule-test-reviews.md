# Revisões entre regras e testes

Em **Regras Sigma → Testes e revisões**, operador/admin pode selecionar um teste,
inspecionar o YAML atual, descrever a relação esperada e confirmar as versões.
Viewer consulta vínculos e histórico. O vínculo é metadado de planejamento:
não implanta Sigma, não modifica a regra Wazuh esperada, não executa testes e
não altera as classificações ou os denominadores de cobertura.

Cada revisão fixa versão/hash da regra, versão do teste, justificativa e autor.
Uma nova versão Sigma ou teste sinaliza **Revisão necessária**. A revisão seguinte
retira a anterior e cria outro registro na mesma transação. Há somente um vínculo
ativo por par regra/teste. Retirar um vínculo preserva seu histórico. Datas e
responsável pela primeira retirada não podem ser reescritos ou anulados pelo
runtime. Hash não é assinatura; o administrador do banco continua privilegiado.

O título exibido em `current_rule_title` é o nome atual do inventário. O conteúdo
revisado é identificado por `rule_version_id`, `rule_version` e `rule_sha256`,
consultável no histórico YAML. Não inferir conteúdo antigo pelo título atual.

Uma atualização da API que mude regra, teste, revisão anterior ou justificativa
invalida a confirmação do formulário. Conflito HTTP409 requer **Atualizar dados**
e nova revisão; o frontend não sobrescreve silenciosamente a revisão de outro
operador. Ausência de técnica ATT&CK em um teste não impede vínculo justificado;
o vínculo não cria associação ATT&CK artificial.

## Escopos e comparação

Novas solicitações e planos guardam `scope.rule_test_links`, ordenado e incluído
no hash aprovado. Somente vínculos dos testes selecionados entram nesse campo.
`rule_versions` mantém o inventário inteiro, como nas versões anteriores: importar
qualquer regra ou versão pode invalidar uma aprovação/plano ainda não iniciado.
Alterar um vínculo relevante também exige nova solicitação e aprovação. Runs já
iniciadas usam o snapshot aprovado; editar inventário não muda suas evidências.

Ao atualizar uma instalação anterior a este recurso, aprovações/planos antigos
sem o novo campo não coincidem com o escopo atual. Criar nova solicitação/plano,
revisar e aprovar novamente. **Não editar snapshots ou hashes históricos** para
reativar autorizações antigas. Histórico e relatórios concluídos permanecem
legíveis e preservados. O agendamento continua somente Demo.

**Cobertura → Comparação entre execuções** mostra diferenças de inventário Sigma,
vínculos, definições de testes e ambiente/coleta a partir dos dois snapshots.
Escopos antigos sem o campo de vínculos mostram contexto **desconhecido**, não
uma conclusão de que não existiam vínculos. Mudanças de resultado/configuração
não demonstram causalidade nem risco de negócio. A matriz ATT&CK exibe vínculos
planejados dos testes do modo selecionado, separados de regras operacionais.

## API

- `GET /api/v1/rule-test-links?rule_id=…&test_id=…&include_retired=true&limit=10&offset=0`
  consulta paginada; filtros opcionais, padrão somente ativos.
- `POST /api/v1/rules/{rule_id}/test-links` registra revisão. Corpo:
  `rule_version_id`, `test_id`, `confirm_rule_sha256`, `confirm_test_version`,
  `rationale` (20–4000 caracteres), `replaces_id` (vínculo ativo anterior ou null).
  Versão Sigma deve ser a última; SHA/test_version precisam coincidir.
- `DELETE /api/v1/rules/{rule_id}/test-links/{link_id}` retira, sem exclusão física;
  repetição não altera a primeira retirada nem retira o vínculo substituto.

Toda mutação exige sessão, CSRF e papel operador/admin. Consultas exigem sessão.
Backend serializa importações/revisões/retiradas pelo lock da regra; FK composta
impede vincular versão de outra regra e índice parcial garante unicidade ativa.
Runtime tem INSERT/SELECT e UPDATE somente para primeira retirada, sem DELETE.
Migrações: `ec3020ae8711`, `977fd0c42ae8`; aplicar via fluxo de implantação normal,
incluindo `grant-runtime`. Nenhuma dependência nova, conector ou ensaio real.

Validação de semântica, conversão oficial para SIEM e implantação continuam
pendentes. Vínculo revisado por uma pessoa não comprova que a consulta detecta o
comportamento: isso exige teste autorizado e evidências defensivas correspondentes.
