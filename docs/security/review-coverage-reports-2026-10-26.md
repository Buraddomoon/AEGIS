# Revisão dos recortes e relatórios — 2026-10-26

Escopo: analytics.py/analytics_api.py, métricas/comparação em queries.py,
exportadores em reporting.py e filtros/UI. Sem migração, nova dependência,
ensaios Linux/Wazuh, coleta externa ou implantação Sigma.

Revisão especializada somente leitura encontrou três bordas relacionadas a
conclusões incorretas; todas foram corrigidas e conferidas novamente por inspeção:

- Pai COMPLETED com filho FAILED ou sem ValidationResult podia sustentar
  equivalência/denominador comparativo. Comparação agora exige filhos concluídos
  e resultado presente; denominador considera pais e filhos COMPLETED.
- Um filho individual ausente não era detectado pela simples verificação de
  lista vazia. Conjunto de test_id presentes deve corresponder ao manifesto
  planejado no scope. Fixtures negativas não apagam dados do ambiente real.
- TanStack conserva dados após erro de refetch. A UI passou a bloquear ações
  e ocultar comparação cacheada também nessa condição, além de dirty/mismatch.
  Regressão simula falha depois de uma comparação válida.

A revisão não executou testes, Docker, rede ou acesso a arquivos privados.
Resultados efetivamente executados ficam no PROGRESS e nos testes. Delta usa
frações antes de arredondar, somente quando comparabilidade e denominadores
são sustentados; contexto desconhecido nunca recebe identidade retroativa.

Seleção validada com fuso explícito e intervalo semiaberto, predicados SQL
parametrizados, releases por identidade exata e snapshot REPEATABLE READ READ
ONLY separado da autenticação. Timeout SQL15s e limite5000runs sem truncamento;
join analítico não retransmite o scope completo por teste já carregado.
Nenhum destino, comando, arquivo ou SQL arbitrário é recebido da API.

Exports exigem sessão,30/min por usuário, auditoria somente de tipo/formato/hash;
viewer pode exportar dentro do workspace compartilhado, sem permissão de
aprovação/administração. HTML escapa dados originais e não carrega scripts ou
recursos externos. Hash cobre JSON entregue, sem seu próprio campo; não é
assinatura ou defesa contra administrador do banco. Comparações identificam
ambos os lados e presença de dados sintéticos; ausência de alerta não confirma
comprometimento nem proteção empresarial.

Limites: relatório novo pode incluir dados posteriores dentro do mesmo recorte,
com timestamp próprio; sem snapshot exportável histórico armazenado, PDF,
multi-workspace ou promessa de grande escala. Backups antigos continuam sujeitos
às guardas de imagem/schema. Advisory transitivo DiskCache já revisado permanece;
não há alegação de ausência de vulnerabilidades.
