# Aceite do MVP Demo

| Critério | Evidência / estado |
|---|---|
| Inicialização reproduzível, API, SPA e banco | Docker build/Compose executados; health ready DB/Redis confirmado |
| Autenticação e RBAC backend | testes de login, CSRF, viewer/operator e escalada negada |
| Campanha, aprovação e worker | E2E navegador + API + worker + PostgreSQL real |
| Demo persistente, sem dados estáticos de UI | eventos/resultados consultados da API; schema E2E real |
| Classificações e evidências corretas | testes contra alerta de outro ativo/marcador/tempo/regra e inspeção de payload/hash |
| Cancelamento, timeout, idempotência e cleanup | testes de claim/entrega concorrente, cancelamento ativo/fila, falha/recuperação |
| Métricas com denominadores e histórico | teste 1/3 e E2E 2/6; técnicas catalogadas distintas das avaliadas |
| Exportação e comparação | HTML escapado, JSON original, repetição com nova aprovação e comparação de mesmo escopo |
| UI funcional e responsiva | E2E visita páginas e verifica ausência de overflow em 390px; capturas reais |
| Catálogo oficial versionado | snapshot, referência, licença e hash de origem |
| Integrações não configuradas explícitas | Wazuh desconectado; Linux somente por opt-in revisado; scheduler somente Demo aprovado |
| Agendamento Demo delimitado | testes de grant exato, slots concorrentes, rollback, busy/atraso, limites, revogação, cleanup, E2E e smoke runtime |
| Segurança de importações | testes YAML, parsing pySigma, versionamento; sem implantação automática |
| Qualidade e GitHub | checks locais, CI configurada, privado/main-only, staged verificado e pushes granulares |

Consulte docs/PROGRESS.md para a rodada final de testes e estado real da CI. Não considerar Wazuh externo ou agendamento de laboratório real concluídos a partir desses critérios. Auditoria de dependências mantém advisory transitivo revisado; isso é limitação documentada, não alegação de ausência de vulnerabilidades.

## Aceite Linux 0.2 limitado ao marcador

Campanha única no ensaio autorizado: cadastro/preflight mTLS/autorização → solicitante operador → administrador distinto → PostgreSQL/worker → marcador real de 43 bytes → CLEANED → recibos e relatório → INCONCLUSIVE sem SIEM. Runtime SQL sem UPDATE/DELETE em comprovantes, workspace vazio, contas temporárias desativadas, laboratório revogado e containers/redes encerrados. Captura do histórico em Firefox real, sem repetir o efeito. Testes de crash, resposta perdida, configuração/usuários revogados, 404 sem liberação e comparação entre modos. Não equivale a validação Wazuh.
