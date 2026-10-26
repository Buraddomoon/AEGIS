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

## Aceite do pipeline Wazuh próprio — 2026-10-22

Uma campanha real `987bd48f-fafc-4a34-bf2a-2d310e7ca794`: preflight de recursos,
imagens 4.14.9 fixadas, mounts efetivos, mTLS, agente 001 Active, regra 100200sandbox,
TLS/ACLs e aprovação segregada de 120s → um marcador43 bytes → log passivo → alerta
original no Indexer → uma evidência persistida, DETECTED/synthetic=false → CLEANED
e workspace vazio → relatório HTML/JSON → revogação/desativação/encerramento.
Diário/volumes preservados e autorização consumida. [Evidência registrada](../evidence/wazuh-2026-10-22/README.md).
Esse aceite cobre só o pipeline de instrumentação; zero técnicas ATT&CK avaliadas,
sem archives, outras versões, Windows ou eficácia de EDR. Testes offline dos
artefatos não constituem outro ensaio real. Não houve nova rodada E2E de navegador.

Incremento de engenharia de detecção: testes PostgreSQL/API cobrem vínculos/versões, concorrência, revisão obsoleta, retirada monotônica, RBAC/CSRF, migração populada, invalidação de início/agendamento e preservação de relatórios. UI permite revisão/retirada/histórico e explica mudanças do escopo. Associação é planejamento; conversão/implantação de regras não estão aceitas. Fluxo Firefox Demo validado com 4 runs/16 testes sintéticos, incluindo troca de versão, retirada e relatório histórico idêntico. Contagens finais e CI em PROGRESS.

Incremento Sigma estático: GET autenticado de versão/hash, checks AEGIS sobre parser/modelo pySigma e consulta de versões atuais/históricas na UI validados por testes e Firefox. Compatibilidade/conversão não configuradas; zero achados não comprova semântica/eficácia. Análise não altera escopos ou veredictos. Compose/smoke confirmaram a leitura pelo papel SQL runtime; contagens finais em PROGRESS.

Preparação Sigma: diagnóstico de campos/requisitos e UI histórica validados; mapeamento candidato não habilita conversão. Requisitos conflitantes e ausência de backend/pipeline/mapping físico continuam bloqueios reais. E2E demonstra exemplo mapeado com can_convert=false e preservação do relatório, sem iniciar SIEM. Conversão/implantação não aceitas; detalhes e contagens finais em PROGRESS.

Catálogo ATT&CK controlado: prepare real do bundle20.0 por commit, plan/apply da
CLI em PostgreSQL, persistência de867referências, repetição idempotente,
proveniência e histórico imutáveis. Dois ciclos sintéticos confirmaram relatório
anterior idêntico e cobertura atual somente após nova aprovação/execução. API,
worker e papel runtime restrito validados; Firefox inspecionou snapshot histórico
e produziu captura real. Demo local migrado/publicado,20runs anteriores
preservadas. Não equivale a nova versão oficial, cobertura defensiva real,
sincronização automática ou novo ensaio Linux/Wazuh.

Recorte analítico: período semiaberto com fuso, release exata/atual/legado,
snapshot consistente e limites sem truncamento; exportações agregadas e
comparativas com membros/evidências/hashes. Equivalência exige árvore/manifesto
e resultados completos/contexto conhecido. UI bloqueia ações após erro e
mudança de filtros; Firefox exportou ambos os tipos, aplicou legado e período
vazio sem novos efeitos reais. Contagens finais e CI no PROGRESS.

Backup cifrado host-only: age/X25519, chave separada, publicação privada e limites;
stream completo autenticado e hash consumido antes de restore. Cópia real restaurada
em clone offline:32tabelas/3.169linhas, fonte/usuários iguais e clone/staging removidos.
Retenção somente leitura usa snapshots distintos e verificados/chave disponível;
sem exclusão/upload. Originais permanecem em claro, chave/cópia ainda locais.
Guarda independente, recuperação entre hosts e RPO/RTO não são critérios aceitos.
[Procedimento](../operations/encrypted-backups.md).
