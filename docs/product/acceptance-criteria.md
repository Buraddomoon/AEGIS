# Aceite por escopo — código 0.2.0

Critérios abaixo cobrem incrementos comprovados; não equivalem ao cumprimento de
todo o roadmap. A versão do código não foi elevada para simular marcos concluídos.

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

Consolidação de entrega: gerador local com recusa de arquivos inseguros/segredos
vazios, preservação de configuração válida e testes em diretórios descartáveis.
Compose renderizado com configuração nova sem iniciar serviços; versões/links
inline locais/cabeçalhos PNG/padrões de credenciais verificados no índice Git.
README/galeria distinguem Demo, histórico Linux e ensaio Wazuh encerrado. CI leve
separada para documentação não instala dependências nem bancos. Não é um novo
boot completo, E2E, ensaio de laboratório ou release publicada.
[Procedimento e limites](../operations/release.md).

Prévia Sigma: pipeline oficial de field rename aplicado em memória no subconjunto
revisado; API de versão/hash somente leitura e UI com antes/depois, unsupported,
loading/erro e recusa de contexto divergente. Não aceita pipeline/YAML/vars/plugins
externos e não altera regra histórica, relatório ou classificação. Can_convert,
query_generated, siem_queried, deployment_performed e mapping físico continuam false.
Backend compatível e pipeline completo para consultas não estão aceitos.

PKI do runner: inspect/prepare/verify host-only aceitos para inventário público e
candidato separado, preservando origem/IDs, com hashes, validação criptográfica,
limites de arquivos, validade atual e recusa de drift. Testes incluem TLS loopback
e falhas de durabilidade/retry. Candidato real verificado sem chaves antigas,
diário, banco ou laboratório. Ativação, novo binding/preflight, recuperação sob
confiança alterada e PKI dos serviços Wazuh não estão aceitos.
[Operação](../operations/runner-pki.md).

Revisão de vínculo: API administrativa somente leitura e UI aceitas para mostrar
bloqueios persistidos; mutações Linux/Wazuh recusam pendências e cleanup inválido
mesmo sem reserva. Solicitação Linux serializada com revogação/revisão, com teste
PostgreSQL concorrente. Ausência de bloqueio não é autorização, validade da PKI
ou integridade do diário. Ativação e recuperação real sob confiança alterada
permanecem fora do aceite. [Limites](../operations/linux-binding-review.md).

Plan/recheck da ativação Linux aceitos para snapshots de metadados: hashes PKI/
Compose, imagens locais por ID, volumes/labels/consumidores e TTL15min; consulta
real e fixtures não concedem autorização nem comprovam diário/runtime/imagens.
Executor/ativação/banco original/mTLS novo ainda fora do aceite. Nenhum ensaio
anterior é reaberto por um plano. [Contrato](../operations/runner-pki-activation.md).

Continuidade banco/diário aceita como componente testado em schemas/diários
temporários: snapshot PG somente leitura, binding antigo exato, provas completas
por hash e revisão DB+WAL sem inicializar a origem. Probe /state limitado e sem
conteúdo de jobs na saída. Não equivale a inspeção dos volumes reais, ativação,
mTLS novo ou permissão de retomar jobs. Esses itens continuam fora do aceite.

Ownership aceito como armazenamento testado em temporários: catálogo/nomes/labels
derivados, eventos/hashchain/fsync, retomada por hash, recusa de histórico parcial e
retenção de dependências. Não aceita Docker/apply/ativação ou ausência real apenas
pelo hash de uma observação registrada. [ADR0022](../architecture/decisions/0022-activation-resource-intents.md).
