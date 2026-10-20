# Registro de progresso — ÆGIS

## 2026-10-20 — Fundação e primeiro ciclo Demo

- Ambiente inspecionado; projeto novo em `/home/IVPTER/codes/aegis`, sem alterar projetos existentes. Python local 3.13.14, Node 24.18, Docker disponível. Serviços próprios PostgreSQL/Redis e portas loopback 18780–18784.
- Arquitetura e ADR 0001 registrados. Fila transacional PostgreSQL escolhida para evitar dual-write. Contratos SIEM independentes, máquina de estados e correlação conservadora implementados.
- Snapshot ATT&CK Enterprise 20.0 oficial: 706 técnicas/subtécnicas ativas, hash de origem no fixture e licença preservada.
- Backend implementado com autenticação, sessão opaca/Argon2id/CSRF, RBAC, catálogo, Demo Lab, campanhas, aprovação de uso único, worker, eventos, evidências, cobertura, comparação, HTML/JSON, parsing Sigma e auditoria.
- Primeira validação: **25 testes pytest passaram** (domínio + integração PostgreSQL real) em 9,61s. Migrações aplicadas e `alembic check` sem diferenças. `mypy` passou para domínio. Build React/TypeScript/Vite passou; aviso de bundle grande a tratar.
- UI implementada sobre API; validação de navegador e testes adicionais ainda pendentes neste ponto. Não declarar aceite completo.
- Conector Wazuh somente leitura implementado com TLS e IP fixado; **nenhuma conexão real validada**. Lab Mode, execução Atomic, scheduler, PDF e implantação de regras não habilitados.
- Revisão especializada inicial concluída; segunda revisão do código em andamento.
- Política de Git atualizada pelo usuário: repositório privado, somente main, commits granulares e push após cada commit. Aplicação da política em andamento; consultar `git log` e remoto para o estado atual.

## Próximas unidades verificáveis

1. Testes de segurança, importação e Wazuh com fixtures.
2. Fluxo E2E em Firefox já instalado, capturas reais e revisão visual.
3. Docker build/Compose completo, lockfiles, Makefile e CI.
4. Documentação operacional, limitações e aceite final do MVP Demo.

## Marco 0.1 — fluxo Demo validado

Fundação e primeiro MVP funcional implementados. Todos os cenários operacionais desta entrega são demonstrativos e explicitamente sintéticos; não houve execução ofensiva real, instalação de Wazuh ou acesso a alvos externos.

### Entregas

- API FastAPI versionada, PostgreSQL/Alembic, Redis, worker independente e SPA React/TypeScript responsiva em pt-BR.
- Sessões opacas/Argon2id, CSRF, RBAC, rate limit, erros sem echo de segredos, headers e origem restrita.
- 706 técnicas/subtécnicas oficiais ATT&CK 20.0, matriz/tabela/filtros; quatro simulações Demo em allowlist, com associação técnica somente quando justificada.
- Campanhas, scope/hash imutáveis, aprovação administrativa com validade/duração/uso único, confirmação de início, claim exclusivo e fence contra entrega duplicada.
- Cancelamento, deadline, cleanup obrigatório, erro visível/reserva retida na falha e recuperação de contextos sintéticos abandonados sem replay.
- Eventos/resultados/evidências persistidos, hashes, correlação conservadora, métricas com denominador, histórico, comparação, HTML/JSON e auditoria.
- Sigma parsing/versionamento/diff; importação Atomic somente metadados; adapter Wazuh somente leitura com TLS/IP pinning/scroll, testado por contrato e ainda desconectado de infraestrutura real.
- Docker não root/read-only/cap_drop; runtime SQL separado sem superuser e com evidências/auditoria/versões append-only.
- README com capturas reais, documentação de arquitetura/segurança/operação, licenças, Makefile e CI eficiente na main.

### Validação efetivamente executada

| Comando/check | Resultado observado |
|---|---|
| `make lint` | Ruff/format, mypy domínio e TypeScript/Prettier aprovados |
| `.venv/bin/pytest -q` | **56 passed**, 1 aviso upstream de TestClient/httpx, 16,43s na rodada final |
| `npm --prefix apps/web test` | **3 passed** |
| `make e2e` | **PASS**, Firefox do host, 2 runs / 8 testes sintéticos, zero erros JavaScript, comparação e exportação reais, viewport móvel sem overflow |
| `make build` | aprovado; bundle principal e gráfico separados, sem aviso de chunk >500kB |
| `docker compose build` + `up -d --wait` | aprovados; migrações/seed/grants e health DB/Redis reais |
| `make smoke` | aprovado no Compose final: login, campanha, aprovação, worker, 4 classificações persistidas e JSON; conta temporária desativada no fim |
| Privilégios no container | current_user=aegis_app, rolsuper=false, UPDATE em audit_events=false |
| `make audit` | npm: zero avisos; Python: um advisory transitivo DiskCache revisado, visível, com teste da premissa de caminho não utilizado |
| Markdown local | referências locais verificadas, sem destinos ausentes |

CI GitHub do código `4833eca`: **SUCCESS**, run [39478839252](https://github.com/Buraddomoon/AEGIS/actions/runs/39478839252). Instalação com locks, lint/tipos, testes PostgreSQL/React, build e auditoria remotos aprovados. O run anterior foi cancelado automaticamente por concurrency, confirmando a política de evitar jobs redundantes. Não foi habilitado plano/recurso pago. O checkpoint posterior modifica somente documentação/proveniência, sem exigir nova execução redundante de CI.

### Revisão e correções

Revisões especializadas iniciais/finais somente leitura não apontaram bloqueador restante para Demo. Corrigidos backfill de migração em banco populado, recuperação concorrente de reserva, streaming Wazuh, IPv4 mapeado, espaços significativos em senha, títulos Sigma excessivos e hash do JSON efetivamente exportado. Ver `security/review-2026-10-20.md`.

O repositório `Buraddomoon/AEGIS` foi criado com visibilidade PRIVATE, confirmada antes do primeiro push e novamente ao final. Desenvolvimento exclusivamente em main, sem PR, branches temporárias, force push ou reescrita. Commits/pushes granulares registrados em `git log`; estado exato do checkpoint de documentação é verificável com `git log -1` e `git status -sb`.

### Retomada / pendências reais

Aplicação local em `http://localhost:18780`. O administrador humano deve ser criado com `make bootstrap`; não há credencial padrão. `.env` local contém segredos aleatórios e está ignorado. Contas de smoke são aleatórias, sem senha registrada e desativadas ao final. Testes usam schemas descartáveis e não apagam dados do aplicativo.

Próxima etapa recomendada: preparar Linux Lab isolado próprio, obter autorização específica para um teste benigno, implementar isolamento/prazo efetivo dos adapters e mapear ativos internos/externos antes de ligar Wazuh. VM Windows somente quando autorizada e necessária. Lab Mode, Atomic executável, consulta Wazuh operacional, scheduler, PDF, implantação de regras e IA continuam no roadmap.

Sem claims de detecção real, proteção empresarial, zero vulnerabilidades ou maturidade enterprise-ready. Atualização do snapshot ATT&CK existe; substituição/depreciação em banco populado ainda requer migração de dados revisada. Sem tenant/MFA/SSO/recuperação de senha na UI e sem política automática de retenção.


## Renomeação do repositório GitHub

Por solicitação do usuário, o repositório foi renomeado para **AEGIS**, em maiúsculas, preservando PRIVATE e main. O GitHub [permite apenas caracteres ASCII no nome de repositórios](https://docs.github.com/en/repositories/creating-and-managing-repositories/creating-a-new-repository), portanto ÆGIS permanece a marca do produto e AEGIS é o nome remoto.

Origin de fetch/push atualizado explicitamente para `https://github.com/Buraddomoon/AEGIS.git`; README e AGENTS atualizados para evitar referências divergentes. O diretório de trabalho continua `/home/IVPTER/codes/aegis`; o exemplo de clone mantém esse nome local explicitamente. Validação desta mudança: consulta do nome/visibilidade/branch via gh, revisão de staged, fetch e push pela URL nova, comparação main/origin/main.

## Continuidade — agendamento Demo aprovado

Estado inicial: main limpa/sincronizada no commit 0e25333, remoto AEGIS confirmado PRIVATE e serviços Demo saudáveis. Próximo marco em implementação: agendamento de campanhas sintéticas sob aprovação delimitada, conforme ADR 0002. Não executar em laboratório real nem estabelecer conexão Wazuh externa. As etapas abaixo ainda precisam de validação antes de serem anunciadas como prontas: transações reutilizáveis, schema/autorizações, dispatcher, RBAC/API, UI, testes e documentação operacional.
