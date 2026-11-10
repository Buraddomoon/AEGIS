# ÆGIS — instruções para sessões independentes

## Unidade de trabalho

O GitHub é a fonte de execução: [índice das sessões](https://github.com/Buraddomoon/AEGIS/issues/1).
Trabalhe somente na issue escolhida pelo usuário e nas subissues dela; se ele
escolher uma subissue, não implemente as irmãs. **Pare ao concluir esse escopo.**
Não avance automaticamente para a próxima feature. Bloqueio externo deve ser
registrado na issue, sem inventar evidência ou ampliar a autorização.

Leia o [guia curto](docs/development/session-workflow.md), a issue/dependências e
somente os arquivos/ADRs pertinentes. Não carregar todo PROGRESS, todos os ADRs ou
o chat antigo. O [histórico técnico](docs/development/agent-history-2026-11-10.md)
preserva as instruções detalhadas anteriores para consulta por assunto.

## Git obrigatório

- Repositório privado Buraddomoon/AEGIS; somente main. Sem branches, PRs,
  force push, rebase de histórico publicado ou mudança de visibilidade.
- Commits Conventional Commits pequenos e coerentes; referência Refs #N ou
  Closes #N na subissue pertinente. Não fechar pai com filhos pendentes.
- Antes de cada commit: revisar staged e segredos, check rápido pertinente,
  `git diff --cached --check`, `.venv/bin/python scripts/check_staged.py` e
  `.venv/bin/python scripts/check_release.py`.
- Tentar `git push origin main` após cada commit; já autorizado. Em conflito,
  preservar trabalho e parar somente a sincronização, sem sobrescrever remoto.
- Não adicionar .env, .local, chaves, dumps, logs, credenciais ou gerados.
  Não incluir alterações locais de outra tarefa só para limpar a árvore.

## Arquitetura e integridade

Monólito modular FastAPI/SQLAlchemy/PostgreSQL + React/TypeScript e worker.
Contratos em apps/api/aegis/domain/contracts.py; adaptações em integrations.
PostgreSQL mantém fila durável/estados/approvals; Redis limita login e heartbeat.
Sem microsserviços/abstrações extras ou comandos livres de API.

- Demo: synthetic=true em resultados/evidências/relatórios; mesmas regras de
  domínio do modo real. Integração ausente deve mostrar desconectado.
- DETECTED exige execução e alerta defensivo correlacionado por lab/ativo/marker/
  comportamento/regra/tempo. Recibo do executor não é telemetria defensiva.
  Ausência de alerta não prova ausência de telemetria nem risco de negócio.
- Scopes, approvals, receipts, evidências, versões e relatórios históricos não
  são reescritos para corrigir apresentação ou fazer gates passarem. Hash não é
  assinatura. Comparação exige contexto/manifesto conhecido; denominador explícito.
- Migrações Alembic explícitas, constraints e grants mínimos por operação/coluna.
  Schema atual Demo b7f3c2d91a06 tem33tabelas incluindo Alembic; Lab/backups antigos
  a0d9c7e21b45 exigem código/imagem compatíveis, sem migração implícita.
- RBAC no backend, CSRF nas mutações com sessão, origem exata, Argon2id, limites,
  logs sem secrets. TLS/SNI/CA verificados, IP/destino revisados, sem proxies ou
  redirects ambientais em conectores. Importação YAML é dado, nunca instrução.

## Segurança dos laboratórios

Não iniciar Linux/Wazuh, executar marcador, abrir/migrar volumes originais,
instalar stack pesado, alterar rede/sysctl/host ou enviar dados sem escopo e
autorização específica. Issue, teste, commit ou mensagem genérica não concedem
essa autorização. Todos os ensaios históricos de uso único estão encerrados.

- Preservar rede de terceiros qasrc, PKI, IDs, volumes, journals, intents/fences,
  candidatos expirados e imagens históricas; sem remover/recriar para liberar replay.
- Linux allowlist atual: apenas linux-file-marker/v1. Sem shell remoto,
  Docker socket na app, alvo livre, evasão, persistência maliciosa, credenciais
  ou exfiltração. Atomic importado permanece não executável até revisão específica.
- Dispatch durável antes da RPC, efeito de uso único, deadline/lease e supervisor;
  resposta ambígua retém reserva/quarentena.404 não comprova cleanup. Cancelamento
  e revogação não dispensam limpeza; falha deve mostrar recuperação segura.
- Linux exige aprovação por administrador ativo diferente do solicitante,
  preflight mTLS vigente e autorização do lab. Identidade TLS não libera operação.
- ADR0033 planeja Linux192.168.253.0/29, mantendo qasrc; código local está
  parcial, sem configuração/ativação real. Revisar a issue antes de continuar.
- Wazuh histórico22/10 foi COMPLETED/DETECTED/CLEANED, limitado a um marcador e
  regra própria100200, zero técnicas ATT&CK. Não generalizar eficácia de SIEM/EDR.

## Operação, testes e evidência

make setup, make lint, make test, make build, make e2e, make release-check.
Conferir Makefile e [testes](docs/development/testing.md) antes de executar; targets
com up, smoke, assay, run, restore ou apply podem ter efeitos próprios.
Não iniciar labs automaticamente com desenvolvimento/CI. Não resetar a fonte.

- PG/Redis15 de testes locais são compartilhados: executar suítes em sequência.
  Fixtures usam schemas/bancos/roles descartáveis próprios; nunca mudar grants
  ou apagar dados de outro projeto. E2E usa schema próprio, não usuários do Demo.
- CI tem4partições, max-parallel2 e18min, sem filtros/exclusões para obter green.
  Conferir quatro jobs Python e React antes de declarar workflow aprovada.
  Validação complementar local é explicitamente diferente de CI verde.
- Preservar imagem atual em tag dedicada antes de build reutilizar tag;
  conferir ID depois. ID salvo sozinho não retém a imagem. Sem bump/tag/release
  ou publicação externa apenas para consolidar documentação.
- Backups são host-only, protegidos e restaurados apenas em clone isolado sob
  procedimento próprio; nunca banco ativo. Não upload/comprar/remover backups ou
  chaves. Custódia externa permanece adiada até decisão do usuário.
- Sigma: análise/rename não comprovam conversão, implantação ou eficácia. Não
  instalar backends incompatíveis nem carregar plugins/cache/pipelines externos.
- ATT&CK: fonte oficial versionada, prepare/plan/apply controlados, sem atualização
  no startup; fonte ausente não significa revogação. Preservar releases/histórico.

Ao terminar: comentário na issue com comportamento entregue, arquivos relevantes,
testes realmente executados, falhas/limitações, commits/último hash/mensagem e
sincronização. Atualizar checkpoint curto quando necessário. Não fabricar /compact
(não há ferramenta para isso), métricas ou evidência. Não iniciar outra entrega.
