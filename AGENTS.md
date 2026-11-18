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
  Schema Demo b7f3c2d91a06 tem33tabelas incluindo Alembic. Lab Linux original atualizado sob aprovação específica da #5 em12/11:
  b7f3c2d91a06/33tabelas; backup da #48 e backup fresco preservam d446/27tabelas; a0d9c7e21b45/32tabelas era hipótese anterior e segue em
  fixtures/perfis intermediários. Exigir código/imagem compatíveis, sem migração implícita.
  Wazuh original atualizado explicitamente na #58 em13/11: b7/33tabelas,
  histórico/verificadores preservados; backup frio/restore4b72c7bb8548/29tabelas
  e clone b7 retidos. Manutenção encerrada, sem operação normal/marcador.
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
- Perfis históricos Linux: apenas linux-file-marker/v1. Fonte da #79 acrescenta
  um perfil opt-in separado de permissões de arquivo próprio, com revisão/hash
  fixados; #80 teve uma campanha nativa autorizada em18/11, pacote202afac5,
  COMPLETED/INCONCLUSIVE/CLEANED. Lab revogado, contas próprias inativas/zero
  sessões, recursos encerrados/três volumes retidos sem consumidores. Provas em
  docs/evidence/atomic-execution-2026-11-18/VERIFIED-80.md. Autorização consumida;
  sem replay/operação contínua. a4335444 expirada preservada sem tentativa.
  #14 com aceite conjunto em18/11: #78/#79/#80 e dependências concluídas;
  ver docs/evidence/atomic-execution-2026-11-18/ACCEPTANCE-14.md. Entrega encerrada.
  Ver docs/development/atomic-execution-checkpoint.md. Sem shell remoto,
  Docker socket na app, alvo livre, evasão, persistência maliciosa, credenciais
  ou exfiltração. Atomic importado permanece não executável até revisão específica.
- #83 em18/11, sob autorização dos pacotes0a85302e/22431af4: uma campanha de
  processo benigno e uma de shell fixo, ambas COMPLETED/INCONCLUSIVE/CLEANED,
  synthetic=false. Labs revogados, quatro contas UI próprias inativas/zero
  sessões, recursos encerrados; seis volumes retidos sem consumidores.
  Autorização consumida, sem replay/reativação/operação contínua. Provas em
  docs/evidence/linux83-2026-11-18/VERIFIED-83.md. Aceite conjunto#15 concluído
  em18/11: docs/evidence/linux83-2026-11-18/ACCEPTANCE-15.md. Entrega encerrada.
- Dispatch durável antes da RPC, efeito de uso único, deadline/lease e supervisor;
  resposta ambígua retém reserva/quarentena.404 não comprova cleanup. Cancelamento
  e revogação não dispensam limpeza; falha deve mostrar recuperação segura.
- Linux exige aprovação por administrador ativo diferente do solicitante,
  preflight mTLS vigente e autorização do lab. Identidade TLS não libera operação.
- Receitas Linux usam192.168.253.0/29 sob ADR0033, mantendo qasrc. Ensaio nativo
  da #4 em12/11/2026 encerrado: binding revogado, preflight/continuidade e cleanup
  confirmados, sem operação normal. Campanha única da #5 verificada e encerrada
  em12/11: marcador43bytes, COMPLETED/INCONCLUSIVE/CLEANED; catálogo inicializado
  sob escopo adicional, lab revogado e contas próprias inativas. Ver relatório
  CAMPAIGN-VERIFIED-2026-11-12; não reutilizar pacotes consumidos.
- Wazuh histórico22/10 foi COMPLETED/DETECTED/CLEANED, limitado a um marcador e
  regra própria100200, zero técnicas ATT&CK. Não generalizar eficácia de SIEM/EDR.
- #58 em13/11: banco original b7/grants verificados e parado; imagens atuais
  locais conferidas, sem implantação. Ver [relatório](docs/evidence/wazuh-database-2026-11-13/UPGRADE-ORIGINAL.md).
  Continuidade/journal/log verificados RO e catálogo versionado adotado no
  original sob autorizações separadas em16/11, ambos encerrados/CLEANED.
  Original b7/33 parado, histórico/verificadores/grants preservados; backup b7
  pré-catálogo2c19f3ed e backups4b72 retidos. Imagens locais corrigidas de
  OpenTelemetry1.45.2: API/worker9e3488c4 e runner/observer77dec541, sem implantação.
  Prontidão integrada limitada verificada depois sob pedido explícito para
  tentar com RAM disponível: perfil3360MiB/heap512MiB, nove serviços/182checks,
  TLS/ACL efetiva/agente/regra/mTLS/observador; sem OOM ou marcador. Falha de IP do
  helper e continuação na API preservadas, ambas CLEANED/zero consumidores.
  Ver docs/evidence/wazuh-cycle-2026-11-16/BOUNDED-READINESS.md. Preparação#58
  atendida;#59/#60 dependem de escopo específico de binding/contas/efeito único.
  Piso padrão8GiB preservado; pacotes de prontidão consumidos. Autorizações de
  diagnóstico/clone/manutenção/catálogo utilizadas. Ver relatório
  docs/evidence/wazuh-cycle-2026-11-16/ORIGINAL.md; não repetir os ensaios.
  Campanha#59 autorizada depois por “autorizo”, única execução em16/11:
  b338665e, COMPLETED/DETECTED/CLEANED, marcador43bytes e alerta original100200;
  zero técnicas ATT&CK. Continuidade/bindings atuais renovados, histórico e
  contas/senhas antigas preservados. UI/JSON/HTML/PDF da mesma run verificados
  na#60, sem replay. Lab revogado/ambiente6, duas contas próprias inativas/zero
  sessões próprias, nove volumes sem consumidores, recursos próprios encerrados.
  Ver docs/evidence/wazuh-cycle-2026-11-16/CAMPAIGN.md e UI-EXPORTS.md.
  Entrega#7 atendida; autorização/pacote9f60b4c8 consumidos, sem operação contínua.
- #63/#8 em17/11, após autorização explícita de retomada: perfil
  `wazuh-4.14.9/1` consultado no Indexer real, alerta original da#59 idêntico,
  negativa de filtro e cleanup de cursores verificados; archives404/incompletos,
  sem habilitar ingestão. NATIVE_PROFILE_QUERY_VERIFIED/CLEANED, zero novas runs/
  marcadores/vereditos, nove volumes sem consumidores. Pacotes/tentativas e
  autorização consumidos; Demo/histórico/PKI preservados, sem operação contínua.
  Ver docs/evidence/wazuh-schema-2026-11-17/README.md; não repetir os ensaios.

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
  #16 em18/11: #84/#85/#86 e aceite conjunto atendidos com conversor oficial em
  venv/processo separados; parser da API2.0.1 preservado. Perfil novo
  aegis-marker-lucene/1 gera query offline, sem validar índice/implantar regra.
  CI69ae1e4 SUCCESS; Demo ativo anterior preservado, sem operação SIEM/Lab.
  Ver docs/development/sigma-conversion-checkpoint.md. Entrega encerrada; parar.
- #17 em18/11: gates físicos#87 e consulta limitada#88 implementados/testados
  localmente,193testes pertinentes/lint e CIf8e20ee aprovados. Ensaio#89 e aceite nativo
  dependem de autorização específica, metadata/ACL reais e pacote novo.
  Ver docs/development/sigma-validation-checkpoint.md. Sem startup/consulta SIEM,
  implantação ou novo marcador; pai/filhos abertos, parar no bloqueio.
- ATT&CK: fonte oficial versionada, prepare/plan/apply controlados, sem atualização
  no startup; fonte ausente não significa revogação. Preservar releases/histórico.

Ao terminar: comentário na issue com comportamento entregue, arquivos relevantes,
testes realmente executados, falhas/limitações, commits/último hash/mensagem e
sincronização. Atualizar checkpoint curto quando necessário. Não fabricar /compact
(não há ferramenta para isso), métricas ou evidência. Não iniciar outra entrega.
