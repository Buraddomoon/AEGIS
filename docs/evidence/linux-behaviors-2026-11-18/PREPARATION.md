# Preparação #81/#82 e bloqueio #83 — 18/11/2026

Base `5e11944b304532aa966a6fd8c81434c3de9157f9`; especificação inicial
`07d7211` (`docs(linux): specify two bounded benign behavior profiles (Refs #81)`),
sincronizada em origin/main. Somente #15/#81/#82/#83, sem PROGRESS integral/chat.

## Implementação preparada

Dois perfis próprios, sem ampliar os bindings históricos:

| Definição | Identidade revisada |
| --- | --- |
| `linux-process-canary-v1` | `linux-process-canary/v1@5d16dd8867b4f8f06163311cfbdd1d754a03784c7c53212cb1709d29738b52e3` |
| `linux-shell-canary-v1` | `linux-shell-canary/v1@1baab18c75ad4a6ce8534962582fd61ae490eef1240ea8db9245af1c092438cb` |

Programa comum SHA256
`4e239181a4c9827da18f386dbee1527747959ff973d584ad48dfae27d78c9c13`.
Revisões em `apps/api/aegis/lab_runner/behavior_policy.py`; bytes verificados
antes de prepare/start/spawn e executados em memória. Um filho `/bin/true`
instrumental sem técnica ou `/bin/sh` com printf fixo/T1059.004 limitada.
Nova configuração inclui a revisão no hash do binding/escopo; nenhuma aprovação
antiga passa a autorizar esses perfis. Sem comandos livres na API.

Supervisor/Workspace/journal existentes preservados. Wrapper trata SIGTERM e
morte do pai, vincula o filho por PDEATHSIG e recolhe-o antes de sair. Recibo
tipado valida PID/exit/stdout e arquivo; cleanup recusa desconhecidos. API/worker,
histórico de cleanup, relatório e consulta de disponibilidade reconhecem cada
perfil. Seed acrescenta definições só se ausentes e não reescreve linhas antigas.
Nesta sessão foi chamado apenas pelas fixtures em schemas descartáveis.

## Verificações locais realmente executadas

Todas com `.venv/bin/pytest`, nesta fonte de trabalho antes do commit técnico:

- `tests/test_linux_behaviors.py -q`:57passed em1,69s. Execução real dos dois
  programas em temporários, consistência do catálogo/hash, drift e arquivos
  inseguros, cancelamento/timeout com filho, morte do pai com subreaper próprio,
  recibos incompatíveis, cleanup falho, reinício sem replay e falsos positivos.
- `tests/test_linux_campaigns.py tests/test_binding_review.py tests/test_domain.py -q`:
  135passed em158,38s. PostgreSQL real em schema descartável/Redis15, API/worker,
  dispatch antes da RPC, segregação/CSRF, revogação/drift, receipts distintos,
  resposta perdida em prepare/start/cleanup/commit, recovery concorrente,
  JSON/HTML e métricas por modo. Transporte HTTP de fixture, sem sensor defensivo.
- `tests/test_runner_protocol.py tests/test_runner_engine.py tests/test_runner_transport.py
  tests/test_runner_identity_server.py tests/test_runner_identity_probe.py
  tests/test_runner_tls_peer.py tests/test_runner_parent_death.py
  tests/test_runner_isolation.py tests/test_atomic_execution.py
  tests/test_linux_behaviors.py -q`:212passed em10,33s. Inclui TLS de loopback;
  não é mTLS nativo. Sobrepõe a rodada57; não somar como casos únicos adicionais.
- `make lint`:Ruff, formatação de355arquivos, mypy/domínio e TypeScript/Prettier
  aprovados. `make build`:SPA aprovada. Sem Docker build ou troca de imagem.

Aviso upstream de Starlette/TestClient-httpx preservado. Primeira rodada da nova
suíte falhou por contratos incompletos das fixtures e limite de espaço virtual
menor que a reserva do Python3.13 local. Corrigidos contratos e limite explícito
512MiB virtual (sem aumentar memória de container); identidades recalculadas antes
do primeiro commit técnico. Cache bytecode local stale após edições de mesmo
tamanho/segundo causou outra rodada inválida; somente esses caches gerados foram
removidos. Houve uma falha de autenticação PG do checkout, resolvida selecionando
a configuração de desenvolvimento existente apenas no ambiente do processo,
sem imprimir segredos, alterar arquivo/conta/grant. Um teste de revogação tentou
ler a API com a própria conta revogada; corrigido para conferir a rejeição no PG.
As rodadas finais acima passaram sem excluir testes ou relaxar gates.

## Limites e próximo gate

Não foi executada campanha nativa, inicializado Linux/Wazuh, aberto/migrado volume
Lab original, alterada rede/PKI/host ou implantada imagem. Demo e suas contas não
foram resetados. Eventos independentes são fixtures; nenhum recibo virou alerta.
Sem coletor/regra correspondente, as campanhas de fixture são
COMPLETED/INCONCLUSIVE/CLEANED; `synthetic=false` indica modo real do contrato,
não comprova laboratório nativo ou telemetria real. Nenhum suporte a sensor novo.

#83 bloqueada por falta de autorização específica de novo pacote operacional.
É necessário fixar imagens/fonte, IDs/lab/endpoint, revisões, janela, uma tentativa
por perfil, contas segregadas, disponibilidade/ausência de coleta e recuperação.
Não há autorização herdada de #5/#14 e não existe tentativa nativa desta entrega.
#15 fica aberta até #83 e aceite conjunto. Ver [checkpoint](../../development/linux-behaviors-checkpoint.md).

Primeira CI integral [44312253261](https://github.com/Buraddomoon/AEGIS/actions/runs/44312253261),
fonte `1831dcc9edbbeeba4f13100dd8dffc4d7e99aea2`: a partição1 falhou em dois
asserts de inventário anteriores à ampliação. `test_flow` esperava zero definições
Linux em T1059.004; agora deve apresentar o shell novo indisponível, mantendo zero
histórico Linux após Demo. `test_attack_publication` não incluía a definição nova
na revisão exigida quando T1059.004 sai do catálogo. Corrigidas expectativas
exatas, preservando os gates de disponibilidade, modo e catálogo. Sem mudança
de código runtime, filtros, exclusões ou parâmetros da CI.

A correção `9e614cb829cccaa70b21ff7a286418a5482fa771`
(`test(linux): account for reviewed shell profile in catalog regressions (Refs #82)`)
foi validada localmente com `tests/test_flow.py tests/test_attack_publication.py -q`:
24passed em21,34s, PostgreSQL/Redis de desenvolvimento e fixtures próprias.
Commit enviado a origin/main após staged/segredos/checks obrigatórios aprovados.
O push iniciou nova CI integral; pela política de concorrência existente, as
partições2/3 ainda em execução da rodada44312253261 foram canceladas. Conclusão
global dessa rodada: CANCELLED, com a falha da partição1 preservada; não é green.

CI final [44313563809](https://github.com/Buraddomoon/AEGIS/actions/runs/44313563809)
SUCCESS em `9e614cb829cccaa70b21ff7a286418a5482fa771`:3703Python/9skips opcionais
e98React. [Detalhamento por job](CI.md). Consolidação posterior apenas documental;
não houve mudança nos inputs executáveis/testes validados. Evidências públicas
contêm apenas metadados de fonte/testes, sem credenciais, dumps, logs ou artefatos
privados. #81/#82 atendidas; #83 permanece bloqueada e #15 aberta.
