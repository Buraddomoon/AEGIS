# Continuidade do diário e ownership — evidência local 2026-10-27

Dois componentes preparados para o executor futuro. Não foi executada ativação,
troca de mounts, nova campanha/marcador, inicialização Linux/Wazuh, consulta SIEM
ou inspeção interna dos volumes reais. Autorização antiga permanece consumida.
Não houve deploy/restart/migração/seed, contas temporárias ou alteração de senhas.

## Implementação verificada

- [continuity.py](../../../apps/api/aegis/lab_runner/continuity.py): lock preexistente,
  arquivos restritos, DB+WAL copiados para scratch e SHM reconstruído ali; schema,
  integridade, identidade, gerações, specs, recibos e todos os eventos/jobs. Provas
  CLEANED conhecidas precisam coincidir; standalone adicional é preservado.
- [persisted_review.py](../../../apps/api/aegis/lab_runner/persisted_review.py):
  snapshot PostgreSQL próprio READ ONLY/REPEATABLE READ15s, binding antigo exato,
  predicado ADR0019 e bundle completo por hash. Atesta linhas coerentes, sem
  inferir vínculo físico do engine com o volume Linux.
- [journal_probe.py](../../../apps/api/aegis/lab_runner/journal_probe.py): /state
  fixo, stdin até4MiB/hash independente e saída só resumo. Import sem settings,
  modelos SQL, servidor/engine, rede/processos ou leitura de segredos.
- [runner_activation_intents.py](../../../scripts/runner_activation_intents.py):
  ownership/nome/labels de catálogo fechado, eventos exclusivos0600/0700, encadeados
  por hash/fsync, lock cooperativo e retomada explícita por ID/hash. Sem daemon,
  executor, autorização ou exclusão de recursos/arquivos/volumes.

[ADR0021](../../architecture/decisions/0021-runner-journal-continuity.md) ·
[ADR0022](../../architecture/decisions/0022-activation-resource-intents.md) ·
[Contrato e limites](../../operations/runner-pki-activation.md).

## Testes efetivamente executados

`make test-runner-continuity`: **104 passaram/9,60s**, sendo65 SQLite/writer,
30 PostgreSQL/bundle e9 probe. Schema PG descartável e SQLite real em temporários.
A tentativa DML de regressão foi rejeitada pelo PostgreSQL read-only com25006.
Comprovantes persistidos foram combinados a um diário temporário pelo contrato
completo, sem RPC de runner ou SIEM.

WAL confirmado fora do DB, WAL parcial/corrompido, SHM ausente, layout após
checkpoint, falhas de cleanup/time budget, arquivos/links/locks e histórico inválido
foram exercitados. O caso de restart usa writer real em temporários: prepare e
intent RUNNING manual, **nunca start/supervise**, depois restart/cleanup falho/retry.
Nenhum processo de marcador foi iniciado nesse caso.

`pytest -q`: **1.073 passaram/364,68s**, antes da adição dos casos de ownership.
Quatro projeções opcionais Docker da suíte existente consultaram somente objetos
Demo já presentes; nenhum objeto de laboratório foi criado por esses testes.
Demais ensaios usam seus schemas/fixtures/temporários conforme o contrato existente.

Após ownership final, `make test-runner-activation`: **134 passaram/33,70s**,
sendo82 plan/metadados existentes e52 novos de intents. Os52 incluem crash,
publicação incerta/retomada, ownership, locks, histórico parcial/unsafe, recursos
proibidos, limites, import isolado e dependências antes/depois de resume. Assim,
**1.125 casos Python distintos foram executados localmente**, em rodadas distintas;
não somar reruns como testes novos. Coleta final confirmou1.125; coleta sozinha não
foi usada como prova de aprovação.

Lint completo aprovado: Ruff/format157 arquivos, mypy4, TypeScript e Prettier.
Aviso upstream conhecido Starlette/TestClient-httpx permanece visível. Frontend/
build/E2E não foram repetidos localmente: não houve mudança de fluxo UI/runtime;
CI executa os checks de frontend/build. Resultado remoto final no PROGRESS.

## Problemas identificados e corrigidos

1. Revisão estática encontrou restart implícito seguido de falha/retry de cleanup
   que o leitor recusava. Interpretação corrigida usando desfecho persistido
   INTERRUPTED; regressão com writer real, preservando o evento ausente legado.
2. Teste em processo novo encontrou import indireto de settings pelo decoder.
   Imports SQL/modelos movidos para collect; probe/decoder agora importam isolados.
3. Revisão do ownership encontrou criação de dependente após intenção de remover
   sua dependência. Bloqueio aplicado durante/depois da remoção e após resume;
   ausência também revalida dependentes. Testes diretos/retomados aprovados.

Revisão especializada somente leitura confirmou os ajustes, sem bloqueadores
adicionais concretos no escopo. Não é pentest nem validação de isolamento real.

## Estado preservado e pendências

Demo localhost18780 ready/database/redis true em consulta posterior aos testes;
nenhum redeploy ou credencial alterada. Material PKI, candidatos/planos antigos,
journals/volumes, backups, imagens e evidências históricas foram preservados.
O plano3f3836… de27/10 já tem validade histórica expirada; não foi renovado/reusado.
Validade da PKI candidata não é inferida de prova anterior e deve ser reverificada.

Falta integrar componentes a lifecycle fixo com queries de ownership/mounts/rede,
verificar proveniência das imagens e volumes/banco/journal Linux originais, provar
mTLS novo sem marcador, registrar binding ainda revogado e encerrar recursos com
prova de ausência. Só depois submeter escopo concreto para nova autorização.
Hash de bundle/escopo/observação não autentica origem nem concede essa permissão.
Custódia externa segue adiada; nenhuma cópia/upload/serviço pago foi contratado.

## Continuação automática — observador de ownership

Código fc5da3d: [runner_activation_ownership.py](../../../scripts/runner_activation_ownership.py)
e50 novos casos em test_runner_activation_ownership.py. Consulta por nome, owner
composto e ID anterior, inspect de nome/ID/cinco labels exatos e repetição das
listas. Labels repetidas não são usadas como um AND presumido; nomes parecidos
bloqueiam conservadoramente. Erro, colisão/rename/duplicata/drift nunca vira
ausência nem autoriza limpeza. Executa somente consultas do catálogo projetado.

`make test-runner-activation` final: **184 passaram/34,37s** (82 existentes,
52 intents e50 ownership). Com a rodada global anterior, **1.175 casos Python
distintos foram executados localmente em rodadas distintas**; coleta final também
confirmou1.175. Lint repetido aprovado com159 arquivos Python, mypy/TypeScript/
Prettier. A suíte global não foi repetida localmente após as bibliotecas host-only;
os novos casos foram executados e CI final valida a composição completa.

Consulta real somente leitura passou para os **nove papéis** com nonce novo
`b46cbcbd00404c87a942062db5f8386d`, em2026-10-27T17:00:17.687401Z;
nenhum desses nomes representa recurso criado.
SHA canônico do recibo:
`bb5ca450e5603b996d2714c158714bc4a8d2743cce71b167fc90d5bb4c2dd6eb`.
Arquivo privado `.local/pki-milestone/ownership-absence-receipt.json`.
As consultas confirmaram ausência somente dos nomes/labels desse catálogo/nonce;
não provaram isolamento geral ou inexistência de todos os recursos do host.
Nenhum intent real/container/rede foi criado, nenhum volume aberto ou serviço
alterado. Templates de inspect para **objetos presentes** continuam validados por
fixtures, sem prova em objetos reais de ativação. Todas as flags operacionais falsas.

Revisão especializada estática não encontrou bloqueador concreto no novo
observador; não substitui ensaio. Próximo continua sendo integrar lifecycle fixo,
mounts/isolamento/mTLS/registro revogado e fechamento antes de pedir autorização
específica. A consulta de ausência não autoriza create/start/stop/rm ou marcador.

CI finalfc5da3d aprovado:
[run40546471235](https://github.com/Buraddomoon/AEGIS/actions/runs/40546471235),
**1.171 Python passaram/quatro opcionais Demo pulados/320,97s**,79 React/12 arquivos,
lint/tipos/build e advisory review. DiskCache5.6.3/PYSEC-2026-2447 conhecido permanece
explicitamente revisado; não é uma alegação de zero vulnerabilidades. Source-review
final356 arquivos/93 Markdown/278 links/14 cabeçalhos PNG, sem substituir testes
ou comprovar ausência de segredos. Estado Git/checkpoint no PROGRESS.
