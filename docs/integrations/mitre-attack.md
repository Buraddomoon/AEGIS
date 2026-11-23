# MITRE ATT&CK — catálogo e publicação revisada

A fonte é [attack-stix-data](https://github.com/mitre-attack/attack-stix-data),
Enterprise STIX2.1. Em2026-10-23, a [página oficial de versões](https://attack.mitre.org/resources/versions/)
indica Enterprise20.0. O snapshot distribuído em `fixtures/attack/enterprise.json`
contém706 técnicas/subtécnicas ativas e registra URL/SHA256 do bundle original,
mas não o commit da captura. A inicialização preserva essa limitação como
`provenance=bundled`; não atribui retroativamente um commit. Licença original em
`fixtures/attack/LICENSE.txt`. Dados de catálogo não são gerados por IA.

## Preparar, revisar e publicar

Use o checkout confiável e o ambiente de desenvolvimento documentado, com
migrações aplicadas e catálogo inicializado. A CLI host-only precisa da conexão
administrativa de implantação em DATABASE_URL; não exponha a senha em argumentos.
Runtime API/worker só consulta as três tabelas do catálogo. Não existe endpoint
de atualização, download no startup ou upload web de STIX.

### Revisão administrativa web (opt-in)

Após `prepare` e `plan` no host, a implantação pode definir `ATTACK_REVIEW_CACHE`
com o caminho absoluto do mesmo cache privado. Não há descoberta remota de
versões. Cache, seu pai imediato e `plans` devem pertencer ao UID da API e ter
modo0700; arquivos0600. Em contêiner, montar o pai/cache somente leitura para
esse mesmo UID, sem credenciais SQL de publicação. Não copiar o cache para a SPA
ou para Git. A conexão runtime e a CLI precisam usar host/porta/banco/schema
idênticos: o destino faz parte do hash. Não editar o plano para adaptar um
destino; gerar outro usando o destino legítimo. Configuração ausente significa
revisão desabilitada; cache ausente/alterado é erro explícito.

Somente administradores ativos consultam `/api/v1/catalog/attack/reviews` e
`/{plan_sha256}`. Inventário limitado a100entradas (inclusive arquivos extras),
paginação1–50; diff e impactos usam páginas independentes `offset`/`test_offset`
e `limit`1–50. Planos têm no máximo12MB e mantêm os limites do candidato.
Arquivos não regulares, symlinks, permissões abertas, hash divergente ou alteração
de candidato/destino/projeção/testes/bloqueadores recusam a revisão. A API refaz o
plano em transação `REPEATABLE READ, READ ONLY`, com prazos de10s por comando e
1s por lock;60consultas por administrador/minuto e respostas `no-store`.

Na matriz, administradores têm a ação **Revisar atualização ATT&CK**. A tela
mostra destino, origem/versão/licença/hashes, valores antes/depois paginados,
impactos e bloqueadores. Ausência de planos ou configuração é explícita.
Troca de plano, página, recarga ou erro descarta confirmação/instrução; respostas
atrasadas de outra consulta não podem restaurá-las. A confirmação do hash exige
revisão integral declarada pelo administrador e nova consulta ao backend.

`/{plan_sha256}/instruction` revalida novamente e fornece o comando host-only
com candidato/hash/ator exatos apenas se não houver bloqueadores e o artefato
ainda não estiver aplicado. Essa leitura não concede autorização nem modifica
catálogo, aprovações ou auditoria. A CLI continua exigindo credencial de
implantação e revalidação sob locks no instante do apply. Após publicação,
o plano antigo fica desatualizado; gerar outro para consultar `already_applied`.
Arquivar planos antigos no host quando o inventário atingir o limite, preservando
as provas necessárias. Não alterar arquivos para forçar uma confirmação.

```bash
# Fonte efetivamente verificada; revisar o plano antes de aplicar.
.venv/bin/python scripts/update_attack.py prepare --version 20.0 \
  --commit c2494b29dd268c46a5d0ea0990553e4327cd2253
.venv/bin/python scripts/update_attack.py plan ID_DO_CANDIDATO
# Inspecione integralmente o review_file privado: destino, mudanças e impactos.
.venv/bin/python scripts/update_attack.py apply ID_DO_CANDIDATO \
  --confirm-plan SHA256_DO_PLANO_REVISADO --actor UUID_DO_ADMINISTRADOR_ATIVO
```

`prepare` aceita versão numerada e commit completo em minúsculas, constrói somente
URLs HTTPS do repositório oficial e baixa bundle e licença desse mesmo commit.
TLS validado, sem redirects/proxies herdados, sem compressão, limites por arquivo
e prazo absoluto compartilhado de75s incluindo headers e corpo. Guarda os bytes,
licença, documento normalizado e manifesto em `.local/attack-catalog/<id>`,
diretórios0700/arquivos0600 exclusivos; não sobrescreve candidatos ou fixture.
O carregamento recalcula hashes e renormaliza a fonte. Hash não é assinatura:
a confiança também depende da origem HTTPS, commit revisado e checkout confiável.

O normalizador valida somente o perfil de catálogo Enterprise utilizado: coleção,
versão, membros/modificações, identidades oficiais, táticas, plataformas,
subtécnicas e flags. Não declara validação integral de STIX. As fixtures de
teste reduzidas são explicitamente sintéticas, nunca uma release oficial.

`plan` usa transação READ ONLY; o arquivo privado fixa host/porta/banco/schema,
release anterior, hashes da projeção/candidato, alterações de campos e testes
afetados. A aplicação exige o hash exato e um administrador ativo, refaz o plano
sob locks NOWAIT e publica projeção, release, ponteiro atual e auditoria na mesma
transação. O UUID atribui a ação; não substitui a credencial administrativa SQL.

Bloqueadores: licença diferente da revisada, downgrade, reescrita de versão
oficial já registrada, conflito STIX/ATT&CK, drift do catálogo, ator inválido,
plano desatualizado, concorrência, runs pendentes, reservas ou agendamentos
PENDING_APPROVAL/ACTIVE/PAUSED. Resolva a pendência legítima e gere outro plano;
não altere evidências ou autorizações para forçar aplicação. Mudança de licença
exige revisão no repositório. Repetição do mesmo conteúdo retorna
`already_applied`, sem nova release/auditoria. Erro não anuncia sucesso.

## Ciclo de vida, escopos e cobertura

- Ativa: presente e sem flags oficiais de retirada.
- Revogada/descontinuada: flags oficiais, sem inferir equivalência por nome.
- Fora da versão atual: ausente no novo conjunto, com metadados anteriores
  preservados. Ausência não é revogação inferida.

IDs referenciados nunca são apagados. Publicação não altera allowlist de testes,
regras, campanhas, scopes, aprovações, evidências ou relatórios JSON existentes.
O seed reconhece somente a projeção legada conhecida e não sobrescreve uma
release inicializada; divergência exige revisão manual.

Novos scopes capturam release/version/proveniência/hashes e metadados das técnicas
selecionadas. Retiradas/ausentes não entram em novo escopo. Worker recusa contexto
ausente/desatualizado antes de preparar/emitir efeitos, mantendo cleanup obrigatório.
Runs históricas sem campos de catálogo mostram versão desconhecida; não recebem
metadados atuais retroativamente. Relatório HTML identifica essa condição.

A matriz e a contagem de técnicas avaliadas exigem a mesma release atual e modo.
Após publicação, essa cobertura começa sem avaliação até novos testes aprovados.
Contagens históricas, resultados, tendência e percentual sobre testes válidos
continuam históricos, com denominador explícito em todas as releases. Comparar
scopes de releases diferentes mostra mudança de configuração e não equivalência
nem causalidade de uma melhoria. Catalogação não demonstra observação/detecção.

## Interface e API

Matriz/tabela têm filtros de ciclo de vida, modo, tática, plataforma e cobertura;
exibem versão, origem, hashes e histórico de releases com pesquisa de snapshots.
Paginação da matriz e detalhe fixam a release; troca concorrente exige recarga.
Referências fora da release atual não recebem cobertura como se fossem ativas.

Sessão de qualquer papel consulta `/api/v1/catalog/attack`, `/releases` e
`/releases/{id}/techniques`. Técnicas aceitam `lifecycle` e
`catalog_release_id` esperado; 409 informa troca de release. Não há botão de
publicação decorativo: a revisão administrativa inspeciona planos preparados,
enquanto preparação/aplicação permanecem operações administrativas locais.
[API](../api/overview.md), [ADR0014](../architecture/decisions/0014-controlled-attack-catalog.md).

Mapeamentos Demo: shell Unix→T1059.004, PowerShell→T1059.001,
enumeração de processos→T1057, todos representados sinteticamente.
Marcador genérico Linux/Demo permanece sem ATT&CK. Fonte atual contém867
referências (706ativas/149revogadas/12descontinuadas); os161 registros retirados
adicionais não aumentam o denominador de técnicas ativas.

## Relações e referências de telemetria — #20

O perfil `aegis-enterprise-catalog/2` mantém a projeção das técnicas e acrescenta
um grafo de referência no documento imutável da release. Preserva IDs STIX/ATT&CK,
modificações, flags e relações `subtechnique-of`/`detects`. Estratégias apontam
para analíticas e estas para componentes e nomes/canais de logs. Referências
legadas diretas de componente e fonte também são preservadas quando existem.
Não há herança de telemetria/cobertura entre pai e subtécnica. Na fonte20.0 fixada
em `c2494b29dd268c46a5d0ea0990553e4327cd2253`, há2622objetos de contexto e1184
relações desse subconjunto; não existem `x_mitre_data_sources` nas técnicas.
Fontes antigas descontinuadas não são apresentadas como sensores ativos.
Modelo consultado: [documentação oficial MITRE](https://mitre-attack.github.io/attack-data-model/).

O perfil `/1` continua legível e com identidade idêntica: ausência de contexto é
`legacy_unavailable`, nunca uma lista inventada. `/2` sem relação de telemetria
é `not_provided`; ID ausente da release atual é `technique_absent`. Pai/filhos
legados podem navegar pelos IDs já preservados, com proveniência da relação
explicitamente indisponível. O detalhe fixa `catalog_release_id`; publicação
concorrente retorna409 e exige recarga. Nenhuma consulta baixa STIX ou toca labs.

Um candidato oficial `/1` existente pode ser enriquecido **offline**, sem
sobrescrever arquivos nem publicar automaticamente:

```sh
.venv/bin/python scripts/update_attack.py enrich ID_DO_CANDIDATO_EXISTENTE
.venv/bin/python scripts/update_attack.py plan NOVO_ID_DO_CANDIDATO
# Revisar destino, hashes, impactos e a nova identidade antes de eventual apply.
```

O enriquecimento revalida manifesto/bytes/permissões e normalização do perfil
anterior antes de criar o candidato `/2`. Publicar exige o fluxo host-only já
documentado. Uma extensão `/1`→`/2` da mesma versão só passa se fonte, commit,
licença e técnicas forem idênticos; gera outra release e preserva o documento
anterior. Reescrita de contexto `/2` e retorno ao perfil antigo são bloqueados.
Uma nova identidade de release separa a cobertura atual do histórico, mesmo com
as mesmas técnicas. Preparação nova usa `/2`; nada muda no seed ou no startup.
Migração explícita `e2a71c9d064b` acrescenta o perfil à unicidade da release e
confere sua igualdade com o documento. IDs/documentos antigos não mudam; downgrade
recusa perder releases `/2`. Exige código/imagem e schema compatíveis; backups
antigos continuam requerendo sua versão de origem. Não migrar Demo/Labs originais
para testar esta entrega, nem implantar automaticamente.

`GET /api/v1/techniques/{id}` acrescenta `catalog_context` com catálogo/perfil,
pai/filhos e caminhos oficiais, além de `observed_telemetry` (até30avaliações do
modo escolhido). Esta última resume somente `telemetry_events` persistidos por
execução/fonte/tipo/synthetic, com release histórica e flags da avaliação. Um
teste disponível, recibo ou vínculo Sigma não produz fonte observada. Eventos
registrados não comprovam conexão atual, correlação ou detecção; acessar as
provas da execução. Zero eventos não prova ausência de telemetria. As listas não
alteram veredictos, cobertura, evidências ou relatórios históricos.
