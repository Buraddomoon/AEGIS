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
publicação decorativo: preparação/aplicação permanecem operações administrativas
locais. [API](../api/overview.md), [ADR0014](../architecture/decisions/0014-controlled-attack-catalog.md).

Mapeamentos Demo: shell Unix→T1059.004, PowerShell→T1059.001,
enumeração de processos→T1057, todos representados sinteticamente.
Marcador genérico Linux/Demo permanece sem ATT&CK. Fonte atual contém867
referências (706ativas/149revogadas/12descontinuadas); os161 registros retirados
adicionais não aumentam o denominador de técnicas ativas.
