# ADR 0035 — Compatibilidade publicada dos backends Sigma

Data: 2026-11-18. Status: pesquisa #84 concluída; conversão #85 e UI #86 bloqueadas.

Retomada posterior em18/11: a exigência de aguardar publicação foi substituída
pelo [ADR0036](0036-isolated-sigma-converter.md), que isola um conjunto oficial
compatível sem reduzir o parser da aplicação. O diagnóstico abaixo é preservado.

## Contexto

A entrega #16 exige um backend oficial compatível e um pipeline fechado para
gerar consultas offline. Os ADRs [0009](0009-sigma-conversion-readiness.md) e
[0017](0017-sigma-mapping-preview.md) preservam pySigma2.0.1 e proíbem resolver
o conflito por downgrade, instalação ignorando dependências ou backend próprio.
O perfil existente tem como alvo OpenSearch Lucene; mapear campos não verifica
o índice nem demonstra conversão.

Reconsultamos os catálogos oficiais PyPI, wheels e seus METADATA/LICENSE, além
dos pyprojects upstream fixados por commit. A
[matriz e as verificações](../../evidence/sigma-compatibility-2026-11-18/README.md)
registram hashes, fontes, comandos e limites. O inventário de10/11 e o snapshot
de22/10 continuam sendo históricos, não consultas atuais.

## Decisão

Manter o runtime e os locks atuais. OpenSearch2.0.3 exige core>=1,<2 e
Elasticsearch2.1.1 exige core>=1.4,<2 nos wheels efetivamente publicados.
O pip26.2.2 recusa tanto o core atual2.0.1 quanto o novo2.1.0 com esse par.
Uma atualização controlada para2.1.0, portanto, não libera a conversão pretendida.

O controle com core1.5.1 resolve18wheels e passa a conferência dos hashes de um
lock temporário, mas representa downgrade proibido, não uma solução aprovada.
Nenhuma dessas distribuições de backend foi instalada ou importada. A troca
de DiskCache por diskcache-community no core2.1.0 também não constitui revisão
de segurança ou autorização para atualizar a aplicação.

O main do Elasticsearch já declara core^2.1.0 em um pyproject, enquanto o wheel
2.1.1 ainda declara<2. Essa divergência não torna o wheel compatível. Não usar
checkout Git, sdist, dependência editável, patch de METADATA ou cópia de backend
para apresentar a incompatibilidade publicada como resolvida. O main do
OpenSearch continua declarando core<2.

## Consequências e retomada

- #84 entrega uma conclusão negativa verificável e pode encerrar a pesquisa.
  #85 permanece bloqueada pela combinação publicada; #86 depende de#85.
  A entrega#16 permanece aberta, sem aceite conjunto.
- `can_convert=false` e nenhum endpoint, botão ou download de consulta é
  acrescentado. A prévia de rename continua sendo uma operação independente.
  O snapshot de metadados22/10 e o perfil/hash existentes não são reescritos.
- Retomar#85 exige reavaliar distribuições oficiais efetivamente publicadas,
  resolver pins/locks sem conflitos e revisar imports/licenças/segurança antes
  de integrar um backend. A publicação futura é condição externa, sem data.
  Mesmo depois disso, pipeline versionado, limites, modificadores/fieldref,
  golden queries, RBAC/API e procedência/UI ainda precisam ser implementados.
- A geração offline não autoriza consultar SIEM, verificar mapping nativo,
  implantar regra ou iniciar laboratório. Nenhum desses efeitos foi executado.

Esta decisão se limita ao alvo OpenSearch e ao par oficial revisado; não afirma
que todos os backends Sigma de outros produtos sejam incompatíveis.
