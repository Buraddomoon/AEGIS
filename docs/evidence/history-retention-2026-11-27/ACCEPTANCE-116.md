# Aceite integrado de #116 e #27 — 27/11/2026

A retomada solicitada pelo usuário foi limitada à conclusão das subissues da #27.
#114 e #115 já estavam encerradas. A #116 foi conferida no GitHub, com dependência
#115 atendida e proibição explícita de aplicação no ambiente humano nesta sessão.
AGENTS, guia de sessão e arquivos de entrada foram reconferidos; PROGRESS inteiro
não foi carregado. Nenhuma autorização histórica de laboratório foi reutilizada.

## Correção do bloqueio do primeiro handoff

O [registro anterior](README.md) preserva o estado e as provas em bb855da. Ele
manteve #116/#27 abertas por exigir uma decisão de expurgo do banco ativo. Essa
interpretação ampliava o critério da subissue: o artefato solicitado é host-only,
com hash/escopo/validade/locks, backup protegido, auditabilidade, dry-run e ensaio
em banco/arquivos descartáveis; uso humano está expressamente fora do ensaio.

A unidade da política já implementada e aceita na #114 é **snapshot completo**.
A retenção atua nas cópias próprias em claro, após arquivamento cifrado e restore
verificado; preserva o conjunto relacional e não exige bypass de append-only.
A correção de interpretação não amplia os alvos da implementação nem autoriza
exclusão humana. Não são alegadas redução das tabelas ativas, exclusão de arquivos
cifrados ou custódia off-host. Esses limites permanecem explícitos na
[política de operação](../../operations/history-retention.md).

O que faltava demonstrar na #116 era a aplicação integrada com restore verdadeiro
e schema completo. A evidência abaixo complementa os testes anteriores de
aplicação com callback de fixture e o roundtrip relacional reduzido da #115.

## Ensaio integrado realmente executado

Comando:

```sh
.venv/bin/pytest tests/native_retention_apply.py -q -s --tb=short
```

Resultado: **1 passed**, um aviso upstream Starlette/httpx, em 101,18 s. O target
reproduzível `make test-retention-native-apply` executa esse mesmo arquivo; não foi
usado como substituto de resultado nem incluído no startup/CI padrão.

- PostgreSQL17 local, fonte e clones **novos**, sem rede, portas ou mounts de
  dados persistentes, somente tmpfs. Nenhuma conexão ao Demo/PG/Redis/Labs humanos.
- Todo o Alembic atual foi aplicado somente na fonte descartável: schema completo
  **f3b28c5d901a, 36 tabelas incluindo Alembic**. A fixture sintética contém 34 linhas
  na última captura; não é cópia de dados humanos nem pretende preencher cada
  tabela com dados de produção.
- Relações não vazias: duas runs e relatórios congelados BASELINE/COMPARISON,
  aprovação/autorização/ocorrência, evento/evidência/resultado, recibo/cleanup,
  versão de regra e auditoria. Flags synthetic, versões, documentos/hashes e
  referências são preservados nos dumps. Não há reivindicação de detecção real.
- Nove snapshots **distintos** são capturados acrescentando auditoria de fixture,
  sem atualizar históricos. Timestamps antigos nos manifestos são explicitamente
  metadados sintéticos de idade, não evidência de backups humanos antigos.
- CLI real de cadastro, arquivo e verificação em todos os nove snapshots; restore
  fixo do coordenador existente, sem substituir transporte, SQL ou callback de
  restauração. Cada verificação conferiu 36 tabelas e remoção do clone.
- Dry-run retornou uma candidata sem excluir; mudança de hold após revisão foi
  recusada antes de intenção/exclusão. Nova revisão foi feita para a aplicação.
- Aprovação **somente de fixture**, com ator identificado como não humano,
  hash/área/validade e confirmação. Uma restauração fresca e cleanup foram
  confirmados antes da primeira remoção da cópia elegível.
- Resultado `applied`: **uma cópia em claro removida; oito preservadas**, incluindo
  sete pelo mínimo e uma adicional sob legal hold. Redução medida:
  **119783 bytes lógicos de arquivos**. A diferença coincide exatamente com
  `candidate_bytes` do plano; não é medição de blocos físicos ou capacidade livre
  do filesystem, nem benchmark/RPO/RTO.
- Todos os membros dos arquivos protegidos ficaram byte a byte iguais durante o
  apply, bem como todas as fontes originais das fixtures. Inventário de dados e
  estrutura da fonte PostgreSQL idêntico antes/depois, incluindo guards/triggers.
- Repetição da aplicação recusada, recibo de sucesso preservado. Em seguida,
  **o snapshot cuja cópia foi removida foi restaurado novamente só pelo arquivo
  cifrado**: schema completo conferido, clone removido, sem fallback em claro.
  Essa nova verificação acrescenta seu próprio recibo; não reescreve os antigos.
- Staging vazio, fonte e clones nativos próprios removidos por ownership; após a
  rodada, `docker ps -a --filter name=aegis-recovery-` não retornou contêineres.

Resumo emitido pelo ensaio:

```json
{
  "status": "FULL_SCHEMA_RETENTION_VERIFIED",
  "synthetic": true,
  "tables": 36,
  "migration": ["f3b28c5d901a"],
  "snapshots_verified": 9,
  "plaintext_copies_removed": 1,
  "plaintext_copies_remaining": 8,
  "legal_hold_preserved": true,
  "removed_bytes": 119783,
  "source_database_identical": true,
  "protected_archives_identical": true,
  "restore_after_removal_verified": true,
  "rows": 34
}
```

## Contratos e diferenças de código

`make test-retention`: **49 passed**, um aviso upstream, em 4,18 s. Inclui a nova
recusa de aprovação consumida mesmo se cópias idênticas forem recriadas e todo o
inventário voltar exatamente ao anterior. O recibo original permanece idêntico;
a intenção de uso único não é apagada para liberar replay.

`make lint`: Ruff/formato/mypy/TypeScript/Prettier completos aprovados. Revisão
staged/segredos, whitespace e release-check executados antes dos commits. Não
houve nova dependência, migração de produto, filtro/skip/timeout ou alteração de
triggers/grants. O runtime em `apps/api` e `scripts` permanece byte a byte igual
à fonte já validada em 46a03b1. Nesta retomada mudam testes, Makefile e documentação.

Fonte do complemento: **fdd8a59e8414ddda17f7e2c69ae5a9a359ef773f** —
`test(retention): verify complete-schema CLI apply and recovery (Refs #116)`.
A prova PostgreSQL nativa é explícita e local; não é executada automaticamente
pela CI e não pode ser inferida de um workflow verde.

## CI e sincronização da fonte

[CI46058984159](https://github.com/Buraddomoon/AEGIS/actions/runs/46058984159)
**SUCCESS na primeira tentativa**, fonte fdd8a59. Cinco jobs finais conferidos:
quatro partições Python e React. União sem somar rodadas sobrepostas:
**4304 Python passed/9 skips existentes**, mais **186 React/24 arquivos**.

| Partição | Passed | Skips |
| --- | ---: | ---: |
|0|1016|2|
|1|1096|2|
|2|1081|1|
|3|1111|4|

Lint/tipos/formato, build e auditorias do workflow aprovados. Nenhum filtro,
exclusão, skip, concorrência ou timeout foi alterado. O teste PostgreSQL nativo
continua explícito/local; SUCCESS de CI não é apresentado como esse ensaio.
A primeira CI da etapa anterior e sua falha Sigma permanecem no registro inicial;
esta CI do complemento terminou na primeira tentativa, sem alterar Sigma.

Somente main, commits Conventional Commits e push direto, sem branch/PR/force.
O commit de fechamento documental e seu hash/mensagem/sincronização são
registrados nos comentários finais de #116/#27; ele só altera Markdown, sem
mudar os inputs executáveis/testes validados na fonte fdd8a59.

## Aceite e limites operacionais

#116 atende o artefato e os testes definidos com as provas acima; #114/#115
permanecem aceitas. O aceite conjunto da #27 cobre a política de snapshots
completos, arquivo recuperável e aplicação em cópias próprias revisadas. Não há
pendência que exija executar exclusão humana para aceitar esses critérios.
O primeiro handoff fica preservado como histórico, com esta correção explícita.

Nenhuma implantação, build/tag de imagem da aplicação, migração de original,
marcador, replay de autorização humana, operação Linux/Wazuh/SIEM, alteração de
qasrc/PKI/volumes/journals/fences ou upload. Backups/chaves humanos não foram
removidos. Nenhum pacote de exclusão no ambiente humano foi preparado/aprovado.
Uma operação futura continua exigindo revisão e autorização específica por
escopo/hash/validade; o pedido para concluir subissues não concede essa permissão.
Parar na entrega #27 após registrar o resultado da CI e a sincronização.
