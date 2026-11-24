# Preparação parcial da recuperação dos labs — #9/#64

Data:24/11/2026. Fonte implementada:
[`5ead4907edb8237536fc5a2b36430384e919ffb5`](https://github.com/Buraddomoon/AEGIS/commit/5ead4907edb8237536fc5a2b36430384e919ffb5),
`feat(recovery): prepare consistent private lab snapshots (Refs #64, #9)`.
Partida sincronizada3c5b848. Somente main; nenhum PR/branch criado.

## Evidência local efetivamente executada

```sh
.venv/bin/pytest tests/test_lab_backup.py tests/test_runner_journal_continuity.py tests/test_runner_persisted_review.py tests/test_runner_journal_probe.py tests/test_runner_persisted_probe.py tests/test_backup_inventory.py -q --tb=short
make lint
git diff --cached --check
.venv/bin/python scripts/check_staged.py
.venv/bin/python scripts/check_release.py
```

- **238passed**,52,28s, sem skips; um aviso upstream Starlette/TestClient-httpx.
  Inclui42novos casos em `test_lab_backup.py`. As execuções anteriores de32 e236
  casos são sobrepostas; não somar.
- PostgreSQL17 real em schema exclusivo de testes; SQLite/WAL reais em diretórios
  temporários. Redis15 compartilhado usado em sequência. Não foram usados volumes
  PostgreSQL ou journals dos labs Linux/Wazuh.
- Exportador PostgreSQL permaneceu aberto durante importação do mesmo snapshot.
  A regressão concorrente remove uma prova CLEANED somente na fixture PG: o leitor
  que importa o snapshot continua vendo a prova antiga; o leitor fresco recusa o
  histórico agora incompleto. Outra regressão altera uma linha durante o dump e
  impede publicação do manifesto, preservando a cópia privada que falhou.
- Testes verificam origem do diário byte/mtime/ctime idêntica, cópia completa de
  DB/WAL/SHM/lock, WAL confirmado necessário à prova, drift de geração/identidade/
  ambiente/schema, autorização/reserva pendentes, cleanup ausente, cópia parcial,
  falha de publicação, links/permissões, hash/contexto e flags operacionais.
- Fences expirados/consumidos da fixture são copiados como bytes opacos, sem
  interpretar instruções ou liberar reservas. Não é prova de coleta completa de
  fences reais do host.
- O escritor de dump é **fixture sintética PGDMP**. Nenhum pg_dump/pg_restore real
  foi executado nesta sessão. Cabeçalho/hash do arquivo não prova restaurabilidade.
- `make lint`: Ruff, formato Python, mypy, TypeScript e Prettier aprovados.
  Staged/segredos/whitespace/release aprovados. Sem mudança de UI; build/E2E local
  não repetidos. A CI executa sua validação React/build própria.

Primeira sondagem:1passed SQLite e1erro de setup PG por autenticação da configuração
deste checkout. A credencial/configuração já existente do checkout de
desenvolvimento foi selecionada apenas no ambiente dos processos, sem imprimir
valores nem alterar arquivos/contas/grants. Repetição do caso PG:1passed.
Essa falha permanece registrada; não é falha de restore nem ensaio nativo.

## CI

[Execução45402749488](https://github.com/Buraddomoon/AEGIS/actions/runs/45402749488)
na fonte5ead490: **SUCCESS**, cinco jobs conferidos individualmente, logs finais
consultados após encerramento. Partições complementares, max-parallel2 e timeout
originais preservados; nenhuma exclusão de testes para obter green.

| Job | Passed | Skipped | Resultado |
| --- | ---: | ---: | --- |
| Python0 | 979 | 2 | SUCCESS |
| Python1 | 1011 | 2 | SUCCESS |
| Python2 | 1060 | 1 | SUCCESS |
| Python3 | 955 | 4 | SUCCESS |
| React | 154 em21arquivos | 0 | SUCCESS |

Total Python: **4005passed/9skips** existentes. Deselected de cada shard são os
arquivos das outras partições, não testes retirados do conjunto. Lint/tipos e
auditoria da partição0 e lint/formato/testes/build/auditoria React aprovados.
[Revisão de fonte45402749351](https://github.com/Buraddomoon/AEGIS/actions/runs/45402749351)
também SUCCESS. O commit posterior de provas é somente Markdown; não altera o
código Python/React validado nem representa implantação.

## Limites e bloqueios

#64 continua aberta: biblioteca de preparação não demonstra vínculo físico com
originais, quiescência externa, coleta completa de fences/configurações ou
restaurabilidade do dump. Ainda faltam o coordenador nativo/transportes limitados
e um pacote concreto de escopo para eventual autorização. Nenhuma flag desse
perfil permite editar um manifesto para transformar fixture em aceite operacional.

#65 ainda não foi implementada/aceita e depende da #64. #66 depende da #65 e de
autorização específica para dados/volumes definidos, ainda ausente. #9 não fecha
com essas pendências. Não se reutilizaram autorizações históricas consumidas.

Sem implantação, start/build de Lab, abertura de volume original, marcador,
migração, troca de PKI/binding, rede ou grants. Sem limpeza/exclusão de backups,
journals, intents, fences, candidatos ou imagens. Nenhum dado sensível/gerado do
pacote foi adicionado ao Git. Alterações alheias do outro checkout preservadas.

[Procedimento e perfil](../../operations/lab-backup.md),
[checkpoint curto](../../development/lab-backup-checkpoint.md).
Parar neste escopo após registrar testes/commits/sincronização nas issues.
