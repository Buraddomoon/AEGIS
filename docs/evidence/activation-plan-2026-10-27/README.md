# Planejamento da ativação Linux — evidência de 2026-10-27

Base8acbf3a. Entregue um harness host-only **plan/recheck**. Não foi executada
troca de certificados ativos, inspeção interna do banco/diário, start de serviços,
campanha, marcador ou chamada SIEM. Autorizações anteriores continuam consumidas.

## Software implementado e validação

- `scripts/runner_activation_metadata.py`: catálogo fechado de consultas
  info/ps/network ls/volume inspect/image inspect no daemon Unix local; config/env
  isolados, projeções sem segredos,10s/64KiB e kill/reap do filho CLI.
- `scripts/runner_activation.py`: PKI verificada antes/depois, perfil Linux exato,
  hashes Compose, quatro IDs locais, volumes existentes sem consumidores, artefato
  exclusivo0600/0700/fsync, hash canônico e rechecagem de política/TTL15min/drift.
- ADR0020, comandos Make e contrato operacional; nenhuma dependência/migração,
  mudança de API/UI/runtime ou credencial humana.

| Verificação executada | Resultado observado |
|---|---|
| Metadados + transporte CLI |48 casos passaram em0,74s após correção; na rodada conjunta incluídos nos82 |
| Plano/rechecagem/PKI temporária |34 casos passaram em38,93s na primeira rodada |
| `make test-runner-activation` final |82 passaram em45,90s |
| `make test-runner-pki` |52 passaram em28,90s, incluindo três handshakes echo loopback |
| `make lint` |Ruff/format149 arquivos, mypy4, TypeScript e Prettier aprovados |
| Coleta de testes final |969 casos Python coletados; não significa969 executados localmente neste marco |
| `make release-check` antes desta evidência |342 arquivos/89 Markdown/256 links/14 cabeçalhos PNG aprovados |

Nenhum caso usa runner de laboratório real: geração OpenSSL/arquivos em temporários,
filhos Python pequenos e TLS echo em loopback. PostgreSQL/Redis/worker de produção
não são usados por esses134 casos. Aviso Starlette/TestClient-httpx conhecido
permanece visível. E2E e frontend não foram repetidos neste incremento de ferramenta
host-only; a última validação do produto está no marco anterior. CI final é registrada
em PROGRESS depois da conclusão, sem presumir sucesso a partir de execução pendente.

Revisão especializada somente leitura não encontrou bloqueador concreto no escopo
plan/recheck; não executou Docker/OpenSSL/rede, não leu segredos e não foi pentest.

## Consulta real de metadados, sem laboratório iniciado

O primeiro plan real foi recusado com `docker_query_failed`: imagem PostgreSQL
oficial omitia Config.User e a projeção direta falhava. Nenhum artefato de plano
foi publicado nesse erro. Corrigido com `index` para o campo opcional e quatro
regressões: null/default root somente DB/cache; API/runner exigem UID10001:10001.
Diagnóstico CLI retido privadamente, nunca inspect bruto/Config.Env.

Depois da correção, a CLI real criou e revalidou o plano:

- ID `3f38362663b840009d3149cfd113c83b`.
- Hash canônico `f7324e0999595546fcdfb3b43e4617c8938eb035f5b6bf9981773716300abee6`.
- Recheck `2026-10-27T14:20:06.673617Z`, status
  `metadata_plan_revalidated_not_activated`.
- Expiração `2026-10-27T14:34:27.588950Z`: esta evidência histórica não prolonga
  validade nem autoriza uso posterior. Não editar/regenerar para contornar gate.
- Candidato PKI90204499ca2144aca175fe809538b7e7, manifesto
  `24179f34ad0a2c708496e9b0b3798a18d547c4648975c95893330458f0ed8d5f`,
  reverificado sem alteração/ativação. Validade curta continua exigindo nova revisão.

Imagens locais inspecionadas, sem pull/build/start:

| Papel | ID |
|---|---|
| application |`sha256:92ffbc4e1de7f47aa6f6e53636cf3a3d9e153cf869228e669f8263368bcaff7d`|
| runner |`sha256:75059996a84d4315eb06d65ffddc77d0b7fdb844e8dd72796b55ef2846607228`|
| postgres |`sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24`|
| redis |`sha256:3811787313eba226a2ef38658c6ccb91cd5e110edc89c37767de373120a0e5a0`|

Estes IDs não comprovam proveniência/código atual. A flag correspondente permanece
false; não reutilizar automaticamente como imagens aprovadas de um ensaio futuro.

Volumes `aegis-linux-lab_journal` e `aegis-linux-lab_postgres-data` confirmados com
labels Compose corretos, driver/scope local, sem opções externas/consumidores.
Datas observadas2026-10-21T09:39:53-03:00 e11:08:45-03:00, respectivamente.
Não foram montados/abertos nem comprovados conteúdo/journal/fences/identidade interna.
Zero containers Linux/Wazuh; nenhuma rede de laboratório foi criada ou modificada.

Artefato/recibo ficam em `.local/pki-activation-plans/ID/plan.json` e
`.local/pki-milestone/activation-metadata-receipt.json`, privados/ignorados por Git.
Hash não é assinatura/custódia independente nem garante ausência de alteração do host.

## Produto em uso e pendências

Demo localhost18780 manteve ready/database/redis true, mesma imagem API/worker
92ffbc4e…, sem deploy, seed/migração, campanhas ou mudanças de contas. Dados,
backups, chaves, imagens e volumes históricos preservados. O schema pytest antigo
registrado no marco anterior não foi excluído nem reinterpretado como fila ativa.

Falta o executor real com intenção/ownership/cleanup duráveis, inspeção autorizada
do banco/diário Linux originais, mounts/isolamento/mTLS reais, registro novo mantendo
lab revogado e encerramento verificável. Worker deve continuar parado durante os
gates. Plano não implementa nenhum desses efeitos nem permite marcador. Só depois
do executor concreto será possível apresentar escopo específico para autorização.

[Contrato e sequência](../../operations/runner-pki-activation.md) ·
[ADR0020](../../architecture/decisions/0020-runner-activation-plan.md) ·
[Progresso](../../PROGRESS.md).
