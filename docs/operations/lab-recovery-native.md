# Cópia fria e restore histórico em quarentena — #64/#65/#66

Ferramentas do host, sem endpoint web. `prepare` consulta metadados e estatísticas
de arquivos; não abre volumes nem lê o conteúdo das chaves/configurações privadas.
`run` exige plano/hash conferidos e autorização humana específica; a confirmação
da CLI é uma afirmação do operador, não autenticação independente dessa aprovação.

Variáveis ambientais `PG*` são recusadas antes da execução; conexões do host usam
socket explícito e passfile vazio próprio, sem serviço/credencial libpq herdados.

## Escopo fechado

Somente os quatro volumes históricos:

- `aegis-linux-lab_postgres-data` e `aegis-linux-lab_journal`;
- `aegis-wazuh-lab_postgres-data` e `aegis-wazuh-lab_journal`.

Origens PostgreSQL17, schema **b7f3c2d91a06/33tabelas**, perfil de marcador
`linux-file-marker/v1`. Revogação/ociosidade e comprovantes CLEANED completos são
obrigatórios. Não atualizar schema, limpar fence, corrigir aprovação ou reescrever
scope/recibo antigo para passar. Perfis Atomic/processo/shell e dados do
Indexer/Manager/Redis estão fora desta recuperação; seus recursos são preservados.
Não é um backup/restore integral do produto Wazuh.

As imagens de referência da aplicação/runner/Redis são inventariadas por IDs
locais retidos, sem execução ou mudança de tag. Somente a imagem PostgreSQL17
fixada é executada, com entrypoints fechados de tar/pg_controldata/initdb/postgres.
O `source_commit` do novo contexto identifica o coordenador que capturou os dados;
não afirma que a imagem histórica da aplicação foi construída desse commit.

A custódia privada inclui todos os JSON/JSONL, locks, PKI e arquivos de configuração
do perfil sob `.local/linux-*`, `wazuh-*`, `pki-*`, `runner-*` e
`sigma-validation*`, no checkout principal e no legado `~/codes/aegis` quando
presente. Inclui os `.env` desses checkouts e os Compose públicos declarados.
Chaves privadas/senhas permanecem **somente no host**, em arquivos0600/diretórios0700;
não aparecem no contexto público, stdout, Git, CI ou issues. Logs, wheels e projetos
alheios não são incluídos. Links são registros inertes, nunca seguidos/recriados.
Expirados/consumidos são preservados, sem executar ou liberar nenhum deles.

Custódia nova usa `aegis-lab-host-custody/2`: um `records.tar` privado com nomes
planos SHA256 dos paths, mais `inventory.json` publicado por último. Há hash e
tamanho do pack inteiro, hash por arquivo e metadados originais. O pack é
sincronizado antes do manifesto; evita milhares de fsyncs individuais. A inspeção
streaming não extrai arquivos, rejeita membros desconhecidos/duplicados, links,
PAX/sparse e tamanhos inconsistentes. A verificação do formato `/1` anterior
permanece disponível; tentativas/manifestos antigos não são convertidos.

## Execução e isolamento

1. Plano de24h, hash independente, código Python/locks, daemon, imagens, identidade
   dos volumes e inventário de arquivos fixados. Consumidor externo, inclusive
   parado, ou container dos projetos originais bloqueia. Rechecks antes dos efeitos.
2. Lock exclusivo e pedido durável de uso único antes da primeira leitura. Plano
   consumido nunca é repetido; tentativa com cleanup desconhecido bloqueia outra.
3. Helpers novos leem originais **RO/nocopy**, sem iniciar PostgreSQL nesses volumes.
   Só tar é executado sobre eles, UID70 ou10001. O volume declarado na imagem é
   sombreado para impedir criação involuntária de volumes anônimos.
4. Extração manual em scratch novo do operador: sem links, caminhos de escape,
   especiais, duplicatas ou arquivos sparse/PAX. Origem precisa estar parada,
   `PG_VERSION=17`, sem PID, e pg_controldata precisa confirmar `shut down`.
5. PostgreSQL inicia exclusivamente sobre a **cópia**, com configuração/HBA próprios,
   preloads/archiving/SSL desabilitados. Configurações copiadas ficam no arquivo frio;
   não são executadas como instruções. Socket Unix privado, sem TCP/portas ou rede.
6. Provas e diário são correlacionados, PKI pública precisa estar na custódia;
   snapshot READ ONLY/RR e pg_dump compartilham o mesmo ID. Não há Journal/Runner
   inicializado na origem nem reparo do WAL.
7. A cópia fonte é encerrada. Um cluster **novo**, initdb próprio e banco vazio
   recebem pg_restore em transação única, exit-on-error, sem owner/ACL antigos.
   UTF8/libc/locale e collation-version são preservados e conferidos. Outros
   providers são recusados. Search_path de verificação coincide com o schema.
8. Inventário completo e arquivos do snapshot/custódia são reconferidos. Nova
   leitura RO dos volumes precisa produzir os mesmos arquivos tar byte a byte.
9. Stop SIGTERM5s e rm dos próprios containers, sem force/volumes; IDs/labels/imagem/
   receita/mounts/limites precisam coincidir. Scratch só é removido após ausência
   dos recursos próprios confirmada. Depois são publicados os recibos verificados.

Até16containers sequenciais nos dois perfis, **no máximo um simultâneo**; CPU0,25,
até384MiB,64PIDs, rootfsRO, sem capabilities, no-new-privileges, sem restart/log
driver. Entradas/saídas privadas limitadas, stderr até64KiB, dump128MiB e arquivo
frio512MiB, kill/reap/deadline no transporte. Prazo900s para novos efeitos, cleanup
continua permitido depois. Preflight mínimo4GiB de RAM disponível e4GiB de disco;
não reduzir gates ou parar terceiros para passar. São limites do perfil pequeno,
não promessa de escala ou medição de consumo do host inteiro.

Após o incidente da primeira tentativa, o perfil desta estação exige limites
também no coordenador do host: CPU0,25, memória384MiB, swap0,32tasks e disco
2MiB/s em cada direção. Os containers também têm CPU0,25 e disco2MiB/s.
O dispositivo fechado é `/dev/nvme0n1`, que atende este checkout e Docker;
outra estação exige revisão do perfil, não remoção do limite. `run` confere
`cpu.max`, `memory.max`, `memory.swap.max`, `pids.max` e `io.max` do próprio
cgroup antes dos efeitos. Nice/IO idle complementam os tetos. Sem alterar
configuração global do host, serviços terceiros ou limites para passar gates.

No ensaio desta estação, o operador também acompanha memória disponível/PSI,
ocupação do NVMe e pressão de I/O do cgroup da sessão gráfica, fora do serviço
limitado. Espera de I/O global sozinha não mede ocupação física do NVMe. O monitor
interrompe o coordenador por SIGINT após três amostras de5s com memória abaixo
de4GiB, PSI de memória >=1%, PSI de I/O da interface >=1%, ou PSI global de I/O
>=20% junto com NVMe >=80% ocupado. Ausência/reinício do cgroup gráfico também
interrompe. Os tetos rígidos e gates de dados/identidade/cleanup continuam exigidos.
Saída zero de systemd após SIGINT não prova restore: conferir recibo verificado
e pin independente em closed.json; monitor interrompido nunca declara sucesso.

Uma falha do gate encerra novos efeitos desse contexto; apenas o pg_isready fixo
tem repetição limitada de prontidão. Ambiguidade de create não é repetida. Ausência
sem ID conhecido não prova cleanup. Colisão/ownership ou log inválido mantém estado
desconhecido; não editar histórico para limpar. Sem recibo verificado em falha.

## Comandos do operador

Depois da implementação revisada/commitada, criar `images.json` privado com as duas
chaves `linux`/`wazuh`, cada qual com `application`, `runner`, `postgres`, `redis`
por imageID completo. Não fornecer destinos, comandos livres ou credenciais:

```sh
.venv/bin/python scripts/lab_recovery.py prepare --images /CAMINHO/PRIVADO/images.json
```

Conferir plano em `.local/lab-recovery/plans/PLAN_ID/plan.json`, hash e escopo.
**Somente após aprovação humana específica**:

```sh
systemd-run --user --wait --pipe --collect --unit=aegis-lab-recovery-PLAN_ID \
  -p CPUQuota=25% -p MemoryMax=384M -p MemorySwapMax=0 -p TasksMax=32 \
  -p Nice=15 -p IOSchedulingClass=idle \
  -p 'IOReadBandwidthMax=/dev/nvme0n1 2M' \
  -p 'IOWriteBandwidthMax=/dev/nvme0n1 2M' \
  -p WorkingDirectory=/home/IVPTER/AEGIS \
  /home/IVPTER/AEGIS/.venv/bin/python /home/IVPTER/AEGIS/scripts/lab_recovery.py run \
  --plan-id PLAN_ID --plan-sha256 PLAN_SHA256 \
  --authorized-plan-sha256 PLAN_SHA256 --confirm-original-volume-read-only
```

Fences/intents, arquivos frios, dump, journal, custódia e recibos ficam privados em
`.local/lab-recovery/operations/RUN_ID`. O pedido no plano identifica RUN_ID;
`requested.json` informa RUN_ID e `begin_sha256`, vinculados a `begin.json`.
Cleanup separado, sem reabrir originais nem
reiniciar etapa e sem depender da validade atual do plano:

```sh
.venv/bin/python scripts/lab_recovery.py cleanup \
  --run-id RUN_ID --begin-sha256 BEGIN_SHA256
```

Se o log estiver parcial/corrompido ou o daemon indisponível, a automação recusa
concluir cleanup: revisar somente nomes `aegis-lab-recovery-*`, labels
`io.aegis.lab-recovery`, IDs/imagem/mounts e registros privados. Não usar prune,
remoção global, force, apagar volumes ou alterar fences/recibos para liberar replay.
Arquivos de backup/custódia e tentativas falhas não são apagados pela ferramenta.

## Provas separadas

`make test-lab-recovery` usa PG/SQLite descartáveis e daemon simulado, sem Lab.
`make test-lab-recovery-native-fixture` é explícito: dump de schema de teste,
cluster offline novo, cópia fria repetida, reabertura da cópia, novo dump e cleanup
reais; `synthetic=true`. Não abre os quatro volumes históricos e não roda na CI
automaticamente. Artefatos privados em `.local/lab-recovery-fixtures`.

O ensaio histórico #66 é separado, `synthetic=false`, sob plano aprovado. Não há
novo marcador/campanha/veredicto, conexão a SIEM, cutover, implantação ou permissão
de operação normal. Sem retenção destrutiva, upload de backups ou custódia externa.
Resultados e limitações no [checkpoint](../development/lab-backup-checkpoint.md).
