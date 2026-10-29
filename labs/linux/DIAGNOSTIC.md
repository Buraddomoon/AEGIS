# Diagnóstico único dos volumes Linux preservados

Estado em2026-10-29: segunda tentativa autorizada também **interrompida e encerrada**,
operação `e6566b9db97d47e88f9e8197a0f85c15`, plano `ef77bb4c...`. PostgreSQL iniciou
e passou nas inspeções físicas/readiness; primeiro leitor não produziu prova
validada. Ambos os containers foram removidos, volumes preservados/sem consumidores.
Sem probe do diário, marcador ou mudança de PKI/binding. Não há conclusão sobre
continuidade. Essa autorização também foi consumida; não repetir o plano.

Primeiro diagnóstico autorizado **interrompido e encerrado**,
operação `de7aabdff5b04c5da116a86bb2d10496`. Somente o container PG foi criado;
falhou a conferência anterior ao start e o container foi removido. Nessa tentativa, nenhum start,
SQL ou probe de diário foi solicitado. Volumes preservados e sem consumidores,
ausência de containers/redes reconferida. A autorização única foi consumida;
não repetir o plano nem apagar seu pedido. A continuidade ainda não foi provada.
Ver [evidência](../../docs/evidence/diagnostic-2026-10-29/README.md).
Antes de novo `run`, obter autorização específica para o novo plano concreto.
`prepare`, `recheck`, testes e builds não concedem essa autorização.

## Objetivo e efeito exato

Conferir continuidade entre as provas persistidas de execuções antigas e o diário
original, preparando a futura ativação PKI. Não executa campanha, marcador, runner
servidor, worker, API, Redis, Wazuh ou migração. Não renova certificados, registra
binding, altera grants/senhas ou cria/remove volumes.

Projeto alvo único: `aegis-linux-lab`. Recursos próprios têm nomes/labels ligados
à operação durável, sem adoção de containers anteriores. Cinco containers no
máximo, sequenciais; no máximo dois simultâneos:

1. PostgreSQL17 existente, pelo imageID revisado, UID70, rootfs RO, volume original
   `aegis-linux-lab_postgres-data` **RW**, HBA fixo externo RO, networknone/loopback.
   Iniciar PostgreSQL escreve metadados/WAL operacionais. O ensaio completo não é
   somente leitura, embora as consultas SQL sejam READONLY.
2. Leitor fixo como UID10001, mesmo namespace do DB próprio, sem mount/portas.
   Consulta exclusivamente perfil/schema/binding/histórico revogado e provas de
   cleanup; captura privada. Não concede privilégios se o papel atual for insuficiente.
3. Probe do diário `aegis-linux-lab_journal` RO, UID10001/networknone, comparando
   todos os registros com as provas. Removido após a conferência.
4. Segundo probe RO do mesmo diário, sem efeito entre as leituras; comparação dos
   inventários lógicos, incluindo trabalhos adicionais e fences.
5. Segundo leitor fixo do DB, comparando binding/versão/histórico/provas com antes.
   Somente o timestamp UTC da revisão é volátil; não representa dump de todo o banco.

Readiness usa somente pg_isready fixo, até15s/oito tentativas; não comprova login.
Cada probe tem transporte de até20s. Prazo de300s para novos efeitos, sem renovar
budget durante a operação; cleanup próprio continua permitido após expiração.
Servidor384MiB/CPU1/PIDs64; leitor256MiB ou probe192MiB/CPU0,5/PIDs16. Todos sem
capabilities, no-new-privileges e sem restart automático. Sem portas publicadas,
rede host, Docker socket ou diretório de credenciais montado.

## Preparação somente de metadados

Usar `make runner-postgres-origin POSTGRES_IMAGE_ID=sha256:...` para consultar o
índice/manifesto oficiais da **imagem já presente**, sem pull/layers. Guardar stdout
num arquivo privado0600 sob pai0700 e seu SHA canônico independente. Não imprimir
tokens, .env ou inspect bruto. Esse vínculo confia no daemon local; não é assinatura
de publicador nem leitura/hash de todos os layers locais.

`make runner-diagnostic-plan` exige application/runner/postgres/redis imageIDs,
RUNNER_BUILD_ID/SHA256/RECEIPT_SHA256 e POSTGRES_ORIGIN_RECEIPT/SHA256. Esses quatro
imageIDs são inventariados; apenas runner e postgres poderão gerar containers.
A imagem runner precisa corresponder ao pacote/dependências de main limpa e ao
build selado conferido. Origem pública Linux fixa, sem candidato PKI; identidade
histórica expirada é inspecionada sem ser aceita num handshake TLS.

O retorno fornece DIAGNOSTIC_PLAN_ID, DIAGNOSTIC_PLAN_SHA256 e scope_sha256. Plano
v3 tem validade24h. Recheck público exige quiescência, mesmas imagens/código/daemon/
volumes e nenhum consumidor, inclusive parado/externo. Preparações v1/v2 permanecem
intactas e não são convertidas em permissão executável. Novo commit exige novo plano.

Antes do ensaio, conferir memória/disco disponíveis e ausência de outras operações;
não parar serviços alheios, alterar swap/sysctl/cache ou apagar imagens/volumes para
forçar preflight. Recursos acima são limites de containers, não garantia de consumo
máximo de todo o Docker/host.

## Execução somente depois da autorização específica

O comando abaixo inicia PostgreSQL sobre dados originais. A confirmação é uma
afirmação do operador local sobre a autorização; não é assinatura/autenticação
humana independente nem substitui a aprovação real do usuário.

```bash
make runner-diagnostic-run \
  DIAGNOSTIC_PLAN_ID=ID_REVISADO \
  DIAGNOSTIC_PLAN_SHA256=SHA_DO_PLANO \
  DIAGNOSTIC_AUTHORIZED_SCOPE_SHA256=SHA_DO_ESCOPO_AUTORIZADO \
  DIAGNOSTIC_CONFIRM_START=yes
```

Sem `DIAGNOSTIC_CONFIRM_START=yes`, Make recusa. CLI também exige
`--confirm-original-database-start`; não há senha em argv. A única credencial lida
é APP_DB_PASSWORD do `.env` local0600 já utilizado pelo projeto, no perfil gerado
pelo inicializador (hex48–128caracteres, sem quotes/interpolação). Valor diferente,
faltante, duplicado ou inseguro bloqueia, sem reset nem fallback de ambiente.
Senha vai só na memória/stdin do leitor; não entra em intent/receipt/log/hash.

Lock compartilhado em `.local/pki-activation-intents` e pedido exclusivo dentro do
plano impedem concorrência/replay. Depois do primeiro pedido, não repetir o plano,
apagar pedidos ou editar intents. Ambiguidade exige inspeção e fechamento próprios.

## Evidências e encerramento

Artefatos privados em `.local/pki-activation-runtime/OPERATION_ID`: HBA não secreto
0444 sob pai0700; bundles SQL, relatórios de etapa e recibo final0600. Intents têm
hashchain/fsync antes dos efeitos. stdout contém somente status/identificadores.
Nenhuma credencial ou conteúdo bruto dos bundles deve ser publicado no GitHub.

Sucesso exige comparação de provas/diário e ausência dos recursos próprios
reconferida. Não declara DETECTED, ativação PKI ou permissão de operação normal.
Falha de cleanup mantém dependências; leitor incerto retém DB. Não apagar volumes.
O relatório privado db-lifecycle inclui failure_phase e failure_code limitado a
códigos estáticos revisados; não publica mensagens brutas de exceções. Recibos
históricos anteriores podem não conter esses campos e não devem ser reescritos.

Se interrompido, consultar diagnostic-requested.json no plano para operation_id e
begin_sha256, e executar somente cleanup desses IDs:

```bash
make runner-diagnostic-cleanup \
  DIAGNOSTIC_PLAN_ID=ID_ORIGINAL \
  DIAGNOSTIC_PLAN_SHA256=SHA_ORIGINAL \
  DIAGNOSTIC_OPERATION_ID=OPERATION_ID \
  DIAGNOSTIC_BEGIN_SHA256=BEGIN_SHA256
```

Cleanup aceita plano expirado, confere integridade/escopo/intent originais e nomes/
labels/IDs/imagens antes de stop SIGTERM/5s e rm sem force/volumes. Não relança
nenhuma etapa, lê senha ou depende de PKI atual. Incidente de ownership/estado incerto
permanece visível; não limpar globalmente ou adotar recurso parecido.

Testes: `make test-runner-diagnostic`. Daemon fixtures, Git/PKI temporários e
SQLite/decodificadores reais; não comprovam runtime nos volumes originais. O ensaio
nativo bem-sucedido e qualquer ativação posterior continuam sendo marcos separados.
