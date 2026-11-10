# Ensaio de identidade mTLS antes da rotação

Estado em 2026-11-10: coordenador e CLIs de execução/revisão/cleanup implementados;
CI42873241181 aprovada para a fonte f0c95b2, incluindo quatro partições Python e
React. A entrega #2 alinhou o perfil à rede `192.168.253.0/29`, preservando `qasrc`.
O bloqueio observado em05/11 referia-se à faixa antiga e permanece como histórico;
a faixa atual exige nova inspeção local antes de qualquer efeito. Validação
automatizada usa PKI/Git temporários, loopback e RPCs simuladas.
Uma tentativa nativa foi autorizada em10/11 e encerrou com falha na etapa do
cliente; os dois containers e a bridge foram removidos. **A identidade mTLS nativa
continua sem comprovação.** A revisão integral dos artefatos também foi recusada.
Ver [resultado e limitações](../../docs/evidence/identity-assay-2026-11-10/README.md).
Este documento não concede permissão para iniciar recursos. A autorização foi
consumida; o plano e os registros dessa tentativa não podem ser reutilizados.

## Objetivo e limites

Verificar o servidor no modo `identity-only`, com certificados candidatos,
preservando identidade e material originais. Não ativa PKI ou binding e não
autoriza a operação normal do laboratório. Não comprova integridade do diário,
recuperação de campanha, telemetria Wazuh ou detecção defensiva.

Somente três recursos próprios do projeto `aegis-linux-lab`:

| Recurso | Perfil fixo |
| --- | --- |
| Rede isolada | Bridge interna IPv4 `192.168.253.0/29`, gateway `.1`, modo `isolated`, sem IPv6 ou portas publicadas. Rotas e redes existentes precisam estar sem sobreposição observada. |
| Servidor | `192.168.253.2:8443`, UID/GID10001, modo identity-only, allowlist vazia e somente GET de identidade. Três binds RO: chave/certificado do servidor candidato e CA cliente candidata. |
| Cliente | `192.168.253.3`, processo Python fixo e stdin privado sem TTY. Quatro binds RO: CA servidor/certificado/chave cliente candidatos e somente CA servidor antiga pública. |

Ambos os containers: rootfs RO, capabilities removidas, no-new-privileges,
192MiB/0,5CPU/16PIDs, tmpfs16MiB, sem restart/healthcheck/volumes anônimos/portas
publicadas. Nenhum socket Docker na aplicação. Não há comando, script, caminho,
alvo ou URL livre fornecido por API.

**Não iniciar** PostgreSQL, Redis, API, worker, Wazuh ou runner normal. Não montar
volumes originais, abrir diário, executar marcador ou ler chaves antigas. A
aplicação Demo e os recursos de outros projetos permanecem preservados.

## Precondições

1. Autorização humana específica para um único ensaio, depois de CLI e escopo
   completos e revisáveis. Confirmação local por hash não é assinatura humana.
2. `main` limpa e fixada no plano, CI aprovada para o código utilizado.
3. Candidato PKI novo e válido, separado da origem, com IDs e URL fixos. Não
   reutilizar o candidato expirado ou modificar arquivos de ensaios anteriores.
4. Imagem runner selada e revisada, com pacote/dependências correspondentes ao
   código atual. O build preparado para a issue #45 está registrado na
   [evidência da imagem atual](../../docs/evidence/identity-image-2026-11-10/README.md);
   a [imagem de30/10](../../docs/evidence/identity-image-2026-10-30/README.md) é histórica;
   build verificado não comprova runtime mTLS.
5. Projeto sem recursos preexistentes, nomes reservados livres e consumidores
   globais dos dois volumes originais ausentes. Imagens/daemon/volumes conferidos
   por metadados somente leitura. Nenhum serviço é parado para forçar preflight.
6. Intent novo sob lock exclusivo. Plano consumido ou role anterior, inclusive
   ABSENT após cleanup, nunca autoriza novo create/start.

## Procedimento interno

O [coordenador](../../scripts/runner_identity_coordinator.py) recebe a mesma
NetworkGates/ConfirmedPlan durante todo o ciclo. A janela de efeitos termina até
begin+240s. O orçamento total de leituras/RPCs/cleanup termina em begin+300s,
limitado também pelo relógio monotônico original; nenhuma reconstrução renova isso.

Antes do primeiro efeito, grava pedido e fence de consumo do plano com
operação/beginSHA/plano/escopo. Os gates são computados a partir de fatos atuais,
persistidos com seus preimages normalizados e rechecados após fsync. JSON salvo
não substitui admissão computada.

O ciclo cria uma única bridge, cria/inicia um único servidor identity-only e
executa uma única vez o cliente fixo. O cliente faz quatro conexões TLS1.3:
positivo com material candidato; negativo sem certificado cliente; negativo com
CA servidor antiga; positivo novamente. Identidade, DER dos peers e política de
certificado são conferidos. Não há retry automático para erro de prontidão/TLS.

Somente alerta TLS explícito de certificado requerido comprova o controle
negativo sem cliente. EOF/reset permanece **inconclusivo**. CA antiga expirada,
servidor inacessível ou erro genérico não são prova de rejeição por trust.

Após saída do cliente, confere runtime, membership, contexto e reply fechado
antes de registrar hashes. Cleanup é sempre tentado: cliente → servidor → rede.
Interrupção gera cleanup e recibo, quando o armazenamento permite, e é propagada.
Falha/expiração não habilitam outro start.

## Evidências e resultados

Artefatos ficam somente em `.local/pki-identity-runtime/<operation-id>`, diretório
0700 e arquivos0600/O_EXCL/fsync. O fence de uso fica junto ao `plan.json`. Registros
contêm JSON normalizado/hash, sem chaves, senhas, stderr ou exceções. Não publicar
esse diretório nem copiar registros privados diretamente para Git.

Em sucesso completo há14registros: pedido, gate/lifecycle da rede, três gates e
lifecycle do servidor, request, três gates e lifecycle do cliente, cleanup e recibo.
O recibo fixa inventário e hashes dos estágios; flags de ativação/binding/diário/
marcador/Wazuh/operação normal permanecem falsas.

- `identity_assay_verified_and_closed`: todos os controles foram confirmados e
  ausência dos recursos próprios foi verificada.
- `identity_assay_inconclusive_and_closed`: fluxo/cleanup concluídos, controle TLS
  negativo permaneceu inconclusivo. Não apresentar como verificação completa.
- `identity_assay_failed_and_closed`: execução ou evidência não confirmada, com
  recursos próprios encerrados.
- `identity_assay_cleanup_unconfirmed`: recursos ou dependências retidos; exige
  inspeção e escopo de recuperação específico, sem force/delete global.

Registro parcial ou armazenamento falho nunca autoriza avançar/repetir. Hash não
é assinatura nem proteção contra um proprietário local malicioso. Fixtures de
protocolo nos testes não são evidência de TLS nativo.

## O que permanece pendente

As subissues seguem a ordem #45 (imagem e pacote concreto), #46 (revisão e
autorização específica) e #47 (uma tentativa e seu encerramento). A correção de
perfil entregue em #2 não comprova ausência atual de sobreposição no host.
O pacote precisa incluir `runner_activation.py recheck` e a revisão somente
leitura de rotas/redes, além da prova selada e da CI do código utilizado.
Em10/11, #45 e #46 foram concluídas; a tentativa única de #47 falhou e foi
encerrada com ausência dos recursos próprios confirmada. A causa exata da falha
do cliente não consta no código estático do recibo; os controles TLS não foram
confirmados. O recibo declara inventário de artefatos não verificado e a CLI de
revisão recusa confirmação integral; não promover registros individuais válidos
a prova completa. #47 e o pai #3 permanecem abertos para diagnóstico.
O [diagnóstico posterior](../../docs/development/identity-assay-diagnostics.md)
descreve a correção do parsing repetido e dos códigos descartados. Recibos
novos /2 incluem diagnósticos fechados; a revisão mantém compatibilidade com /1
e explica inventário declarado não verificado, sem aprovar o histórico recusado.
Nova tentativa exige outro pacote/plano, rechecks e autorização específica;
CI aprovada não substitui autorização. Não usar imports Python manuais para
contornar o procedimento. A ativação real de PKI/binding permanece uma etapa
separada e precisa também de imagem de aplicação atual, plano e aprovação próprios.

Consulte o [checkpoint](../../docs/PROGRESS.md), o
[ADR0030](../../docs/architecture/decisions/0030-runner-identity-only.md) e a
[preparação da rotação](../../docs/operations/runner-pki-activation.md).

## Revisão histórica somente leitura

A CLI abaixo lê apenas o diretório privado de artefatos. Exige pins retidos
independentemente: UUID da operação e hashes de begin/plano/escopo/corpo do recibo.
O último hash é o digest JSON canônico do **corpo** do recibo, não SHA dos bytes
do envelope/arquivo. Não extraia os pins dos próprios arquivos como se isso
comprovasse uma origem independente.

```bash
.venv/bin/python scripts/runner_identity_review.py \
  --operation-id UUID_HEX_DA_OPERACAO \
  --begin-sha256 HASH_BEGIN \
  --plan-sha256 HASH_PLANO \
  --scope-sha256 HASH_ESCOPO \
  --receipt-body-sha256 HASH_CORPO_RECIBO
```

Substitua os placeholders pelos pins reais; o comando não aceita destinos ou
comandos nativos. Confere envelopes/inventário/hashes de estágios e preimages dos
gates, request/reply fechados e classificação, com duas leituras dos arquivos.
Recusa parciais/adulteração/permissões/links/inventário desconhecido. Funciona
após expiração, sem abrir plano/intents/PKI, criar lock, gravar ou consultar Docker.

Exit0 significa **integridade dos registros salvos**, inclusive de um ensaio que
falhou. A saída usa recorded_assay_status/recorded_tls_controls_verified; não
revalida runtime, origem TLS ou fence junto ao plano e nunca permite retomada.
Recibo incompleto não pode ser promovido a verificação íntegra por essa CLI.

## CLI de execução opt-in

`scripts/runner_identity_assay.py --help` apenas lista argumentos. **Não executar
o ensaio antes de concluir escopo/CI e obter autorização específica.**
A CLI exige plan-id, expected-sha256, authorized-scope-sha256, build-id,
build-plan-sha256, build-receipt-sha256 e confirm-identity-only-assay explícito.
Não aceita alvos/URL/comandos/roots livres, credenciais ou geração de chave.

Sob lock compartilhado do projeto, recusa fence ou histórico de uso do mesmo
plano (mesmo tentativa vazia/encerrada), revalida metadata e fonte/imagem selada
antes de iniciar o orçamento. Então cria intent novo e invoca somente o
coordenador identity-only. Plano/candidato precisam estar válidos; preflight não
concede assinatura humana. Erros não imprimem exceções privadas.

A saída inclui corpo do recibo e seu digest JSON canônico. Exit0 é reservado a
identity_assay_verified_and_closed; resultado inconclusivo retorna1, com evidências
preservadas. Uma falha antes do primeiro efeito fecha somente intent vazio. Com
recursos pendentes, preserva ownership para recuperação; não reinicia ou limpa
globalmente. A existência da CLI não autoriza seu uso automático ao continuar o
desenvolvimento.

## Recuperação após crash ou cleanup incerto

Recuperação nunca retoma o ensaio. Primeiro prepare um escopo separado, com os
pins independentes da operação original. Esta preparação grava somente um novo
plano local, sob o lock/resume exatos do projeto; não consulta Docker nem abre
PKI/credenciais/volumes. O plano fixa o estado/fence/requested originais e main
atual, tem validade15min e não concede autoridade por si só.

```bash
.venv/bin/python scripts/runner_identity_cleanup.py plan \
  --original-plan-id UUID_HEX_PLANO_ORIGINAL \
  --original-plan-sha256 HASH_PLANO_ORIGINAL \
  --operation-id UUID_HEX_OPERACAO_ORIGINAL \
  --begin-sha256 HASH_BEGIN_ORIGINAL
```

Revise o plano e obtenha **autorização específica desse novo escopo**. Só então:

```bash
.venv/bin/python scripts/runner_identity_cleanup.py run \
  --cleanup-plan-id UUID_HEX_NOVO_PLANO \
  --expected-sha256 HASH_NOVO_PLANO \
  --authorized-scope-sha256 HASH_NOVO_ESCOPO \
  --confirm-owned-cleanup
```

Substitua os placeholders pelos pins reais. Roots são fixos, sem argumentos de
alvo/comando. Run revalida snapshot/fonte sob o lock original e consome o plano
antes do primeiro RPC. A nova janela é **somente cleanup, até120s**, independente
da autorização de300s do ensaio anterior. Native só consulta ownership e permite
SIGTERM5s/remove dos papéis/IDs originais, com fence durável e REMOVAL_REQUESTED.
Não aceita create/start, force, remoção de volumes ou papéis de DB/API/worker.

Resposta perdida é reconciliada; foreign/ambiguidade/expiração/interrupção mantêm
a pendência. Não repetir plano consumido ou apagar fences; prepare outro escopo
para revisão se necessário. O recibo de recuperação fica separado no diretório
do novo plano e não reescreve o recibo do ensaio. Exit0 exige ausência dos recursos
próprios verificada e operação encerrada; não autoriza PKI/binding/operação normal.

Se plano/fence/requested original estiver ausente ou adulterado, a recuperação
automatizada recusa efeitos. Preserve a quarentena e obtenha um escopo de
inspeção/intervenção próprio; não contorne os checks com Docker rm manual.

Escopo operacional para revisão humana:
[ensaio único de identidade](IDENTITY-ASSAY.md). Pacote privado com candidato,
plano, hashes e CI precisa ser concluído antes da solicitação de autorização.
O plano tem validade de15min. Se expirar durante a revisão humana, preservar o
plano e preparar outro pacote, com novos hashes e nova revisão, antes de executar;
não renovar o TTL ou reaproveitar aprovação de outro escopo.
