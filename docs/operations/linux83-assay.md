# #83 — uma tentativa nativa por comportamento Linux revisado

Preparação de18/11/2026. O pedido de retomada permite preparar/revisar o ensaio;
a operação exige aprovação de pacote concreto conforme AGENTS/issue. Este
arquivo não é autorização. Autorizações #5/#14 consumidas e originais preservados.

## Duas tentativas independentes e sequenciais

O coordenador `scripts/atomic_assay.py` é compartilhado, mantendo o perfil legado
`atomic80` e acrescentando somente duas escolhas fechadas:

| Perfil | Definição | Efeito fixo |
| --- | --- | --- |
| `linux83-process` | `linux-process-canary-v1` | Um `/bin/true <marker>`, exit0/stdout0;43bytes próprios |
| `linux83-shell` | `linux-shell-canary-v1` | Um `/bin/sh -c <printf fixo> <marker>`, exit0/stdout43;43bytes próprios |

Cada escolha recebe pacote/hash/tentativa, IDs, PKI, credenciais, projeto e três
volumes novos próprios. Nunca trocar teste em binding/journal existente.
Executar em sequência; liberar as redes da primeira somente após cleanup
confirmado/recursos encerrados, mantendo volumes. Se houver ambiguidade ou
quarentena, bloquear a segunda. Nunca repetir run/start/bootstrap.

Namespace `.local/linux83-packages/<id>` protegido, projeto `aegis-linux83-<id>`;
nenhum original/backup/clone/journal montado. Banco novo `linux83_assay`, owner
novo `linux83_owner`, duas contas próprias `linux83_*`. Helper recusa outro
db/host/owner/query antes da conexão. Bootstrap explícito só em public vazio:
Alembic c8e4a6d21f90/36tabelas, seed versionado e grants mínimos, sem reset.
O schema novo não altera os gates b7 dos originais.

## Preparação sem startup

Main limpa, testes pertinentes e CI. Exportar blobs de Git, conferir wheels/locks/
base imutável e construir runner/aplicação em tags exclusivas, sem substituir
tags antigas; RUNs sem rede/pull=false. Os nomes históricos dos helpers/builders
não autorizam efeito Atomic.

`atomic_assay.py prepare` recebe recibo/hash da aplicação e
`--profile linux83-process` ou `--profile linux83-shell`: gera PKI/IDs próprios,
revisões, segredos e receita sem criar containers/redes/volumes.
`verify --package-id <id> --expected-sha256 <hash>` confere namespace, perfil,
revisão, fonte, inventário, imagens, receita e prazo. Nenhum cria
`authorization.json` ou `attempt.json`. Hash não é assinatura.

Apresentar os dois hashes/IDs, imagens, janela, alvos, efeitos e cleanup ao usuário.
Só após aprovação explícita desses pacotes registrar a decisão para cada hash,
`approved_by=user,one_attempt=true`. Validade12h/PKI limitada; expiração/drift
bloqueiam sem renovação silenciosa. Segredos/dumps/logs ficam fora do Git/issue.

## Recursos e gates

Duas redes internas isolated192.168.253.0/29 e192.168.253.8/29, IPv6 desabilitado,
nenhuma porta host ou conexão a qasrc/outros projetos. Recheck RO de todas as
redes/rotas antes de create; alvos/IDs/imagens concretos na proposta. API/worker/
runner usam UID10001, rootfs RO, cap_drop ALL, no-new-privileges e tmpfs próprio;
app sem owner PostgreSQL ou CA privada. Redis usa999:999/rootfs RO/tmpfs. O PG
usa entrypoint oficial para inicializar somente seu volume novo, com rootfs
gravável. Administração separada; sem comando/alvo livre.

Limites: runner192MiB/API512MiB/worker256MiB/PG384MiB/Redis128MiB e controlador128MiB/
helper256MiB em fases distintas. Pico1728MiB; MemAvailable≥3072MiB antes de iniciar.
Memória insuficiente bloqueia; não reduzir o piso, alterar host/swap/sysctl ou
parar outros projetos. Operação≤15min, run60s, efeito5s/lease2s.

`run` recusa autorização ausente/divergente, expiração/drift, fence existente,
colisão, memória insuficiente e sobreposição de rede. Fence fsynced antes do
primeiro create; UUID/scope persistidos antes de approve/start. Prontidão RO,
inspeção nativa de runtime, mTLS, registro inicialmente revogado e aprovação por
administrador ativo distinto do solicitante precedem o efeito.

## Evidência e recuperação

Exatamente uma run Linux por pacote, synthetic=false. Conferir recibo tipado,
PID/exit/stdout, hash/43bytes, cleanup e JSON/HTML da mesma run. Sem sensor/regra
defensiva, resultado esperado COMPLETED/INCONCLUSIVE/CLEANED. Recibo/stdout não
são telemetria; nenhum alerta, DETECTED ou eficácia de técnica fabricados.

Revogar lab, inativar duas contas/remover sessões, inclusive se API falhar.
Helper owner verifica binding-review/cleanup antes de permitir stop. Encerrar
somente recursos próprios/conferir zero consumidores; reter três volumes, PKI,
imagens, diário/fences e provas de cada pacote. Não apagar desconhecidos,
volumes/intents nem liberar por HTTP404.

Em ambiguidade, manter reserva/quarentena e consultar job/spec/geração da mesma
tentativa; recuperar somente cleanup. Não executar de novo o coordenador ou criar
outra run. Bloquear o segundo pacote até reconciliar o primeiro. #83 só fecha
com provas nativas e limites; não iniciar outra entrega após concluir.

## Operação encerrada em18/11/2026

Após aprovação humana da proposta específica, processo0a85302e e shell22431af4
tiveram uma campanha cada, COMPLETED/INCONCLUSIVE/CLEANED, synthetic=false.
Labs revogados, quatro contas UI inativas/zero sessões, recursos encerrados e
seis volumes preservados sem consumidores. [Provas e limites](../evidence/linux83-2026-11-18/VERIFIED-83.md).
Autorização consumida. Este procedimento não permite replay, nova tentativa,
reativação dos recursos ou reutilização dos pacotes; preservar histórico/fences.
