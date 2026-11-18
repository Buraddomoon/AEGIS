# Pequena allowlist Linux — #81 / #15

Revisão de18/11/2026, base `5e11944`. A dependência #5 está concluída.
O inventário de10/11 é histórico: hoje existem o marcador original e o perfil
Atomic de permissões próprio da #14, ambos preservados. Esta especificação
acrescenta exatamente dois perfis opt-in, um por identidade/binding; não altera
os quatro testes Demo nem torna metadados Atomic executáveis.

| Definição v1 | Comportamento | Processo filho fixo | ATT&CK | Resultado esperado |
| --- | --- | --- | --- | --- |
| `linux-process-canary-v1` | `benign-process-creation` | `/bin/true <marker>` | Nenhuma | Exit0, stdout vazio; wrapper grava43bytes em `proof.marker` |
| `linux-shell-canary-v1` | `fixed-unix-shell` | `/bin/sh -c 'printf '\''%s\n'\'' "$0"' <marker>` | T1059.004, limite abaixo | Exit0, stdout exatamente `<marker>\n`; wrapper grava esses43bytes |

O marcador é exclusivamente `aegis-<UUID canônico>`, gerado pelo domínio. É um
argumento separado, nunca interpolado em código. O script completo é a constante
`printf '%s\n' "$0"`, sem leitura de script externo, rede, redirecionamento,
pipeline, background, discovery, privilégio ou persistência. Não há campo de
comando, caminho, argumentos ou ambiente fornecido pela API. `/bin/true` somente
exercita criação de processo; não é descoberta de processos/T1057. O wrapper Python
é infraestrutura do executor, sem associação automática a T1059.006.

T1059.004 descreve execução por interpretador Unix, inclusive scripts. A associação
do segundo perfil representa somente essa primitiva benigna, sem provar cobertura
integral da técnica ou adversário. Fonte oficial consultada em18/11:
[MITRE ATT&CK v20, T1059.004 v1.4](https://attack.mitre.org/versions/v20/techniques/T1059/004/).
O catálogo ATT&CK ativo ainda deve validar a disponibilidade da técnica; esta
entrega não atualiza releases do catálogo.

## Contrato da revisão e execução

Cada identidade de teste usa `linux-{process|shell}-canary/v1@<sha256 da revisão>`.
A revisão inclui definição, comportamento, técnica, hash do programa, argv/script,
artefatos, limites e versão. Hash é integridade, não assinatura. Mudança de bytes
ou revisão exige nova identidade; descriptor/configuration_hash e escopo aprovado
incluem essa revisão. Não reescrever binding, aprovação ou diário antigos.
Perfis combinados e execução por binding legado são recusados.

Pré-requisitos: Linux, Python da imagem revisada, `/bin/true` ou `/bin/sh` da
mesma imagem fixada por ID, UID sem privilégio, workspace0700/tmpfs próprio,
rootfs RO, sem capabilities, limites de memória/PIDs, mTLS/preflight vigente,
binding revisado, laboratório autorizado e administrador ativo distinto do
solicitante. Nenhuma instalação ou configuração de auditoria é implícita.

Supervisor existente: intent durável antes do spawn, concorrência1, lease2s,
efeito até5s/deadline. Wrapper e filho têm vínculo de morte do pai; cancelamento,
timeout e encerramento terminam/recolhem seus processos. Recibo contém perfil,
PID do filho, exit0, hash/bytes de stdout e do artefato, tempos e contexto;
é `execution_receipt`, `synthetic=false`, sem evento defensivo fabricado.

Somente `proof.marker`0600 e `receipt.json`0600 no diretório UUID próprio.
Cleanup usa a allowlist existente, sem remoção recursiva. Arquivo desconhecido,
link, falha ou resposta ambígua mantém reserva/quarentena e recibos anteriores.
Não repetir start para recuperar; consultar job/geração e executar somente cleanup
sob revisão do estado original. Se falhar, preservar diretório/diário e manter
laboratório indisponível até recuperação confirmada; não apagar fences/volumes.

## Telemetria esperada e limites

Fonte candidata: sensor defensivo independente de criação de processos (auditd
ou EDR já autorizado), com executável, argv contendo marker, PID/PPID e timestamp;
FIM do arquivo só prova o artefato, não prova a execução do shell. Log/recibo do
runner e stdout não são essa fonte. Não habilitar sensor, regra ou Wazuh nesta
entrega sem autorização. Não reutilizar a regra100200 do marcador como prova
do comportamento novo.

Normalização deve conservar laboratório, ativo/endpoint, execution_id, marker,
comportamento, synthetic e timestamp verificados. DETECTED requer ainda regra
esperada explicitamente aprovada e alerta independente correlacionado. Falso
positivo por endpoint, comportamento, marker, regra, execução ou tempo distintos
deve ser recusado pelo validador existente. Sem regra/coletor configurado,
resultado é INCONCLUSIVE; ausência de alerta não prova ausência de telemetria.
Fixtures de eventos demonstram contrato, não ingestão nativa. Esta versão não
adiciona conector auditd/EDR nem gera eventos do recibo.

## Validação e bloqueio operacional

#82 deve exercitar programas reais em temporários locais, drift de fonte/revisão,
recibo incompatível, timeout/cancelamento com filho, resposta perdida/no replay,
cleanup falho, API/worker/PG descartável e falsos positivos. Suítes PG/Redis15
sempre sequenciais. Demo permanece synthetic=true.

#83 requer pacote concreto e aprovação humana nova: imagem/código fixados,
IDs/lab/endpoint/workspace e janela, revisão/hash de cada perfil, um efeito por
teste, contas segregadas, pré-condições, fonte defensiva disponível ou ausência
explícita, limites, rollback/cleanup e recursos a preservar. As autorizações
#5/#14 estão consumidas. A issue e o pedido genérico não autorizam iniciar labs,
reabrir volumes originais, executar ensaio nativo ou alterar rede. Até aprovação,
registrar #83 bloqueada e manter #15 aberta; não declarar implantação/aceite real.
