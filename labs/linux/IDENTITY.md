# Ensaio de identidade mTLS antes da rotação

Estado: coordenador interno implementado com gates, armazenamento privado e
cleanup por ownership; validação automatizada usa PKI/Git temporários e RPCs
simuladas. **O ensaio nativo ainda não foi realizado nem autorizado.** A CLI e o
escopo operacional final ainda estão em preparação. Este documento não concede
permissão para iniciar recursos. Os ensaios históricos não podem ser repetidos.

## Objetivo e limites

Verificar o servidor no modo `identity-only`, com certificados candidatos,
preservando identidade e material originais. Não ativa PKI ou binding e não
autoriza a operação normal do laboratório. Não comprova integridade do diário,
recuperação de campanha, telemetria Wazuh ou detecção defensiva.

Somente três recursos próprios do projeto `aegis-linux-lab`:

| Recurso | Perfil fixo |
| --- | --- |
| Rede isolada | Bridge interna IPv4 `172.30.88.0/29`, modo `isolated`, sem IPv6 ou portas publicadas. Rotas e redes existentes precisam estar sem sobreposição observada. |
| Servidor | `172.30.88.2:8443`, UID/GID10001, modo identity-only, allowlist vazia e somente GET de identidade. Três binds RO: chave/certificado do servidor candidato e CA cliente candidata. |
| Cliente | `172.30.88.3`, processo Python fixo e stdin privado sem TTY. Quatro binds RO: CA servidor/certificado/chave cliente candidatos e somente CA servidor antiga pública. |

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
   código atual. O build histórico disponível está registrado na
   [evidência da imagem](../../docs/evidence/identity-image-2026-10-30/README.md);
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

CLI opt-in, revisão histórica dos recibos e escopo operacional final, seguidos de
autorização específica e um único ensaio nativo. Não usar imports Python manuais
para contornar essa preparação. A ativação real de PKI/binding permanece uma etapa
separada e precisa também de imagem de aplicação atual, plano e aprovação próprios.

Consulte o [checkpoint](../../docs/PROGRESS.md), o
[ADR0030](../../docs/architecture/decisions/0030-runner-identity-only.md) e a
[preparação da rotação](../../docs/operations/runner-pki-activation.md).
