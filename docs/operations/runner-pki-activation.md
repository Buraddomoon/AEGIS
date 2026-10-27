# Troca coordenada da PKI do runner — plano, sem execução autorizada

Este documento prepara a revisão de uma intervenção futura. Nenhum comando de
ativação ou ensaio foi executado neste incremento. As autorizações de outubro21/22
continuam consumidas. A ferramenta atual oferece somente inspect/prepare/verify.
Este plano não é um executor e não recebe uma aprovação pelo simples merge/push.

## Perfil inicial delimitado

Priorizar o Linux integrado, projeto **aegis-linux-lab**, API loopback18785,
runner172.30.88.2, arquivos Compose root → linux/compose.yml → linux/platform.yml.
Não iniciar simultaneamente standalone/integrado com os mesmos IDs/volume.
Demo18780 e Wazuh ficam fora da intervenção. Primeiro ensaio deve verificar
confiança/identidade/diário **sem criar marcador**, sem nova campanha/start.

Origem pública existente: `.local/linux-lab`. Candidato offline atualmente
preparado: `.local/pki-candidates/90204499ca2144aca175fe809538b7e7`;
manifestoSHA256 `24179f34ad0a2c708496e9b0b3798a18d547c4648975c95893330458f0ed8d5f`.
Descritor candidato `d1b616e115fecdf115652472656b4a82e6cd1c65f45b778f0239a2b4afbd566f`.
Esses hashes identificam uma preparação; sua validade não é permanente. Reverificar
material/tempo real imediatamente antes da revisão/uso. Se não houver>=24h nas
folhas, preparar outro candidato e atualizar o escopo/hash; não reutilizar recibo.

Volumes esperados: `aegis-linux-lab_journal` e
`aegis-linux-lab_postgres-data`, observados presentes sem containers em2026-10-27.
Nomes presentes não comprovam conteúdo/labels/mounts/integridade. A intervenção
deve verificar esses vínculos antes de criar qualquer recurso; volume ausente ou
ambíguo aborta, sem criação substituta. Não transportar o diário para outro runner.

## Troca dos arquivos montados

Todos os arquivos da tabela vêm **do mesmo candidato verificado**. Preservar o
connection.json, IDs, endpoint e nomes dos secrets internos; mudar somente a
origem host revisada em AEGIS_LAB_CONFIG_DIR. Não sobrescrever o diretório antigo,
concatenar raízes ou acrescentar confiança antiga para facilitar a transição.

| Serviço | Secret | Arquivo candidato |
|---|---|---|
| runner | runner_server_key | runner-server.key |
| runner | runner_server_cert | runner-server.crt |
| runner | runner_client_ca | client-ca.crt |
| API/worker/controller | controller_server_ca | server-ca.crt |
| API/worker/controller | controller_client_cert | runner-client.crt |
| API/worker/controller | controller_client_key | runner-client.key |
| API/worker/controller | controller_connection | connection.json |

Chaves das CAs, CSRs, manifests e diretório inteiro não entram nos containers.
Compose monta secrets por arquivo; parar/recriar os consumidores necessários é
parte da troca. `restart` não aplica uma configuração Compose alterada. Uma troca
parcial deve falhar mTLS, sem verify=false ou confiança dupla como fallback.
[Secrets](https://docs.docker.com/compose/how-tos/use-secrets/),
[recriação](https://docs.docker.com/reference/cli/docker/compose/up/),
[limites de restart](https://docs.docker.com/reference/cli/docker/compose/restart/).

Os targets Make atuais ainda selecionam o ids.env original. **Não usar up/smoke
como executor de rotação.** Falta implementar um harness de ativação com hash e
perfil exatos, ambiente saneado, inventário/guardas e fechamento no finally.
Não sobrepor lab.env Wazuh com ids.env Linux: os projetos têm PKIs/segredos distintos.

## Ordem e pontos de interrupção

1. Revisar escopo humano, imagens locais por ID, manifesto atual, IDs, labels e
   volumes; material original e histórico permanecem preservados. Registrar
   hashes públicos/configuração e identidade do ambiente; não imprimir segredos.
2. Consultar o banco **próprio do Linux Lab**, sob procedimento autorizado,
   comprovar laboratório revogado e ausência de reservas/pais/filhos pendentes.
   Aplicar a [revisão persistida](linux-binding-review.md) e verificar o diário
   original. Nunca deduzir o estado do Linux a partir do banco Demo.
3. Dispatch/efeito ambíguo interrompe a rotação operacional. Recuperação sob
   descritor alterado ainda não está implementada: manter quarentena, sem start,
   replay, exclusão de intent/journal ou liberação manual de reserva.
4. Com processos de execução parados e pré-condições comprovadas, recriar os
   consumidores mTLS sob o candidato aprovado, preservando volume/identidade.
   API administrativa pode ser necessária para revisão; worker deve permanecer
   parado até encerrar todos os gates. Não chamar migrate/seed/smoke implicitamente.
5. Verificar isolamento real, mounts exatos, UID/limites e integridade/continuidade
   do diário. Provar mTLS/identidade sem preparar/start/marker. Conferir recusa de
   trust/cliente antigos sem atribuir ao trust um erro causado apenas por expiração.
6. Registrar o binding Linux novo explicitamente; confirmar incremento da versão,
   invalidade de preflight/escopos anteriores e laboratório ainda revogado. Novo
   preflight mTLS não autoriza execução. Binding Wazuh só se houver escopo separado.
7. Encerrar os serviços/redes próprios, contas temporárias e quaisquer recursos
   efêmeros; preservar os dois volumes, material original/candidato e evidências.
   Conferir ausência de marcador/start e não declarar operação normal liberada.

Falha em qualquer gate impede avançar. Não retornar ao trust antigo para contornar
um bloqueio; manter o laboratório revogado/parado e os artefatos para investigação.
Sem remoção de volumes, expurgo, replay, upload, alterações de rede/sysctl ou
parada de serviços de terceiros. Recurso criado pelo ensaio futuro precisa de
intent durável, nome/label exatos e cleanup verificável; dúvida no fechamento
retém dependências e impede recibo de sucesso.

## Fora deste ensaio futuro

Não executar novo marcador nem campanha, não iniciar Wazuh, não rotacionar PKI do
Indexer/manager/agente/Filebeat, não migrar host nem trocar credenciais humanas.
Uma campanha posterior exige outro escopo/solicitação/aprovação separada. Prova
de handshake/diário não é evidência de detecção, ingestão SIEM ou retomada segura.

Estado atual: plano e guardas do backend disponíveis; harness de ativação,
inspeção do banco/diário Linux parado e ensaio específico continuam pendentes.
