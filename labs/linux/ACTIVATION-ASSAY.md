# Ensaio de ativação — issue4

Ensaio nativo concluído em12/11/2026: **native_rotation_verified_and_closed**.
Binding revogado, preflight atual e continuidade antes/depois confirmados;
recursos próprios ausentes, conta temporária desativada e intents fechados.
O [relatório do ensaio](ROTATION-2026-11-12.md) fixa fontes, hashes e limites.
Essa autorização de uso único foi consumida; o documento não autoriza replay.

## Dependências entregues

1. #48: backup frio real RO/nocopy, restore e upgrade somente em clones,
   comparação de dados/contas/ACLs e grants mínimos. O inventário real corrigiu
   a hipótese a0: original d446/27tabelas; clone atualizado b7/33tabelas. Ver
   [compatibilidade](../../docs/operations/linux-schema-compatibility.md).
2. #49: executor concreto, SQL/diário, gates físicos de runtime/mounts/ownership,
   intent antes de efeito, prazo fixo e cleanup sem replay. Perfil v3 fechado
   para d446, sem API normal/worker/migração. Ver
   [coordenador nativo](../../docs/operations/runner-native-rotation.md).
3. #50: registro transacional revogado, revisão repetida sob lock, preflight
   separado e sensível a drift, fingerprints na UI. Implementação/testes de UI
   não implicam deploy do Demo; binding/preflight reais foram verificados no ensaio.
4. #51: execução nativa autorizada e concluída com evidência privada antes/depois,
   uma prova histórica, ambiente2→3, diário idêntico, cleanup e conta desativada.

## Preparar uma intervenção futura

A CLI antiga `runner_activation.py` mantém somente plan/recheck; seu plano não
concede autorização executável. `runner_rotation.py` exige pacote próprio,
evidência real do clone, imagens e candidato vigentes, código limpo e revisão
física. Nunca rehashar pacote antigo ou remover fence para liberar efeito.

Fixar o schema real e os entrypoints compatíveis. Não trocar uma imagem geral
sobre d446/a0, executar Compose migrate/seed/bootstrap, alterar grants ou senha
existente para fazer gates passarem. As receitas atuais usam somente os cinco
helpers administrativos d446; um clone b7 não migra o original.

O registro exige administrador ativo. Neste ensaio, as três contas originais
estavam inativas; o usuário autorizou separadamente uma única conta temporária,
SQL de criação/desativação foi testado em clone novo e o encerramento confirmou
zero sessões e hashes antigos inalterados. Não reativar contas históricas nem
provisionar contas como consequência automática de um plan/prepare.

Antes de efeitos: PKI candidata verificada, fonte antiga preservada, imagens por
ID/fonte selada, proveniência PostgreSQL, plano/pacote vigentes, hash aprovado,
projeto vazio, consumidores/rotas/subnets revistos e fence exclusivo durável.
Somente bridge interna isolada192.168.253.0/29, SQL loopback e secrets RO
individuais. Nada de portas host, API normal, worker, campanha, marker ou Wazuh.

## Resultado exigido e falhas

Revisões SQL e WAL-aware do diário antes/depois, identidade mTLS nova, recusa da
CA anterior por erro de cadeia, binding revogado com versão+1 e preflight atual.
EOF/expiração não comprovam recusa de trust. Não contatar jobs, gerar marcadores
ou transformar handshake/recibo em evidência defensiva.

Falha/ambiguidade bloqueia efeito e conserva reserva/intent. Retomada é somente
cleanup próprio por IDs/labels históricos, sem renovar prazo ou repetir fases.
Não remover dependentes, volumes, imagens, PKI, backups, journals ou fences para
obter replay. Conferir ausência física e encerramento real antes de fechar.

O controle com chave privada do cliente antigo continua fora deste ensaio;
previous_client_rejection_verified/all_tls_controls_verified permanecemfalse.
Autorização normal ou uma campanha futura exige escopo próprio.
