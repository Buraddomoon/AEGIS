# Proposta concreta para uma campanha —#59/#60

**Ainda não autorizada nem executada.** A [preparação#58](../../docs/evidence/wazuh-cycle-2026-11-16/BOUNDED-READINESS.md)
confirmou prontidão real com a memória disponível; seus dois pacotes foram
encerrados e não são o pacote desta campanha.

Novo pacote privado `9f60b4c8d7154babaca1e6271b110683`, Compose/PKI SHA256
`5ae34818255f7f9f1af408ca61419a29a61cae19748d8b6c30123e2d345dd32b`.
Proposta host-only em `.local/wazuh-single-campaign`, SHA256
`bfe8a3df1ad60feed480abdf299304af3f9a2fe0928026a1b7e3bcd585e1f498`.
Pacote preparado/rechecado sem efeitos. Credenciais novas geradas somente em
arquivo0600/diretório0700; nenhuma conta inserida no banco.
Código operacional existente: preparação/inspeção, revisão de continuidade em
processo, registro controlado e `wazuh_cycle_assay.run_once`.

## Efeitos e limites a aprovar

1. Revalidar fonte34c8093 (mudanças posteriores somente documentais), sete IDs
   locais de imagens do relatório, configuração original, PKI vigente,
   nove volumes sem consumidores, redes sem colisão e recursos reais. Nenhum
   build/pull, instalação, sysctl, migração, seed ou reset de senha.
2. Fazer backup frio **novo**, antes do banco: original postgres-dataRO/nocopy,
   helper128MiB/sem rede, imagem de cópia
   `sha256:b5ae5340f417ef3fce7ce25f8ec07d2dd92545b3a34d6db1982ac37fb108c593`.
   Destino `aegis-wazuh-campaign-9f60b4c8d715-cold-backup`. Exigir inventários
   idênticos origem antes/depois e cópia; manter todos os backups. Nenhum restore
   sobre original.
3. Iniciar DB256MiB e helper256MiB da imagem de aplicação já revisada, antes dos
   demais serviços. Helper UID10001/rootFSRO, journal originalRO/nocopy, conexão
   somente ao banco original por namespace do DB, senha só stdin. Repetir provas
   SQL independentes/journal antes de renovar o binding **atual**, mediante
   `activation_review.collect` e `require_current` na transação de registro.
   Descriptor antigo `095a23848c401a6ef798ccddbb7b3a327d8e19ec4daa85da32d6d442488cb0ea`
   →novo `cbaf88fc1ab6b1bfdfeec61fe834a2cc9dcf518723649913c41edaecb3c7d753`.
   Ambiente3→4 nesse registro, lab ainda revogado. Preservar todos os scopes,
   receipts, approvals e cleanups históricos; nenhum ID novo de lab/ativo/runner.
4. Criar somente duas contas exclusivas novas: administrador e operador
   distintos, nomes terminando `9f60b4c8d715`, senha Argon2 e auditoria.
   Não reativar nem alterar contas anteriores. Encerra-se o helper antes dos
   outros oito serviços; pico configurado permanece3360MiB, mais512MiB de reserva.
5. Subir o perfil já exercitado `bounded-3360m/1`: heap512MiB, sem swap adicional,
   API somente127.0.0.1:18786, redes/volumes/imagens fixos e qasrc preservada.
   Revalidar182checks, mTLS, TLS/ACL efetiva, Filebeat, regra/agente/observador,
   histórico/intent e estado ocioso. Probes na API existente, sem outro IP `/29`.
6. Operador solicita **uma** campanha/uma run/um teste. Administrador diferente
   aprova o scope novo por2min, duração até120s. Somente
   `linux-file-marker/v1`, arquivo benigno43bytes, filho até5s, regra100200;
   zero técnicas ATT&CK. Intent e dispatch duráveis antes de um único start.
   Sem retry do marcador, inclusive em resposta ambígua.
7. Capturar alerta original `_index`/`_id`/`_source`, observação independente,
   execução/cleanup e hashes. DETECTED somente com correlação real completa;
   manter resultado proporcional se incompleto. Depois conferir **a mesma run**
   na UI/JSON/HTML/PDF por leitura, sem campanha extra para screenshots ou comparação.
8. Revogar lab, confirmar cleanup físico/workspace vazio, desativar somente as
   duas contas novas e remover suas sessões. Se cleanup ambíguo, preservar acesso
   de recuperação e investigar a tentativa original, sem repetir o efeito.
   Encerrar somente containers/redes próprios; reter nove volumes, backups,
   PKI, logs, intents/fences e imagens. O supervisor interrompe em pouca memória,
   OOM/saída inesperada; nenhum aplicativo de terceiros será fechado.

PKI vigente é a separada já verificada na prontidão: runnerb37eb940 e serviços
00b37f26, manifestos completos no relatório. IDs preservados:
lab`cbf6e0ec-962c-450e-861e-ba7a313c2a5a`,
ativo`40ba5412-0034-4096-b88f-78a2ccdb789a`,
runner`3fa6fd77-e493-4d3d-b85d-aff08cb0e356`. Política original: agente001,
regra100200, aegis-json/1, data.aegis, janela/espera60s, poll2s, timeout3s,
skew5s e sem archives. Nenhum encaminhamento para SIEM de terceiros.

O pedido de tentar com menos RAM autorizou a prontidão já encerrada. A campanha
acima acrescenta binding/contas/efeito único e exige autorização específica
conforme [AGENTS.md](../../AGENTS.md). Proposta/hash não são autorização nem
assinatura; qualquer gate vencido interrompe antes do efeito.
