# Entrega #7 — checkpoint da preparação #58 em13/11/2026

**Aberta/bloqueada para ensaio nativo.** Trabalhar somente #58→#59→#60, sem
avançar a outras features. Dependências#5/#6 fechadas, autorizações consumidas.
O [pacote de revisão](../../labs/wazuh/CYCLE-ASSAY.md) fixa versões/digests,
regra/agente/TLS/ACL/política/observer, diferenças históricas e efeito único.

Entregue: transição offline explícita do runner Wazuh legado172.30.89.2 para
192.168.253.10, preservando três IDs e origem. `runner_pki.py` usa manifesto `/3`,
sem reinterpretar `/1`/`/2`; CLI/função recusam perfis errados e flags simultâneas.
Makefile/runbook atualizados,12novos casos de regressão. Sem ativação/PKI real nova.

Revisão host-only:
`.local/wazuh-cycle-review/d49fd387ef3b487eb8517285d4fbdecf/review.json`, SHA256
canônico`35f9a66f7129e35bf70cd250e4c02c2b4a743febe79504af8fb33710b713c839`,
observado em2026-11-13T12:33:04.439519Z. Inclui metadados de imagens/volumes,
inventários públicos, política e hashes dos artefatos históricos. Nenhuma chave
antiga, conteúdo de volume ou credencial publicado. Snapshot representa seus
arquivos no instante da observação; mudanças documentais posteriores são distintas.

- Última RAM disponível6.602.915.840bytes (~6,15GiB), ainda abaixo de8GiB.
  Primeira leitura4.924.940.288bytes; não afirmar gate aprovado com a melhora.
-20redes/61rotas, nenhuma sobreposição observada; nove volumes próprios e zero
  consumidores conferidos por filtro de volume, inclusive fora do projeto.
- Origem protegida no checkout antigo, ausente no checkout de trabalho atual.
  Certificados originais expirados/SAN legado; não preencher a ausência gerando
  identidades/senhas novas nem ativar candidatos consumidos da #6.
- Schema/backup/restore/grants/continuidade Wazuh permanecem desconhecidos por
  leitura de metadados. Não transferir resultados/autorização Linux para Wazuh.
- Harness de22/10 exige banco vazio/intent ausente e não serve para a retomada.
  Não apagar intent/execuções/journal ou alterar IDs para fazê-lo passar.

Testes efetivos: `make test-wazuh`:60passaram; `make test-wazuh-preparation`:
114+96passaram, em sequência; regressões PKI/geração/TLS/transições Linux e Wazuh:
80passaram. Conjuntos se sobrepõem; não somar como testes únicos. Primeiro target
Wazuh teve50pass/10erros por credenciais locais divergentes; reexecução completa
passou selecionando apenas no ambiente do processo as credenciais de dev já
existentes, sem mudar conta/grant/configuração. Aviso conhecido Starlette/httpx.
`make lint` completo passou. Hash/commit, staged/release e estado da CI constam
no comentário de#58/#7; não apresentar fixture/CI como ensaio/implantação.

Próxima intervenção proposta: diagnóstico/backup frio Wazuh e inventário em
clone isolado, sem original RW, migração, API/worker/Wazuh/runner ou marcador;
escopo concreto em CYCLE-ASSAY. Precisa de autorização específica antes do efeito.
Depois, resolver compatibilidade real e revisar o pacote integrado completo,
com recursos suficientes, candidatos vigentes e autorização própria da#59.
#59 e#60 permanecem pendentes por ordem técnica. Não houve nova campanha,
evidência defensiva, captura de UI, implantação ou alteração de qasrc/volumes.

## Diagnóstico e backup especificamente autorizados

Após o usuário responder **“autorizo”** à proposta de diagnóstico/backup frio e
restore isolado, a etapa foi executada e encerrada. Resultado final
**VERIFIED_AFTER_RECONCILIATION/CLEANED**; [relatório verificável](../evidence/wazuh-database-2026-11-13/README.md).
Original montado RO/nocopy somente para uma cópia fria; nunca iniciado/migrado.
As continuações trabalharam apenas com clones existentes. Nenhum journal aberto.

- A cópia revelou schema **4b72c7bb8548/29tabelas**, e não o d446 do backup Linux.
  Dados das29tabelas, contas/verificadores, ACLs e demais definições preservados.
- Backup físico51.673.168bytes/1.451entradas, inventárioSHA256
  `f93cd36d483a25d30b2df11bce97dd331aaba1fb6bf8fb2ae33ce9d128a05085`.
  Dump PG17:407.077bytes, SHA256
  `18d356ce243a793636c3917db46ff1bff3047acfb9af49f27b8d7d64d2047406`.
- Interrupções por consulta incorreta de catálogo e, depois, diferença textual
  de casts de quatro constraints foram preservadas. Consulta corrigida para
  pg_db_role_setting;23comparações SQL e reconhecimento estrito das expressões
  confirmaram equivalência. Nenhum dado/constraint reescrito e nenhum restore
  refeito para obter aceite. Recibos e inventários brutos mantidos separadamente.
- Recibo final718bf2b95e0340019e32f4f92ef43968, SHA256 canônico
  `022b807c120b7c7f3faabafecf214e60dc58555019942d627dafc946a48afaed`.
  Zero containers dos quatro projetos; zero consumidores originais/clones.
  Nove volumes originais, backup frio, cópia de trabalho e restore preservados.
- RAM final~6,57GiB: **integrado continua bloqueado pelo mínimo8GiB**.
  A etapa sequencial384MiB não valida recursos para o stack integrado.
- CI344b012 aprovada: [quatro jobs Python e React](https://github.com/Buraddomoon/AEGIS/actions/runs/43426260585),
  [source-review](https://github.com/Buraddomoon/AEGIS/actions/runs/43426260609).

A autorização de diagnóstico foi utilizada; não incluiu migração em clone ou
original, grants, seed, contas, binding, PKI, Wazuh/runner/observador/API/worker ou
marcador. Próxima etapa técnica: propor upgrade4b72→b7 em clone e conferir a
preservação antes de qualquer intervenção original. Nenhuma migração feita.
#58/#59/#60 e pai#7 permanecem abertos. Parar no escopo aprovado até liberar
requisitos específicos; não iniciar outra entrega.

Proposta offline da próxima etapa, ainda não autorizada:
`8468ae93bc934550a10d7bf180f7fa36`, SHA256 canônico
`3c7db2a52533a6b8448d5210a28aaddfa3f7dddcaed625a7e8207e994ba6ee45`,
host-only em `.local/wazuh-schema-upgrade`. Define novo clone do backup frio,
PG384MiB+helper384MiB, socket Unix privado, imagem/migrações/grants fixados,
upgrade4b72→b7 e comparação integral. Nenhum efeito executado, original montado,
PKI, catálogo publicado ou marcador. Escopo revisável ao final de CYCLE-ASSAY.
