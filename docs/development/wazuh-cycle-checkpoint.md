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
