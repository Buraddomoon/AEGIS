# Checkpoint da issue4 — 11/11/2026

Escopo: #4 e seus quatro filhos nativos, sem descendentes adicionais. #3 fechada.
Trabalho em `/home/IVPTER/AEGIS`, main com push direto; os cinco arquivos da outra
cópia `/home/IVPTER/codes/aegis` permanecem intactos.

## Estado atual

| Issue | Evidência e pendência |
|---|---|
| #48 | Backup frio real, restore/upgrade em clone e grants verificados; versão real d446/27tabelas, corrigindo inventário a0 anterior |
| #49 | Núcleo, executor concreto e perfil fechado v3/d446 implementados/testados; aguardar CI final |
| #50 | API/UI concluídas e issue fechada; registro mantém revogação e preflight separado |
| #51 | Preparação em andamento; falta executar e revisar ensaio nativo com pacote próprio |
| #4 | Aberta até aceite do conjunto, sem avançar para outra entrega |

## Evidência real da #48

Autorização desta conversa após apresentar o escopo de cópia read-only e clones.
O original `aegis-linux-lab_postgres-data` foi montado somente RO/nocopy por um
helper sem rede. Cópia fria51.434.896bytes/1.439entradas, inventários fonte e
backup idênticos. Original nunca iniciou PostgreSQL nem recebeu migração.
Journal original não foi montado nessa etapa.

A revisão real encontrou `d4465b7aca2a`,27tabelas, em vez de a0 presumido.
Dump custom PG17 privado397.998bytes, SHA256
`4ef1bc67cdb7013198c76890685eab8f59785683226aa32b001900379ef5e969`.
Restore preservou todas as linhas/colunas, contas, verificadores e ACLs efetivas.
Upgrade explícito somente no clone para b7/33tabelas, `alembic check`, seis novas
tabelas vazias e todas as colunas/valores antigos preservados. Grants mínimos
verificados somente no clone, sem alteração de senha.

Evidência canônica SHA256
`f6ded75cdfe08dbdc3d24d439681babd749869d0dda44d0d1209bbd11da2635a`.
Recibo privado em `.local/linux-schema-clones/1947140a2cd4411d81b9e686ff21358c`;
dump/globals em bce29bd182564212ad88173d4b9fe61f. Preparações intermediárias
falharam de forma fechada (normalização CAP_CHOWN, hipótese de schema, bootstrap
PG/ACL e envelope stdout Alembic). Ledgers/volumes preservados; nenhuma nova cópia
do original após a primeira cópia verificada. Cleanup final comprovado, intents
fechados, ambos originais sem consumidores. Ver
[compatibilidade](../operations/linux-schema-compatibility.md).

## Código e verificações

Commits anteriores sincronizados: df5f5ef,9f31e48,c99e14d,8399ad3,19c9eec,
54f61b0,295b8b8,5e91afc,0c08332. O complemento atual fixa pacote/perfil v3/d446,
sem API normal, worker ou migração. Pacotes v1/b7 e v2/a0 só permitem cleanup
histórico, sem conversão de escopo. Imagem de fonte0c08332 foi apenas preparada,
ainda não construída; preparar nova fonte após commit do perfil real.

PG/Redis15 sequenciais, credenciais existentes fornecidas somente ao processo;
`.env` da cópia ativa desatualizado não foi alterado/resetado.

- Executor sobre schema d446 descartável: **44passed/101,69s**, inclui recusa de
  a0/b7; mais **2casos distintos** de cleanup histórico v1/v2 no grupo seguinte.
- Compatibilidade4casos (a0, d446, dump/restore, grants) e os2casos de cleanup
  anteriores: **6passed/7,40s**, dump local executado, sem skips.
- Rodada anterior a0:43passed/94,63s, substituída pelo perfil d446 real.
- Grupos anteriores:239passaram no complemento nativo; núcleo70, binding72,
  PKI/TLS/continuidade229 e React91. Há sobreposição: não somar essas rodadas.
- CI19c9eec: [43091653314](https://github.com/Buraddomoon/AEGIS/actions/runs/43091653314)
  SUCCESS, quatro Python e React conferidos,3120Python/9skips,91React.
- CI5e91afc43099786692 falhou em3casos nativos por introspecção do schema de
  fixture; corrigido em0c08332. A CI do perfil atual ainda precisa ser conferida
  integralmente, sem filtros ou exclusões adicionais.

## Próximo passo dentro da #4

Preparar build revisado da fonte atual, PKI candidata nova e plano/pacote nativo
com prova real de clone. Não reaproveitar candidatos/autorizações expirados.
Executar apenas o procedimento delimitado de identidade, binding revogado,
preflight, continuidade e cleanup, sem marker/campanha/Wazuh/operação normal.
Preservar PKI, qasrc, volumes, imagens, backups e fences; nunca repetir efeito
ambíguo ou limpar uma reserva para obter nova tentativa. Ver
[executor](../operations/runner-native-rotation.md) e
[ensaio](../../labs/linux/ACTIVATION-ASSAY.md).
