# Diagnóstico e backup Wazuh — 13/11/2026, #58/#7

**VERIFIED_AFTER_RECONCILIATION / CLEANED.** Sob autorização específica do usuário
ao escopo em [CYCLE-ASSAY.md](../../../labs/wazuh/CYCLE-ASSAY.md), uma cópia fria do
PostgreSQL Wazuh foi preservada e um dump foi restaurado em clone isolado.
O original não foi iniciado nem migrado. Nenhum marcador ou Wazuh foi executado.

## Escopo realizado e origem conhecida

Original: `aegis-wazuh-lab_postgres-data`. Nove volumes próprios sem consumidores
antes da operação. Somente esse volume foi montado, **RO/nocopy**, por helper
UID70 sem rede, root filesystem RO, caps removidas e no-new-privileges. O helper
leu arquivos físicos e conferiu hashes/owners/modos/mtimes antes/depois da cópia.
Journal e demais volumes originais receberam somente inspeção de metadados.

Imagem PostgreSQL17/amd64 existente:
`sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24`.
Helper Python existente:
`sha256:b5ae5340f417ef3fce7ce25f8ec07d2dd92545b3a34d6db1982ac37fb108c593`.
Sem pull/build, redes novas, portas publicadas ou alteração de terceiros.
PostgreSQL apenas em clones próprios,384MiB/0,75CPU/48PIDs, sem swap adicional,
network=none. Helpers de cópia/inicialização também limitados, em sequência.

**A cópia byte a byte revelou revisão `4b72c7bb8548`,29tabelas com Alembic.**
Não é o schema d446 do backup Linux nem o b7 atual da aplicação. Essa conclusão
vem da cadeia cópia física idêntica→SQL no clone; não de startup do original.
Há uma campanha/run/teste históricos, uma aprovação, um receipt/dispatch/cleanup,
uma coleta/evento/evidência Wazuh e706entradas ATT&CK. A contagem do catálogo não
significa técnicas avaliadas; não houve nova avaliação de detecção nesta operação.
Todos os hashes de linhas de todas as29tabelas foram comparados na restauração.

## Artefatos protegidos e integridade

Backup físico:51.673.168bytes,1.451entradas. Inventários de origem, backup e cópia
de trabalho idênticos antes de iniciar qualquer PostgreSQL no clone:
SHA256`f93cd36d483a25d30b2df11bce97dd331aaba1fb6bf8fb2ae33ce9d128a05085`.
O backup frio foi novamente lido após a reconciliação, conservando esse hash.
Conteúdo físico dos clones iniciados pode mudar por operação normal do PostgreSQL.

Dump custom PG17:407.077bytes, SHA256 dos bytes
`18d356ce243a793636c3917db46ff1bff3047acfb9af49f27b8d7d64d2047406`.
Dump/globals, senhas/verificadores, inventários e saídas SQL ficam host-only em
diretórios0700/arquivos0600, sem upload. Configurações bind individuais0444 ficam
protegidas pelo diretório host0700. Nenhum desses arquivos foi adicionado ao Git.

| Inventário JSON canônico | SHA256 |
|---|---|
| Antes do dump | `8e076899d9c90040fa4dabd7df8e1ba898b2d20db60ff582f05c09d2aea48dcf` |
| Restore, representação textual original | `9cc07855e2d18f2599cf83c799d039b74eebce38f7f8303790d1da1062d13bd5` |
| Restore, comparação semântica restrita abaixo | `8e076899d9c90040fa4dabd7df8e1ba898b2d20db60ff582f05c09d2aea48dcf` |

JSON canônico: UTF-8 de `json.dumps(value, sort_keys=True, separators=(",", ":"))`,
sem newline. Hash identifica conteúdo; não é assinatura nem autorização.

## Interrupções e reconciliação preservadas

A primeira etapa completou as duas cópias, mas não concluiu o inventário SQL.
Encerramento confirmado; backup e cópia de trabalho retidos. A continuação nos
clones capturou o erro: a consulta usava `rolconfig`, ausente em `pg_authid` no
PG17. Foi corrigida para ler `pg_db_role_setting`. A primeira etapa não preservou
o erro SQL detalhado; não se atribui retroativamente sua causa com certeza.

As continuações usaram socket Unix restrito aos clones, sem listener TCP, HBA
local apenas para o owner e nenhum acesso externo. Isso não altera credenciais
armazenadas nem comprova autenticação/RBAC da aplicação. O restore inicializou
owner com o mesmo nome `aegis`; o CREATE ROLE desse bootstrap foi omitido da
entrada de globals **somente no clone**, mantendo os ALTERs e verificadores
originais. Globals original e entrada derivada foram preservados separadamente.

O restore ocorreu uma vez e preservou dados/colunas/contas/verificadores de senha,
ACLs/owners, índices, triggers, funções, extensões e schemas. A comparação textual
recusou quatro diferenças entre as109constraints: PostgreSQL decompôs casts de
arrays `varchar[]→text[]` em casts de cada literal `varchar→text`.

| Constraint CHECK | Casos SQL de equivalência |
|---|---:|
| schedule_occurrences.status | 5 |
| schedules.state | 9 |
| test_definitions.execution_kind | 4 |
| users.role | 5 |

A reconciliação aceitou somente o padrão exato `coluna::text = ANY` com a mesma
lista de literais varchar, mudando apenas a posição do cast. Recusa qualquer
outra expressão/literal/identidade/diferença. No clone restaurado em READ ONLY,
**23comparações SQL passaram**: cada literal, NULL e um valor fora do conjunto.
O reconhecimento da expressão literal dá a equivalência para os demais valores
fora do conjunto. Não houve alteração de constraints/dados para fazer o check
passar; os dois inventários brutos e as recusas anteriores continuam intactos.

| Etapa host-only | Resultado preservado | SHA256 canônico do recibo |
|---|---|---|
| 6fd466f0fc3d46ba83cf8741222e8e24 | diagnostic_unconfirmed/CLEANED | `241edb05389ffce60aa482c7a0948ee81896acd2c59d7f44ff7917c6f13eaf7a` |
| e986fb2951cb4f4ab34ac447da023093 | continuation_unconfirmed/CLEANED | `a885a758d7235add7681e47497ca5388a1738caa76579d02b0cb25f75b86debf` |
| 116fe767f9f64765bf97015e13708ff1 | restore_inventory_mismatch/CLEANED | `0313de42e0811030aa10157de11a28fdc17f8be6fe80d9743f3d35a41fce11f4` |
| 718bf2b95e0340019e32f4f92ef43968 | VERIFIED_AFTER_RECONCILIATION/CLEANED | `022b807c120b7c7f3faabafecf214e60dc58555019942d627dafc946a48afaed` |

As etapas posteriores retomaram apenas cópias existentes; original não remontado,
cópia fria não repetida, restore não refeito. Diretórios, operadores congelados,
intents/ledgers e outcomes ficam em `.local/wazuh-schema-clones`, preservados.
O recibo final em bytes tem SHA256
`d51dc54771fce316b7f13cd0fb547900744763e43d6714d339c50abc1df66a0c`.

## Encerramento e limites

Zero containers dos quatro projetos de diagnóstico; zero consumidores dos nove
volumes originais e dos três volumes próprios retidos. Metadados originais
preservados; backup frio, working-copy e restored-copy retidos. Nenhuma migração
em original ou clone. Original sem seed ou alteração de grants, senha, conta,
binding ou aprovação. Nos clones, roles/ACLs/dados vieram da restauração verificada.
Sem API/worker/runner/observador/Wazuh, marcador ou alerta novo. A autorização de
diagnóstico/backup foi utilizada neste escopo, sem autorizar operação permanente.

Preflight integrado após cleanup:16CPUs, MemAvailable7.048.957.952bytes (~6,57GiB),
Docker livre417.297.952.768bytes, max_map_count1048576. **Gate de8GiB ainda recusado.**
Não parar terceiros nem contar swap para passar. O diagnóstico sequencial de
384MiB é distinto do stack integrado de~7,03GiB.

Próximo requisito técnico da#58: ensaiar explicitamente o upgrade
4b72→b7/33tabelas e grants em clone separado, com comparação das colunas antigas,
novas tabelas vazias e preservação de contas/histórico. Essa migração não foi
autorizada nesta etapa. Original continua4b72; não executar API/worker atuais nem
o serviço genérico `migrate` sobre ele. Eventual intervenção original, PKI/
continuidade, pacote integrado e marcador exigem escopos próprios. #58 permanece
aberta; #59/#60 dependem dela. Este relatório não é o ensaio defensivo pedido#59.

Fonte executável da preparação:344b012, [CI integral aprovada](https://github.com/Buraddomoon/AEGIS/actions/runs/43426260585),
quatro jobs Python e React; [revisão de fonte aprovada](https://github.com/Buraddomoon/AEGIS/actions/runs/43426260609).
Essa CI não comprova a operação nativa; os recibos acima registram a operação.
