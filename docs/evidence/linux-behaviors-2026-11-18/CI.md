# CI integral da preparação Linux — #81/#82

[Validate AEGIS44313563809](https://github.com/Buraddomoon/AEGIS/actions/runs/44313563809)
concluída SUCCESS em18/11/2026. Fonte exata:
`9e614cb829cccaa70b21ff7a286418a5482fa771`.
Os cinco jobs foram conferidos por metadados e resumos dos logs completos.

| Job | Passed | Skipped | Selecionados | Tempo pytest |
| --- | ---: | ---: | ---: | --- |
| Python0 | 937 | 2 | 939 | 129,44s |
| Python1 | 869 | 2 | 871 | 277,59s |
| Python2 | 973 | 1 | 974 | 234,50s |
| Python3 | 924 | 4 | 928 | 205,63s |
| Total Python | 3703 | 9 | 3712 | Rodadas paralelas em jobs isolados |
| React | 98 | 0 | 98 | 16arquivos |

Partições complementares pelo mecanismo existente: nenhum filtro, exclusão,
relaxamento, alteração de SHARDS/PINNED ou aumento de timeout/max-parallel.
Os deselected de cada job são as demais partições, não testes omitidos da união.
Lint/tipos/formatação/build e auditorias previstas no workflow passaram.
O aviso upstream de Starlette/TestClient-httpx continua visível.

Nove skips nativos opcionais, sem criação de recursos para passar gates:

- Grupo0: projeção opt-in de metadados de imagem (1) e DemoAPI ausente (1).
- Grupo1: ferramentas do PostgreSQL de desenvolvimento ausentes (1) e DemoDB
  ausente (1).
- Grupo2: rede Demo existente ausente (1).
- Grupo3: objetos próprios do Demo ausentes para inspeção Wazuh (4).

[Review AEGIS source delivery44313563738](https://github.com/Buraddomoon/AEGIS/actions/runs/44313563738)
também SUCCESS na mesma fonte. É revisão documental/de fonte, distinta da CI de
execução acima. A primeira rodada44312253261 teve dois asserts antigos de
inventário falhos e acabou CANCELLED pelo push corretivo; detalhes e correção24passed
preservados em [PREPARATION](PREPARATION.md). Não somar passagens das duas rodadas.

Commits técnicos enviados: `07d7211` (especificação), `1831dcc` (implementação)
e `9e614cb` (regressões de inventário). A consolidação final muda apenas Markdown;
inputs de runtime/testes/build/CI permanecem idênticos à fonte validada. Último
hash/mensagem e sincronização constam dos comentários finais das issues.

Esta CI usa fixtures, temporários, PG/Redis descartáveis e loopback. Não prova
implantação, sensor defensivo ou ensaio nativo. Nenhum laboratório foi iniciado
nesta entrega; #83 exige novo pacote/autorização humana e permanece bloqueada.
#15 fica aberta até ensaio/aceite conjunto. Nenhuma autorização consumida foi
reutilizada, e recibos não foram convertidos em evidências defensivas.
