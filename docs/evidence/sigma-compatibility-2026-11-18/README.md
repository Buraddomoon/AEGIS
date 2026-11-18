# Pesquisa de compatibilidade Sigma — #84 / entrega #16

Revisão em18/11/2026, iniciada às16:47:26UTC. Fonte de partida:
`1a9022fd4db6a517ac36094ddb7f77ca2c5e6fc3` em main, árvore limpa e igual ao remoto.
Somente pesquisa offline e regressões locais; nenhuma conversão implementada,
consulta ao SIEM, instalação de backend, implantação ou laboratório iniciado.

## Fontes e matriz

Consultados os JSON oficiais de
[pySigma](https://pypi.org/pypi/pysigma/json),
[OpenSearch](https://pypi.org/pypi/pysigma-backend-opensearch/json) e
[Elasticsearch](https://pypi.org/pypi/pysigma-backend-elasticsearch/json).
As maiores versões com wheel não revogado, incluindo pré-releases no inventário,
eram respectivamente2.1.0,2.0.3 e2.1.1. Os catálogos tinham107/16/30versões;
isso é inventário na data, não inspeção de todos os wheels históricos.

Cada wheel selecionado foi baixado do URL do JSON versionado, conferido contra
`digests.sha256` e aberto como ZIP para ler METADATA e LICENSE, sem executá-lo.
Os requisitos abaixo são do wheel, não inferidos do main upstream.

| Core | OpenSearch2.0.3 | Elasticsearch2.1.1 | Resolução do trio / decisão |
| --- | --- | --- | --- |
| 2.0.1, runtime atual | exige>=1,<2 | exige>=1.4,<2 | exit1, ResolutionImpossible; manter bloqueado |
| 2.1.0, atualização candidata | exige>=1,<2 | exige>=1.4,<2 | exit1, ResolutionImpossible; upgrade não resolve |
| 1.5.1, controle comparativo | requisito satisfeito | requisito satisfeito | exit0,18wheels; downgrade vedado pelos ADRs0009/0017 |

OpenSearch também exige `pysigma-backend-elasticsearch>=2.0.0`. Requisitos de
Python dos wheels: core2.0.1/2.1.0 `>=3.11,<4.0`; core1.5.1 e ambos os backends
`>=3.10,<4.0`. Resolução realizada em CPython3.13.14/Linux x86_64, pip26.2.2.
Não foi validada uma instalação da aplicação em Python3.14.

| Distribuição / fonte versionada | SHA-256 wheel | SHA-256 METADATA |
| --- | --- | --- |
| [pySigma1.5.1](https://pypi.org/pypi/pysigma/1.5.1/json) | `1e6e080bde31db6039eb5d87d43322bf416534f30048091c65038e88225b8200` | `0002dbe5732e69232e19d1f098ca217d6a0fed6a4bb339c84673926b852b2e52` |
| [pySigma2.0.1](https://pypi.org/pypi/pysigma/2.0.1/json) | `7769a8f22177e732094312fb4c3a08f9fdd8af152a5905a4c549ff59dc7708e6` | `39c6a7791afe8cd212a772a56454309e4cc40a27c281c90768bf7561f1485cd4` |
| [pySigma2.1.0](https://pypi.org/pypi/pysigma/2.1.0/json) | `3495dcfff8aaefc81f9249a6ebdb3ef823ca84bfa32fa0a8f0ef0421049cced4` | `8aa8c3a1edfd440ff24487b4a9da74c349729fee7665c13c3b8b35bca1565a74` |
| [OpenSearch2.0.3](https://pypi.org/pypi/pysigma-backend-opensearch/2.0.3/json) | `bcb90e21207385fadb56ac5358242c86d32736a897289f2e0cb5d6949670e927` | `b656d697c82d05549a23f260c46a25396f2e8ad2746c936fd6a3febff49958e1` |
| [Elasticsearch2.1.1](https://pypi.org/pypi/pysigma-backend-elasticsearch/2.1.1/json) | `0bb514ae02445d2053d530bd732c8747ffac9184246d45f3fa2669d0862a5af4` | `0a0ee6aee8d9219e810b3bc1c0b7d58d76683a7c2cfbebf75270fc1a9e63954b` |

Licenças: os três cores declaram LGPL-2.1-only, com texto LICENSE LGPL2.1 e
hash `20c17d8b8c48a600800dfd14f95d5cb9ff47066a9641ddeab48dc54aec96e331`.
Ambos os backends declaram LGPL-3.0-only, texto LGPL3 e hash
`dc85c8df1d513788c34763e89e9585d60b9cdf7cda81c4e0a6afd59dba04dd45`.
Nenhum código ou wheel de backend foi adicionado ao repositório ou à distribuição.

Comparação de alterações transitivas: core2.1.0 troca
`diskcache>=5.6.3,<6` e `diskcache-stubs>=5.6.3` por
`diskcache-community>=5.8.3,<6`, e aumenta o mínimo de types-PyYAML de
`6.0.12.20260815` para `6.0.12.20261103`. Não houve instalação/import desse core,
auditoria dessa nova árvore ou alegação de correção do advisory atual.

## Repositório upstream versus distribuição publicada

Os pyprojects oficiais foram lidos em commits exatos:

- [OpenSearch950caeee](https://github.com/SigmaHQ/pySigma-backend-opensearch/blob/950caeee9284988e4f0a84710d09be4e6e5e51cb/pyproject.toml):
  declara core>=1.4,<2 e backend Elasticsearch>=2.1; o wheel tem mínimos1.0/2.0.
- [Elasticsearch98d2540e](https://github.com/SigmaHQ/pySigma-backend-elasticsearch/blob/98d2540e9cb3c8aeb21cec28635b94b24e8f1301/pyproject.toml):
  declara core^2.1.0 e Python^3.11, divergindo do wheel2.1.1 ainda publicado.
- [pySigmae5221881](https://github.com/SigmaHQ/pySigma/blob/e5221881d5f3d69033b34882fad83864d80db826/pyproject.toml):
  versão2.1.0 e mudança de dependência de cache acima.

Não foram construídos fontes Git/sdists nem alterados requisitos publicados.
O título/número de versão de um repositório não substitui METADATA do wheel.

## Comandos e resultados efetivos

Criado um venv sem pip em diretório temporário próprio com modo0700. O pip do
ambiente de desenvolvimento foi direcionado a esse venv pelo argumento
`--python`; nada foi instalado nele. Para cada CORE2.0.1/2.1.0/1.5.1, foi executado:

```sh
.venv/bin/python -m pip --isolated --python "$SIGMA_REVIEW_VENV/bin/python" install \
  --index-url https://pypi.org/simple --only-binary=:all: --dry-run \
  --ignore-installed --no-cache-dir --disable-pip-version-check \
  --report "$SIGMA_REVIEW_DIR/resolution-$CORE.json" \
  "pysigma==$CORE" pysigma-backend-opensearch==2.0.3 \
  pysigma-backend-elasticsearch==2.1.1
```

`--ignore-installed` inspeciona a árvore completa sem usar o ambiente existente;
não ignora requisitos. Os dois exits1 são conflitos esperados, não falha de rede:
o resolvedor informa o pin do usuário e o requisito core<2 do OpenSearch.
A exclusão de2.x pelo Elasticsearch foi confirmada no METADATA verificado.

Para o controle1.5.1, o report gerou um lock temporário com18pins/hashes. Foi
executado `pip --isolated --python ... download --index-url https://pypi.org/simple
--require-hashes --only-binary=:all: --no-cache-dir --disable-pip-version-check
-r <lock-temporário> --dest <diretório-próprio>`: exit0. Os18wheels baixados
coincidem com os18hashes do lock; nenhum backend instalado no venv descartável.
Hash do lock comparativo:
`6f63d628f1c880058059738e395e68c0dc5b46f129b957599eb40c9745aefe7e`.
Esse lock não foi adotado/publicado como instalação aprovada. Inclui ainda
DiskCache5.6.3; resolução satisfeita não significa segurança revisada.
Downloads/reports/logs/venv ficam fora do Git; os hashes e fatos revisados estão
registrados neste documento, sem atribuir durabilidade aos temporários.

Regressões existentes executadas, sequencialmente em relação a PG/Redis:

```sh
.venv/bin/pytest tests/test_sigma_readiness.py tests/test_sigma_mapping.py \
  tests/test_sigma_mapping_api.py tests/test_sigma_analysis.py -q
.venv/bin/python -m pip check
.venv/bin/ruff check apps/api scripts tests
.venv/bin/ruff format --check apps/api scripts tests
.venv/bin/mypy
```

Primeira rodada:76passed/15errors em4,85s; falha de autenticação no PostgreSQL
local antes da criação do schema, sem falha de assertion. A senha de.env diverge
da configuração do serviço de desenvolvimento existente. Nenhuma senha, conta,
grant ou arquivo.env foi alterado. Na segunda rodada, as credenciais dos serviços
próprios já ativos foram lidas em memória e passadas apenas ao processo de teste
por DATABASE_URL/REDIS_URL. Não estão neste relatório nem nos comandos publicados.

Segunda rodada: **91passed em14,67s**,1warning já existente de depreciação
Starlette/httpx. Schema PostgreSQL próprio descartável e Redis15, sem uso de
contas do Demo. Não somar76+91 como testes distintos. A suíte inclui import e
pipeline reais em processo novo com audit hook bloqueando cache/backend/rede/
subprocesso/gravação e sem desserializar pipeline; também integra RBAC, ownership,
integridade, limites, histórico e ausência de mutação. O teste do perfil usa
alerta gravado; não é consulta atual ao Wazuh nem validação do índice físico.

`pip check`: sem requisitos quebrados. Ruff: sem findings e357arquivos já
formatados. Mypy: sem erros nos4arquivos configurados. Sem testes novos que
espelhem implementação: esta mudança contém somente Markdown.
Revisão do staged/segredos, `git diff --cached --check`, `scripts/check_staged.py`
e `scripts/check_release.py` passaram; release-check conferiu690arquivos,
191Markdown e625links locais, sem afirmar validação de links externos.

Sonda local adicional: runtime core2.0.1, backends ausentes, readiness blocked,
`can_convert=false`; prévia do exemplo autoral status=previewed, com
query_generated/siem_queried/deployment_performed=false. Não foi produzido
artefato de consulta para download. UI/E2E não foram reexecutados nesta pesquisa;
não há nova CI integral executável nem implantação alegada.

## Preservação e handoff

Hashes SHA-256 conferidos antes/depois das verificações, sem alteração:

| Arquivo | SHA-256 |
| --- | --- |
| pyproject.toml | `b51f0ec1ddf6ca5bae88380591ca4f6776a036dcf9886947549627b53303a9d5` |
| requirements.lock | `e43ca0a86b0f24c2eb362abc9886f69dc2b72962f39dace35a32d03710da83e8` |
| requirements-dev.lock | `ac6f3de5f0582bfafc4be50de0d7cac256ae050cfc0ee0cbbff71fe1060cae7a` |
| fixtures/sigma/backend-metadata.json | `7dad5f4eeef1bf19fb0fb53bb095bd1c572488d04abaee9f07e972566b4500db` |

O snapshot22/10 permanece datado como tal na API; a pesquisa nova não o reescreve.
Nenhuma versão de regra, scope, aprovação, evidência, veredicto ou relatório foi
reescrito. Demo ativo e recursos de laboratório não foram implantados/operados.

#84 conclui a pesquisa prevista, inclusive o caso de combinação inviável.
#85 está bloqueada por dependência externa de distribuição oficial compatível;
#86 continua dependente de#85. #16 fica aberta, sem aceite conjunto. Decisão:
[ADR0035](../../architecture/decisions/0035-sigma-published-backend-compatibility.md).
Commits, último hash/mensagem e sincronização são registrados nos comentários
finais das issues. Parar neste bloqueio, sem iniciar outra entrega.
