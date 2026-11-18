# Preparação da validação Sigma — #17

18/11/2026. Escopo exclusivo #17 e filhos #87/#88/#89. Dependências nativas
#16 e #7 conferidas CLOSED. **Aceite nativo pendente**: não existe autorização
específica desta entrega para iniciar/consultar o laboratório. Nenhuma subissue
foi fechada com fixture em lugar da prova física exigida.

## Implementado e testado

- `66bf13de2f998745da6ae9d6731fbf36642946cc` —
  `feat(sigma): gate queries on reviewed physical index metadata (Refs #87)`.
  Gate de versão anunciada/mapping/settings/aliases, tipos e campos físicos;
  TLS/CA/SNI/destino herdados do adaptador. Sem confiança aprendida da resposta.
- `f8e20eee34f74c01a1ac8d150b0d1b1a6af1cfae` —
  `feat(sigma): validate reviewed queries with bounded provenance (Refs #88)`.
  API administrativa opt-in, escopo privado/temporário, query regenerada por
  versão/hash, agente/período/índice fechados, paginação/timeout/bytes, verificador
  literal independente, origem integral, completude e cleanup explícitos.
  Endurece #87 contra `_source` filtrado. Não altera evidência/veredictos históricos.

Arquivos centrais: `apps/api/aegis/integrations/sigma_index.py`,
`sigma_validation.py` no mesmo diretório, `apps/api/aegis/api.py`, `config.py`,
`schemas.py`, `tests/test_sigma_index.py` e `tests/test_sigma_validation.py`.
[Contrato e procedimento](../../operations/sigma-query-validation.md).

SHA-256 dos bytes na fonte final:

| Arquivo | SHA-256 |
| --- | --- |
| sigma_index.py | `81eae1930ce3abe890d819636d23e5731a98b98be3446d3c5d4a993b86f66daf` |
| sigma_validation.py | `dbaabea276f53f410ae1f568073553b0f401931a4a1fb0f9dfdb835c395a413d` |
| test_sigma_index.py | `6386019a8de23112e945b2d03b08d969ca8bde507399f779331d4d6a0e49ce71` |
| test_sigma_validation.py | `2cb835b85082110f90949e30d6f1e48932daff3bc4ec7f80efeb3b26ab947012` |

Hashes detectam alterações; não são assinaturas nem comprovam implantação.

## Verificações locais executadas

Com credenciais dos serviços locais existentes selecionadas **somente no processo**,
sem alterar `.env`, contas/grants ou dados do Demo:

```sh
.venv/bin/pytest tests/test_sigma_validation.py tests/test_sigma_index.py tests/test_wazuh_tls.py tests/test_sigma_conversion.py tests/test_sigma_converter_worker.py tests/test_wazuh_collection.py tests/test_wazuh_profiles.py tests/test_sigma_mapping_api.py tests/test_wazuh_availability.py -q --tb=short
```

**193passed/31,59s**, PostgreSQL real/schema descartável e Redis15, execução
sequencial. Inclui62casos nos dois arquivos novos; os demais são regressões.
Metadados/Search/Scroll usam fixtures; TLS usa servidor real em loopback, sem SIEM
externo. Recusas cobrem aliases/texto/normalizer/nested/source filtrado, drift,
hash/contexto, falsos positivos, tempo/agente, shards/total/cursor, resposta perdida,
limites, revogação, RBAC/CSRF/rate limit/Redis e preservação de versões/auditoria/
cobertura. `synthetic=false` no contrato do conector em fixture não é prova nativa.

`make lint` final passou: Ruff, formatação365arquivosPython, mypy e
TypeScript/Prettier. Antes dos commits: staged revisado, scanner de padrões de
credenciais, `git diff --cached --check`, `.venv/bin/python scripts/check_staged.py`
e `.venv/bin/python scripts/check_release.py`, todos aprovados. Não houve mudança
de dependências/locks nem instalação local de pacotes nesta entrega.

Rodadas intermediárias são subconjuntos sobrepostos, não casos novos somáveis:
31passed no gate inicial;53passed/3erros de setup por credencial PG desatualizada;
55passed/1falha na fixture por whitespace externo normalizado na importação.
Selecionar credenciais apenas no processo e fixar o hash da versão realmente salva
resolveram esses pontos, sem relaxar validação. Rodadas184/189/191passaram antes
dos últimos casos/ajustes. Uma verificação de formatação intermediária falhou,
foi corrigida e o lint completo repetido. Aviso upstream Starlette/httpx preservado.

## Checagem offline do alerta existente — preparação da #89

`pytest tests/test_wazuh_recorded_assay.py -q --tb=short`: **6passed/0,04s**,
integridade/normalização do registro histórico22/10, sem rede.

Outra checagem Python local leu somente os arquivos versionados da #59 em
`docs/evidence/wazuh-cycle-2026-11-16`, verificou bytes/canonical contra seu manifesto,
gerou duas queries com o conversor oficial e aplicou o verificador literal ao
`_source` preservado. Original não alterado:

- Bytes do alerta: `8bfa75cd4e7c24b8bd305508d83c331a903d37f3a7e88621791e5a86dd7ab03b`.
- Canonical do alerta: `1181e2d800bd99e3117b22b760f30223ff88c1243e0462328f2137889c2276c5`.
- Positiva: conteúdo de `fixtures/sigma/aegis-marker-candidate.yml`,
  correspondência literal verdadeira; query SHA-256
  `924cbb0bf9deba5db7916e43d4a2c01bf3af2747295eb1d0167f78371cebfa4a`.
- Negativa: trocar somente `marker_file_read` por
  `sigma_validation_negative_no_event`, correspondência literal falsa; query SHA-256
  `0f1b1825318f1181099b8bf7cc34f720ae121580f3d1cce8f4d1e5298c1a2e39`.

A primeira tentativa dessa checagem parou antes das comparações por consultar a
chave antiga do manifesto; a retomada usou `bytes_sha256` e validou também o hash
canônico. Nenhum artefato histórico foi reescrito. **Não executou Lucene/OpenSearch**,
não verificou recall, mapping físico nem ACL; não representa ensaio nativo da #89.

## CI e sincronização

CI do primeiro commit66bf13d:
[44383988852](https://github.com/Buraddomoon/AEGIS/actions/runs/44383988852),
**SUCCESS**, quatro partições Python e React conferidos.3809Python/9skips
existentes (962+897+1026+924passed;2+2+1+4skips),115React/17arquivos.
Esse resultado não é a validação da fonte finalf8e20ee.

CI da fonte finalf8e20ee:
[44386130666](https://github.com/Buraddomoon/AEGIS/actions/runs/44386130666),
**SUCCESS**. Quatro grupos Python e React conferidos individualmente, sem alterar
filtros/partições/timeout:3843Python/9skips existentes,115React/17arquivos.

| Grupo | Passed | Skipped | Tempo pytest |
| --- | ---: | ---: | ---: |
| Python0 | 962 | 2 | 136,33s |
| Python1 | 931 | 2 | 243,69s |
| Python2 | 1026 | 1 | 242,81s |
| Python3 | 924 | 4 | 289,96s |

Os grupos coletaram3852casos completos; a seleção complementar preserva a suíte.
Source-review do mesmo hash44386130532 passou; é workflow distinto.
Os dois commits de implementação foram enviados para origin/main; nenhuma branch,
PR, force push, tag, release ou implantação. Commits posteriores deste registro
são documentais; último hash/mensagem e estado remoto constam no comentário final.

## Bloqueio e limites operacionais

#87 implementada/testada localmente; mapping/settings/aliases/ACL reais ainda
dependem de coleta própria autorizada. #88 implementada/testada em API/DB/fixtures;
o aceite físico depende da #87 e do ensaio. #89 permanece bloqueada: falta
autorização de startup/coleta read-only, snapshot físico revisado e pacote novo
com imagens/PKI/redes/IDs/volumes, principal de leitura e encerramento. Consultas
positiva/negativa devem fixar versões/hashes próprios; novo marcador exigiria
outra autorização e não é necessário para o plano baseado no alerta existente.

Nenhum Linux/Wazuh iniciado, volume original aberto, query enviada ao SIEM,
marcador/run real ou migração de Lab. Sem build/pull de imagens, stack pesado ou
implantação local. A CI executa seu build frontend conforme workflow preservado.
Demo ativo preservado; inspeção final de nomes/imagens mostrou somente seus quatro
serviços ÆGIS existentes. API/worker continuam na imagem anterior
`sha256:b8abe5e44af4bad90d2e302a045f38fb9cf268932be5ea0493fc72f078657a23`;
o código desta entrega não foi implantado. PKI, qasrc, journals, fences, pacotes consumidos e dados
históricos preservados. Não inferir eficácia geral, implantação Wazuh, ausência
de telemetria ou aceite conjunto. **Issues continuam abertas; parar neste bloqueio.**
