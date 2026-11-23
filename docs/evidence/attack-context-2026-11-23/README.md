# Aceite da #20 — relações ATT&CK e referências de telemetria

Escopo: #95 e #96, sessão independente em23/11/2026. Base `eb61342`;
fonte implementada/testada `975a155`. Somente main, sem branch/PR/release.

## Comportamento e limites

- #95: documento `/2` preserva IDs STIX/ATT&CK, release, modificações e flags
  das relações e dos caminhos estratégia→analítica→componente/fonte/log. `/1`
  mantém sua identidade; ausência/legado explícitos. Sem herança de coverage.
- Enriquecimento offline cria candidato novo a partir de fonte local revalidada.
  Mesma versão `/1`→`/2` só passa com fonte/commit/licença/técnicas idênticos.
  Migração explícita `e2a71c9d064b` altera a unicidade pelo perfil do próprio JSON,
  sem coluna nova ou reescrita de linhas. Downgrade recusa perder histórico `/2`.
- #96: modal existente navega pai/subtécnicas mantendo modo, release e filtros.
  Referência oficial é planejamento; eventos registrados aparecem em outra seção,
  por execução/modo/synthetic/release histórica, com links para as evidências.
  Teste disponível/recibo não vira fonte observada; conexão atual não é inferida.
  Zero eventos não prova ausência de telemetria. Legado/ausência/erro são visíveis.
- Fontes retiradas mantêm flags. Nova identidade de release separa cobertura atual
  do histórico, mesmo com técnicas iguais. Não há incremento artificial no pai.

## Verificações executadas

Infraestrutura PG/Redis existente, schemas descartáveis e Redis15 em sequência.
Credenciais selecionadas somente no ambiente dos processos, sem editar `.env`,
contas ou grants dos serviços. Comandos documentados em
[testing](../../development/testing.md#relações-attck-e-telemetria-de-referência--20).

- Catálogo/revisão/API/publicação/CLI/artefatos/documento/migrações:116passaram
  em35,42s; contexto repetido depois:20passaram em4,97s, incluindo um caso novo
  de migração populada/downgrade (117casos distintos nesse conjunto).
- Após a correção de compatibilidade:69passaram em23,72s em
  `test_attack_context`, `test_migrations`, `test_atomic_catalog`,
  `test_linux_campaign_preparation` e `test_wazuh_cycle_catalog`. Verificam a
  preservação integral das linhas e as recusas históricas de operação dos labs.
- React:136passaram/19arquivos, incluindo11novos;21testes de segurança do glob.
  `make lint` completo e `make build` passaram. Aviso Starlette/httpx permanece.
- Checks staged/segredos/whitespace e release executados antes de cada commit.

## Firefox com API/worker e fonte oficial local

O comando `scripts/attack_review_e2e.py --reference-context` reutilizou o candidato
`798dc8da9a8e2f7996894d11b5ec00211c2532a26da391a50d2c170b2b849844`
em cópia privada. Fonte Enterprise20.0/commit
`c2494b29dd268c46a5d0ea0990553e4327cd2253`, SHA256
`81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352`.
Nenhum download ou versão nova foi necessário. Grafo projetado:2622objetos e
1184relações do subconjunto; nenhum `x_mitre_data_sources` inventado nas técnicas.

Candidato `/2` e release aplicada **somente no schema descartável**:
`2511188bd81a62112257224857a0723491fb59f09b10c5ae95afd15a490c39a2`.
Uma run Demo sintética `4c0b59f5-bb78-4518-ba3f-75472b2bbcce` produziu o resultado
esperado `OBSERVED_NOT_ALERTED`. Firefox verificou legado→revisão web→apply local
real→perfil enriquecido, navegação pai/subtécnica, quatro caminhos oficiais para
PowerShell, modo Linux sem eventos Demo,1440px/390px sem overflow e zero erros JS.
Após publicação, técnica voltou a `NOT_TESTED` na release nova; pai permaneceu
`NOT_TESTED`, e o evento sintético manteve a release histórica.

Os três relatórios permaneceram idênticos byte a byte antes/depois:

| Artefato | SHA256 |
| --- | --- |
| JSON | `afbd97bf18bef74326a8e15b12d822d8ad3748a4b51630a540d34149c78c45b1` |
| HTML | `9af73ed6bde8a040eeda31e092ed8c61e480d165464583013e2090c40fe0cc81` |
| PDF | `6594ea608cc357c670f90ff2568d728d7815ef06943a2efb47a7b99187d64834` |

Resumo e capturas privados: `.local/attack-context/acceptance-idq66qsz/`.
Captura `context-after-desktop.png`: SHA256
`08a5ff3b2178a1493b5a5c020205414e3a6222d29c07c07f5510f60d404f81df`;
`context-after-mobile.png`: SHA256
`3c288fb5c01ff9b9e4d4026a41c9b0a0d65be25269515162bf4f2dbe897cf443`.
Inspeção visual da captura móvel confirmou referências/flags legíveis.
Processos próprios encerrados, schema exclusivo removido e cache original
conferido por hashes e preservado. Consultas somente leitura confirmaram ausência
dos três schemas das tentativas; nenhum processo próprio de API/navegador permaneceu. Não há implantação no Demo ou ensaio nativo.
Demo API/worker continuam na imagem `b8abe5e44af4bad90d2e302a045f38fb9cf268932be5ea0493fc72f078657a23`;
readiness observado `ready` (banco/Redis true). Nenhum Linux/Wazuh, marcador,
volume original, PKI, rede ou `qasrc` foi operado. Outro checkout local foi preservado.

## Falhas anteriores retidas

- Primeiras integrações recusaram credenciais PG desatualizadas; seleção de
  credenciais dos serviços somente no processo resolveu o ambiente.
- Fixture negativa detectou regex de URL permissiva; corrigida para origem exata.
- Tentativa de publicar perfis distintos encontrou a unicidade antiga; migração
  explícita acrescentou o perfil sem reescrever documentos.
- [CI69ac915](https://github.com/Buraddomoon/AEGIS/actions/runs/45220966016) falhou
  em6testes: coluna nova exigida em schemas históricos, diferença na preservação
  de linhas e expectativa de head antigo. Correção `921bd34` usa índice de
  expressão sobre JSON e confirma o head real antes de provar recusa dos labs.
  A CI intermediária921bd34 foi cancelada pela fonte final, não é CI verde.
- Testes iniciais da UI tinham seletores inexatos para o nome com seta; corrigidos,
  sem mudança no comportamento para fazer o teste passar.
- Firefox inicial esperava DETECTED no cenário PowerShell; a fixture existente
  define OBSERVED_NOT_ALERTED. Segunda tentativa selecionava o título do modal
  em vez do nome da técnica. Expectativa/seletor corrigidos; diretórios privados
  `acceptance-cjsyhjbo` e `acceptance-pt9xqsic` retidos com cleanup registrado.

## CI e encerramento

[CI integral da fonte975a155](https://github.com/Buraddomoon/AEGIS/actions/runs/45246697612)
**SUCCESS**, quatro partições Python e React conferidos até o encerramento dos
serviços da workflow. Sem filtros/exclusões novos e sem reduzir gates.

| Job | Aprovados | Skips existentes |
| --- | ---: | ---: |
| Python0 | 962 | 2 |
| Python1 | 931 | 2 |
| Python2 | 1060 | 1 |
| Python3 | 944 | 4 |
| Total Python | 3897 | 9 |
| React | 136 | 0 |

React inclui mais21testes de segurança do glob, tipos/format/build/auditoria npm;
Python0 inclui lint/tipos e revisão de advisories. Os9skips opcionais não são
ensaios nativos. A revisão de entrega da fonte também passou na
[workflow própria](https://github.com/Buraddomoon/AEGIS/actions/runs/45246697732).

Commits de implementação, todos enviados diretamente a origin/main:

- `69ac915` — `feat(catalog): preserve versioned technique and telemetry context (Refs #95)`.
- `921bd34` — `fix(catalog): preserve historical schema row contracts (Refs #95)`.
- `975a155` — `feat(web): navigate technique context and distinguish recorded telemetry (Refs #96)`.

Aceite conjunto: relações e fontes com proveniência; distinção entre referência
e coleta registrada; modo/release preservados; ausência/erro explícitos;
sem aumento artificial de cobertura; migração e relatórios históricos
preservados. #95/#96 atendidas. Evidência de CI, fixture, navegador e implantação
são distintas: somente código/artefatos no checkout e schemas descartáveis foram
exercitados; o Demo anterior permanece ativo. Último commit documental e igualdade
local/remoto serão registrados nos comentários finais das issues. Parar na #20.
