# Comparação entre laboratórios — #21/#97/#98/#99

Entrega offline em23/11/2026. Fonte executável final:
`8c1d74eb0c2f4ccab7218619180d13057cefa73b`; versão do produto permanece0.2.0.
Não houve implantação no Demo nem operação Linux/Wazuh. Este documento registra
fatos de fixtures e de um percurso Demo descartável, sem alegação de eficácia
defensiva real ou equivalência física de laboratórios.

## Comportamento e aceite conjunto

| Critério | Resultado |
|---|---|
| #97: testes/versões/ATT&CK/configuração/fonte e diferenças | Coortes pelo scope histórico, retirando apenas IDs de campanha/lab/ativo; configurações completas e diferenças por campo disponíveis |
| #97: equivalência/descritiva/incomparável | Classificação explícita; desconhecido, legado, parciais, frequência diferente e fonte incompleta impedem delta |
| #97: origem e denominadores | Demo/real separados por lado; origem contraditória suprime a taxa inteira; válidos/excluídos e estados explícitos |
| #98: snapshot consistente e limitado | Dois lados em uma transação própria RR/READ ONLY; concorrência e escrita recusada pelo PostgreSQL real verificadas |
| #98: sem truncamento ou nova coleta | Limites por lado e do documento recusam o todo; consultas/exports preservam contagens de runs/testes/resultados/eventos |
| #98: membros/origem verificáveis | IDs, scope original/hash, resultados/hashes, fonte/metadados/hashes de eventos e vínculos de evidência; sem payload bruto ou recibo tratado como sensor |
| #99: seleção explícita e cache | Dois laboratórios/modos/releases/períodos; mudança de filtro descarta preview/exports e cancela/ignora respostas e downloads pendentes |
| #99: motivos e limites | UI apresenta classificação, motivos, taxas/denominadores por lado, diferenças e contextos; sem promessa de proteção geral ou melhoria causal |
| #99: JSON/HTML/PDF | Mesmo documento materializado; hash/data completos revalidados na exportação,409 em drift, HTML escapado e PDF conferido por parser |
| Histórico preservado | Relatórios individuais existentes mantêm contratos; JSON/HTML/PDF byte a byte idênticos antes/depois no E2E descartável |

Equivalência é somente dos registros. Números locais de versão iguais não são
atestação física. Nenhuma taxa combina modos e não existe taxa global dos dois
lados. Delta em pontos percentuais usa frações antes do arredondamento e só
existe com equivalência suficiente e dois denominadores válidos. Hash não é
assinatura nem autorização.

## Verificação local

Comandos e infraestrutura estão no [guia de testes](../../development/testing.md#comparação-entre-laboratórios--21).
PG já existente, schemas exclusivos e Redis15 em sequência; credenciais
selecionadas apenas no processo, sem alterar contas/grants/.env.

- Rodada abrangente: **92Python passaram**, incluindo integração de snapshot,
  concorrência, limites, API/RBAC/exports e regressões de comparação/relatórios.
- Após reforço de contexto de fonte: **33contrato/API passaram**, incluindo quatro
  casos novos. Os22testes puros passaram novamente após melhorar a fixture para
  testar a fonte independentemente de um runner incompleto. Conjuntos se
  sobrepõem:96casos distintos exercitados, sem somar repetições como novos testes.
- React: **144passaram/20arquivos** com `npm --prefix apps/web test -- --maxWorkers=2`.
  Nenhum caso, timeout ou gate removido. A configuração da CI permaneceu intacta.
- `make lint`, `make build`, `make audit` aprovados. Auditoria Python mantém
  um achado DiskCache previamente revisado; não é zero findings. npm0 e21casos
  do glob aprovados separadamente.
- Staged/segredos, `git diff --cached --check`, `scripts/check_staged.py` e
  `scripts/check_release.py` executados antes de cada commit.

Limites/falhas preservados em `.local/environment-comparison/`:

1. Configuração padrão do checkout falhou autenticação PG:3erros de setup.
   Seleção da conexão do serviço existente só no processo resolveu; depois os
   três testes de snapshot existentes passaram.
2. Primeira rodada ampliada:75passaram/1falhou no tratamento de intervalo
   invertido. Corrigido para422; repetição contrato/API28passaram.
3. Primeiro roteiro React: sete falhas por procurar uma opção existente nos
   dois seletores como se fosse única, mais erro de tipagem do mock. Corrigidos;
  143passaram antes do caso adicional de cancelamento de download.
4. Repetição React sob pressão de memória:31passaram e15erros de inicialização
   de workers; não é suíte verde. Repetição completa com dois workers144passaram,
   sem alterar configuração de CI ou encerrar recursos de terceiros.
5. Dois roteiros Firefox falharam por ausência de espera do login e por usar
   `JSON.stringify` na verificação de hashes Python. Corrigidos no harness,
   preservando JSON original (inclusive representação0.0), sem alterar relatórios.

Aviso upstream Starlette/httpx permanece. Fixtures com flags reais são somente
contratos; nenhum sensor/runner nativo foi consultado por esta entrega.

## Firefox e encerramento descartável na fonte final

`.venv/bin/python scripts/environment_comparison_e2e.py`, fonte`8c1d74e`,
**VERIFIED**. Provas privadas em
`.local/environment-comparison/acceptance-zb1xsw0x/summary.json`, capturas1440px/
390px e arquivos originais. Observação da API real, sem interceptação/substituição.

- Duas runs Demo completas, cada qual com um teste sintético: IDs
  `eab5c92c-e512-4af3-a8db-a8931ab3e292` e
  `93202ef6-1b0a-407e-8f01-0d7a303a5271`.
- Estado equivalente nos registros; mudar B para legado vazio produz incomparável.
  Restaurar filtros e criar normalmente uma run Demo pendente altera membros;
  export anterior recusa409 e nova consulta produz descritiva/sem delta.
- Solicitação adicional`bde536db-2755-430e-a2ee-baa3ff71c03c` permaneceu
  PENDING_APPROVAL, sem start/efeito, até remoção do schema próprio.
- Três exports verificados; PDF8páginas, hash do JSON fonte conferido e aviso
  sintético em todas as páginas. Zero errosJS e zero overflow do documento390px.
- JSON/HTML/PDF individuais anteriores permaneceram byte a byte idênticos.
  Processos API/worker/Firefox próprios encerrados, schema e limites da conta
  própria removidos. Consulta posterior ao PostgreSQL encontrou zero schemas
  `aegis_environment_e2e_%`, incluindo todas as tentativas.

| Artefato da rodada final | SHA256 |
|---|---|
| Integridade do snapshot comparativo, sem seu próprio campo | `240ceeea258a9ea5b6b4762a4cf2452e60f3999f05c77246ffabf9537c6a9d29` |
| JSON fonte completo identificado no header do PDF | `8baf49532f2c037095cf7840d50a0fdb44de54e1923e9f3bfcfb056f8a709429` |
| Relatório individual JSON preservado | `50ea6c43cbb34bc20a0b9ef96e36251fc8759775e1653ffdbdb8288eb299070b` |
| Relatório individual HTML preservado | `08b144faad74346b81c181924892e9f3bb6c4a10cb2d35c3ac35709eaa22d762` |
| Relatório individual PDF preservado | `a482a8beb5dab48e5ca00c2b6125b7838bb71cc010053bb5344f19ea1ba5d3a9` |

O hash do JSON fonte não é o hash dos bytes PDF. A rodada anterior na fonte
`99ab48b` também terminou VERIFIED/encerrada; não somar suas runs/páginas como
evidência nova da rodada final. Falhas anteriores permanecem privadas.

## Fonte e sincronização

- `5dcfefe` — `feat(analytics): define bounded environment cohort comparability (Refs #97)`
- `a0c442d` — `feat(analytics): expose coherent cross-laboratory snapshot exports (Refs #98, #97)`
- `99ab48b` — `feat(web): compare laboratory cohorts with verified snapshot exports (Refs #99, #21)`
- `8c1d74e` — `fix(analytics): reject incomplete defensive source context (Refs #97, #21)`

Cada commit foi enviado diretamente a origin/main, sem branch/PR/rebase/force.
Checkout usado:`/home/IVPTER/AEGIS`. As cinco alterações locais de preparação de
rede no outro checkout não foram modificadas/incluídas. Demo API/worker seguem
na imagem anterior`b8abe5e44af4bad90d2e302a045f38fb9cf268932be5ea0493fc72f078657a23`.
Sem migração/DDL em originais, reset de histórico, marcador, build de contêiner,
alteração de rede/PKI/volumes, nova autorização de Lab, tag ou release.

## CI integral e aceite final

[Workflow45255847606](https://github.com/Buraddomoon/AEGIS/actions/runs/45255847606),
fonte`8c1d74eb0c2f4ccab7218619180d13057cefa73b`: **SUCCESS**. Cinco jobs conferidos
individualmente, incluindo quatro partições complementares e React. Sem reduzir
casos/partições/timeout/max-parallel ou alterar gates para obter aprovação.

| Job Python | Passed | Skipped |
|---|---:|---:|
| 0 | 962 | 2 |
| 1 | 953 | 2 |
| 2 | 1060 | 1 |
| 3 | 955 | 4 |
| Total | **3930** | **9** |

3939casos coletados em cada partição; seleção complementar pelo script de CI,
sem omissão/overlap. Nove skips opcionais já existentes: metadados opt-in de
imagem, Demo API/DB/rede ausentes, ferramentas PostgreSQL locais ausentes e quatro
objetos Demo de inspeção indisponíveis. Não foram criados recursos para eliminar
skips. React**144/20arquivos**, glob**21**, lint/tipos/formatação/build e auditorias
aprovados; DiskCache revisado continua visível, npm0.

A CI intermediária`a0c442d` também passou; workflows substituídos por fontes
posteriores não são apresentados como validação final. A conclusão acima é da
fonte executável final e é distinta do E2E local. O commit de encerramento contém
somente documentação; inputs executáveis idênticos a`8c1d74e` foram reconferidos.

#97/#98/#99 atendidas e aceite conjunto da #21 conferido. Commits/último hash e
sincronização final ficam nos comentários GitHub, evitando autorreferência do
hash deste documento. Entrega encerrada; parar sem iniciar outra feature,
implantar ou reativar laboratório. Pacotes/autorizações anteriores permanecem
consumidos; esta entrega não concede operação nativa.
