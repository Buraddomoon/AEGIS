# Recomendações por evidência — #22

## Escopo e fonte

Somente #22 e subissues #100/#101. Base `526f1a6`, clone novo em
`C:\Users\Gamer\Desktop\codes\AEGIS`, somente `main`. Instruções de entrada,
dependências nativas e arquivos indicados conferidos; PROGRESS não foi carregado.

- `61dc14809f7049e89dd7cc029c4088631b16ed90`: política versionada determinística
  e17casos novos — #100.
- `c6676ae1d77cb3777d0c3f4d296796452c5cf30e`: detalhes, análise/export separado,
  UI e testes/parsers — #101.
- `40bc98413ee4a9ab803e95fbacc16a98bfbf86fc`: job manual de aceite Demo isolado
  e verificador dos downloads — #101.
- `3abc397b6efd1d707658d466ac3f8947e41038a0`: diagnóstico de etapas e prazo
  global limitado360s, preservando todos os checks e contando PDFs efetivos.
- `a7266c089a773d7506ce9e912b6e23e7e91e3658`: sincronização de foco/viewport
  e fechamento de diálogo no Firefox; fonte final de código desta entrega.

A política incorpora fatos, vínculos defensivos registrados, versão/documento/
hash, hash da entrada e integridade da análise. A prioridade orienta investigação
técnica, sem inferir vulnerabilidade/risco ou reclassificar veredictos. Cleanup
falho permanece prioritário mesmo com detecção registrada. Recibos não viram
evidência defensiva. Campos ausentes e vínculos órfãos permanecem explícitos.

Detalhes usam snapshot REPEATABLE READ READ ONLY. Export de recomendações exige
hash da análise exibida e recusa drift409; contrato inválido422. O artefato novo
inclui política e fonte completa. Relatórios1.2 e documentos automáticos
congelados mantêm builders/contratos originais. UI inspeciona ID/hash do evento,
identifica origem e cancela download quando muda a análise.

## Verificações locais efetivamente executadas

Windows/Python3.14, sem PostgreSQL/Redis locais:

| Comando | Resultado |
|---|---|
| `python -m pytest tests/test_recommendations.py tests/test_domain.py -q --tb=short` |34passed |
| `python -m pytest tests/test_recommendations.py tests/test_recommendation_reports.py tests/test_pdf_reporting.py tests/test_domain.py -q --tb=short` |64passed |
| `npm --prefix apps/web test` |154React/21arquivos +21casos de segurança do glob |
| Ruff check/format de apps/api, scripts, tests; mypy | Aprovados,5módulos de domínio |
| `npm --prefix apps/web run build` e `run format:check` | Aprovados |
| `npm --prefix apps/web audit --audit-level=high` |0vulnerabilidades reportadas |
| `node --check apps/web/e2e.mjs` e parse YAML do job | Aprovados |
| `git diff --cached --check`, check_staged e check_release | Aprovados antes de cada commit |

Os parsers conferem HTML e PDF reais, conteúdo/hashes, escapes e igualdade dos
bytes de exports históricos em fixture. HTTP local substitui storage/auth;
não é prova PostgreSQL/RBAC real. Os4casos de API PostgreSQL novos foram apenas
coletados localmente e são executados na CI. Aviso de depreciação Starlette/httpx
permanece; não houve exclusão de casos para obter sucesso.

### Falhas de preparação preservadas

O lock original é Python3.13/Linux. Instalação direta no Windows recusou hash
da wheel msgpack; o lock original não foi alterado. Um lock complementar privado
Windows foi gerado com os mesmos pins, hashes próprios e dependências de plataforma,
instalado com `--require-hashes --no-deps`. Não equivale ao ambiente Linux da CI.

Git Windows converteu LF para CRLF: o gate dos hashes do fork picomatch e o
format-check recusaram esses bytes. Arquivos sem edição tiveram os bytes dos
blobs Git repostos; não houve mudança de hash esperado, dependência ou gate.
Nenhuma alteração de conteúdo vendor entrou nos commits. Um erro inicial de
tipagem do fixture React foi corrigido preenchendo o DTO completo, sem reduzir
checagem TypeScript. As verificações finais acima passaram após as correções.

## CI e aceite Demo

- Política #100: [Validate AEGIS45311840734](https://github.com/Buraddomoon/AEGIS/actions/runs/45311840734)
  SUCCESS, React e quatro partições Python conferidos individualmente. #100 fechada
  com comentários de prova.
- CI de `c6676ae`:45314175985 foi substituída/cancelada pelo push da fonte seguinte;
  não é apresentada como CI verde.
- CI40bc984/45314548793 e3abc397/45315370864 foram substituídas por novo push;
  não são apresentadas como workflows verdes.
- [CI final da fontea7266c0](https://github.com/Buraddomoon/AEGIS/actions/runs/45316191331):
  **SUCCESS**, React e quatro partições Python conferidos individualmente.
  Python0:979passed/2skips; Python1:969/2; Python2:1060/1; Python3:955/4.
  Total3963passed/9skips opcionais existentes. React154/21arquivos e21glob,
  lint/types/format/build e auditorias aprovados. Partições complementares mantêm
  todos os casos; nenhum filtro ou exclusão foi acrescentado para obter green.
- [E2E final45316212021](https://github.com/Buraddomoon/AEGIS/actions/runs/45316212021):
  **SUCCESS**, fluxo completo sem exclusões. Firefox,5runs/20testes Demo,
  2relatórios automáticos,5exports PDF por cliques,19capturas e0erros JS.
  Etapa de recomendações VERIFIED, JSON/HTML/PDF e eventos,1440px/390px,
  sem overflow e exports históricos idênticos. Verificador do pacote também
  VERIFIED, PDF18páginas; capturas finais inspecionadas.

### Tentativas de navegador anteriores

[45314588774](https://github.com/Buraddomoon/AEGIS/actions/runs/45314588774)
falhou no limite global180s, após a etapa de recomendações VERIFIED. Artefato
14883963314 foi preservado e verificado separadamente; isso não torna o job verde.
[45315388008](https://github.com/Buraddomoon/AEGIS/actions/runs/45315388008)
falhou esperando o fechamento do diálogo na segunda aprovação, após a etapa
de recomendações novamente VERIFIED; artefato14885590154 inclui captura da falha.
A captura mostrou a aprovação registrada e diálogo já fechado. O harness agora
retoma foco antes de cliques, verifica visibilidade após downloads e usa polling
100ms para a mesma condição de fechamento, sem depender de animation frame.
Capturas passam a aguardar a transição do menu móvel e começam no topo.
Nenhuma condição, aprovação, cadência ou assert foi removido/abreviado.

### Pacote final e integridade

[Artefato14885339239](https://github.com/Buraddomoon/AEGIS/actions/runs/45316212021/artifacts/14885339239),
914906bytes, ZIP SHA256
`5ef72c2167b222dc24822632b49d4c39eea574363592e4c5466f48a05cd0b8e1`.
Retenção até01/12/2026 03:02:14UTC; cópia host-only em
`.local/artifacts/14885339239`. Pacotes anteriores também retidos localmente,
sem incluí-los em Git. A sessão começou em23/11 e concluiu verificações em24/11
no fuso America/Sao_Paulo; timestamps da CI e do navegador são UTC.

Análise SHA256: `1e0238e4b5820a38194eba64ae6fb34e2e50438047c82edbff96a77fe9c142d4`.

| Arquivo | Bytes | SHA256 |
|---|---:|---|
| recommendations.json |35783|`6d57e49e7a335cfab85210f8a520c18d52e7cff3869ec62ba7580e5826506e63`|
| recommendations.html |73060|`9fef64eb9935f3961e2a4e0135e793bd68f688f32451ca08ef313736072a4827`|
| recommendations.pdf |78636|`a7e902cb14a3a4c804a02703a48d7e01ca886b6a3228bac7281c82ce7a7624f7`|
| recommendations.png |491627|`662f4f86019b927e052db90ae75dcbacfb1ba3f661666cdf273d40a9e4911f8d`|
| recommendations-mobile.png |415044|`af122b37c71a7ea19cf5d26ec6844340f6acb2b44dbc99d923cf234704c49dfa`|

O job manual reutiliza o E2E existente, PostgreSQL/Redis efêmeros do runner e schema
próprio; exige Firefox já disponível e não instala laboratório. Capturas ficam em
diretório novo. Somente JSON/HTML/PDF de recomendações e duas capturas sintéticas
entram no artefato, com retenção7dias; logs/credenciais não são enviados no pacote.
O verificador checa documento/análise/política/entrada, HTML embutido idêntico,
PDF parseado, quatro outcomes e origem em todas as páginas; calcula hashes dos
cinco arquivos. O pacote final foi baixado e a verificação repetida no Windows,
com os mesmos hashes e18páginas; essa repetição não inicia outro ensaio.

## Limites e estado

Não houve implantação, migração de originais, nova campanha nativa, marcador,
consulta SIEM, acesso a volumes, PKI, journals, fences ou rede qasrc. O estado
operacional dos ambientes originais não foi medido nesta máquina. Prova Demo é
sintética e não comprova detecção real, cobertura ATT&CK ou risco de negócio.

## Aceite conjunto — 24/11/2026

| Critério | Prova e limite |
|---|---|
| #100: mesma entrada/saída, política/hash/fatos/evidências |17casos novos + domínio, CI integral; análise não altera regra/veredicto |
| #101: motivos, ações e evidências em detalhes/exports |12casos de builders/parser/HTTP fixture e4PG novos;154React; E2E completo/API/worker reais |
| Histórico e origem |Builders1.2/congelados preservados; bytes JSON/HTML/PDF idênticos antes/depois no E2E; Demo sempre sintético |
| Integridade e drift |Política/entrada/análise/documento checados;409 para preview alterado; download antigo cancelado; PDF18páginas parseado |
| Autorizações e recursos |Sem operação de originais; E2E finally encerrou API/worker/browser e removeu schema; serviços CI encerrados, job SUCCESS |
| Rastreabilidade |Commits somente emmain, pushes, falhas e hashes registrados; pacote final e cópia host-only preservados |

#100 e #101 atendidas, aceite do conjunto #22 realizado sobre a fontea7266c0.
Nenhum bloqueador restante para o escopo **offline**. Os9skips opcionais não
comprovam ambientes originais e não mudam esse limite. Implantação/ensaio nativo
continuam fora do escopo e não são declarados concluídos. Comentários finais
registram o último commit documental, sincronização e fechamento das issues.
**Parar nesta entrega; não iniciar outra feature ou laboratório.**
