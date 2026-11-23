# Revisão administrativa ATT&CK — provas da #19

Em23/11/2026, #92/#93 entregaram revisão web de planos preparados no host, e #94
validou o percurso em PostgreSQL/Firefox descartáveis. Publicação permanece na
CLI com credencial administrativa de implantação; nenhuma publicação/download
web, URL livre, atualização no startup ou operação Linux/Wazuh foi adicionada.

## Fonte e limites

Implementação: `a0d39e2` (API,#92), `5509192` (UI,#93), `57f2bba` (roteiro de
aceite e correção da paginação móvel,#93/#94). As verificações abaixo usam esses
inputs; a consolidação posterior é documental. Versão do produto permanece0.2.0.

O candidato oficial **já existente** foi revalidado no cache original, copiado
para um cache temporário e revalidado novamente. Nenhum download foi necessário.
É a **mesma versão20.0**, bundled→official_commit, sem inventar release mais nova.
O hash verifica bytes; não é assinatura nem consulta atual ao upstream.

| Identidade | Valor |
|---|---|
| Candidato/release publicada no schema temporário | `798dc8da9a8e2f7996894d11b5ec00211c2532a26da391a50d2c170b2b849844` |
| CommitMITRE fixado | `c2494b29dd268c46a5d0ea0990553e4327cd2253` |
| SHA256 do bundle original | `81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352` |
| Documento da release bundled preservado | `b572391494ef2b9ec7b68095bef5ba16c7190da123497c1b814b9c5c0ce6b3e2` |
| Plano antes de apply | `fe66df66170c3031ab62e4411ef8aff16dd173e521c7f31e2f95341d14f71fb4` |
| Novo plano depois de apply | `02915c556987be15a8f359c336485fbb5d652f5b16a3157bb71af9ad658d0c50` |

O diff continha161adições de referências retiradas e706alterações de metadados,
com706técnicas ativas após publicação; nenhuma técnica ausente. Zero runs
pendentes, reservas ou agendamentos retomáveis no instante do plano. Cadastro de
catálogo não constitui evidência de observação/detecção. Os fixtures reduzidos
19.2→20.0 nos testes automatizados continuam explicitamente sintéticos, distintos
deste candidato oficial completo.

## Comportamento e verificação

- API opt-in por cache privado somente leitura, administrador ativo, inventário
  limitado/paginado, origem/versão/licença/hashes/destino, diff antes/depois e
  impactos sobre testes. O plano inteiro é refeito em SQL REPEATABLE READ/READ ONLY.
- Confirmação exata descarta cache divergente, mudança de candidato/plano/destino,
  erro, troca de página/plano e respostas atrasadas. Nenhum GET grava catálogo,
  auditoria ou autorizações; teste de escrita real comprovou a transação read-only.
- Firefox real, API/worker reais, Alembic/seed somente em schema próprio:
  revisão→página2→confirmação do hash→instrução local, então apply da CLI real com
  cache temporário. Plano antigo recusado409, novo plano `already_applied` com
  checkbox desabilitado. Backend não foi substituído/interceptado no navegador.
- Uma run/um testeDemo na rodada final, sempre `synthetic=true`. JSON/HTML/PDF
  anteriores preservados byte a byte; duas releases retidas no schema até cleanup.
  Novos efeitos exigem contexto de catálogo vigente; testes de API/publicação
  também verificam reaprovação/escopos, bloqueadores, concorrência e rollback.
- Desktop1440px e celular390px, zero errosJS em ambas as fases. Diálogo móvel
 358px, client/scroll344px; botões da paginação contidos no diálogo após correção
  visual. Capturas finais inspecionadas, sem sobrescrever a galeria histórica.

Comandos efetivamente executados, sequencialmente em PG/Redis15:

```sh
.venv/bin/pytest tests/test_attack_review.py tests/test_attack_api.py tests/test_attack_publication.py tests/test_attack_cli.py tests/test_attack_artifacts.py tests/test_attack_document.py tests/test_migrations.py -q --tb=short -x
npm --prefix apps/web test
make lint
npm --prefix apps/web run build
.venv/bin/python scripts/attack_review_e2e.py --candidate-cache /home/IVPTER/codes/aegis/.local/attack-catalog --candidate-id 798dc8da9a8e2f7996894d11b5ec00211c2532a26da391a50d2c170b2b849844
node --check apps/web/attack-review-e2e.mjs
```

Resultado local: **97Python**, **125React/18arquivos** e **21testes do glob**,
lint/tipos/formatação/build aprovados. Diff/staged/segredos e check_release
aprovados antes dos commits. Starlette emitiu aviso preexistente de depreciação
TestClient/httpx; não foi ocultado. Suítes menores anteriores se sobrepõem a esses
97casos, sem somar como testes distintos. A CLI do E2E é carregada com `runpy`,
trocando somente seu caminho de cache pela cópia temporária.

As credenciais desatualizadas do `.env` causaram19erros de setup na primeira
rodada; seleção das credenciais dos serviços locais ocorreu somente no processo,
sem editar `.env`, usuários ou grants. Uma invocação Vitest no diretório errado
falhou sem ambienteDOM; tipos do teste também foram corrigidos. Três tentativas
iniciais do roteiro falharam por campo de laboratório, espera de login e texto do
botão; seus processos/schemas foram encerrados. Rodadas bem-sucedidas anteriores
não são contadas como novos casos. A inspeção visual posterior revelou corte de
botão móvel; corrigido e o último ensaio repetido com assert geométrico específico.
Provas de tentativas permanecem em `.local/attack-admin/acceptance-*`.

## Recibos da rodada final e encerramento

Diretório privado local: `.local/attack-admin/acceptance-c3a79p9j/`.
RunDemo: `37f24a0b-fb95-49a5-85e8-f47bf4dc92b2`.
Schema descartável removido: `aegis_attack_review_13c8185d7f0543df936e4373f0d9ea54`.

| Artefato local | SHA256 |
|---|---|
| summary.json | `b60266044688b254b6da240bbde4472b7a7594b1ead24a6dbbd1196cdfe70bc6` |
| before-desktop.png | `5acb200bb246af4b8e45564ef63df58d2075cadf0c94c2a39d663125eb0b6855` |
| before-mobile.png | `5600d0ff0808f5a9bd1801cc1455c20130ef27b7792061183d2f284605218362` |
| instruction-mobile.png | `5c85129ea53b22c13030512f68fc2ef72ccff0169dc294f77b200c01557ab3db` |
| after-desktop.png | `a2459ef3d595c34c9489df1fe7c1122f4f516bca103708956b20ad13ceb714c1` |
| after-mobile.png | `8c37a9719a09a6d9298a8e6045c27000bdab35dfa23683a8eb02a5b4103876e7` |
| JSON histórico antes/depois | `19bacd75209d409d26d96638b22c6c85f7d9a6589f1343e3c287e1ae189ca4fd` |
| HTML histórico antes/depois | `0763fb11bb6e21ef2a0e8522c774bf2bea17cfb0b44a8592375853505d500f72` |
| PDF histórico antes/depois | `cf051a07639fef6d5c1ddec11ec03919342f74c63444597a1558b0176436dc6c` |

Processos próprios encerrados, schema removido e chaves de limite do usuário
próprio removidas. Consulta posterior encontrou **zero schemas**
`aegis_attack_review_*`. Bytes de todos os arquivos do candidato original
conferidos antes/depois, sem mudança. Cache/capturas/recibos/logs privados não
foram adicionados ao Git. Nenhum volume original, backup, PKI, journal ou fence
foi aberto para escrita/migração/replay.

O Demo ativo continuou ready200, API/worker na imagem anterior
`sha256:b8abe5e44af4bad90d2e302a045f38fb9cf268932be5ea0493fc72f078657a23`.
Não houve implantação desta feature no Demo ativo. Ensaios e publicação descritos
são locais/descartáveis; não comprovam nova versãoMITRE, operaçãoSIEM ou eficácia
defensiva. A visibilidade preexistente do repositório não foi alterada.

## Validação integral da fonte

A primeira tentativa da CI [45199031895](https://github.com/Buraddomoon/AEGIS/actions/runs/45199031895)
na fonte `57f2bba578fc03554b23884a001084dd6832f79a` terminou com falha na partição2:
`test_benign_behavior_campaign_uses_durable_dispatch_and_independent_verdict`
(perfil `linux-shell-canary/v1`) encontrou `sqlite3.OperationalError: database is
locked` em `Journal.connection`, no `PRAGMA synchronous=FULL`. Resultado:
3876Python passaram,9skips opcionais e1falha; React125 passou. Não é CI verde.

`journal.py` e `test_linux_campaigns.py` não mudaram entre a base `fbab8d2` e essa
fonte. As duas parametrizações do caso passaram em rechecagem local sequencial
(**2passed**, runner/TestClient temporários, sem laboratório nativo). Isso não
explica sozinho a contenção remota nem apaga a falha. Foi solicitada nova execução
**integral** da mesma workflow/fonte, sem filtros, exclusões, alteração de timeout,
partição, Journal ou semântica do teste. Contagens dessa rechecagem local são
separadas dos97casos ATT&CK/migração e do resultado da CI.

A [segunda tentativa integral](https://github.com/Buraddomoon/AEGIS/actions/runs/45199031895/attempts/2)
terminou **SUCCESS**, mesma fonte, cinco jobs aprovados conferidos individualmente:

| Job | Passaram | Skips opcionais | Tempo pytest |
|---|---:|---:|---:|
| Python0 | 962 | 2 | 199,91s |
| Python1 | 931 | 2 | 324,36s |
| Python2 | 1060 | 1 | 272,80s |
| Python3 | 924 | 4 | 202,06s |
| TotalPython | **3877** | **9** | Partições complementares |
| React | **125/18arquivos** | 0 | Job aprovado |

Os9skips existentes correspondem a inspeções opt-in de imagens/API/banco/rede/
objetosDemo ausentes e ferramentasPG locais indisponíveis; não foram criados
recursos para contorná-los. O teste Linux que falhou na primeira tentativa passou
na segunda. Lint/tipos/formatação/build e auditorias incluídos: Python1finding
já revisado, npm0vulnerabilidades reportadas nessa execução; isso não garante
inexistência de vulnerabilidades.21casos de segurança do glob também passaram.

Manifesto dos520arquivos não Markdown, em ordem de `git ls-files`, codificando
`caminho + NUL + SHA256(bytes) + LF`, SHA256 final:
`12ff1b16ce8ca98886a3967c55b5d2976a4a4b0fc458787db376fff45701fd62`.
A consolidação posterior altera somente Markdown e preserva esses inputs.
As runs anteriores de CI dos commits intermediários foram canceladas pela
concorrência da workflow; não são apresentadas como validação integral aprovada.

## Aceite conjunto e parada

#92: inventário/diff/impactos bounded e administrativo, artefatos/hashes exatos,
recusas sem publicação/download web. #93: revisão completa e instrução local,
drift/races bloqueados e estado real da publicação vindo da API. #94: percurso
CLI/Firefox em ambiente descartável, concorrência/rollback, releases/relatórios
imutáveis e limites entre fixtures, candidato oficial e implantação documentados.

Critérios conjuntos da #19 atendidos em23/11, sem bloqueadores remanescentes desse
escopo. A feature permanece opt-in e **não implantada no Demo ativo**; publicar no
ambiente de uso exige procedimento próprio e não foi necessário para este aceite
offline. Commits e sincronização finais constam nos comentários da #94/#19.
**Entrega encerrada. Parar sem iniciar outra feature, implantação ou laboratório.**
