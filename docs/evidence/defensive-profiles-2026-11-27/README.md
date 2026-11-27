# Conexões defensivas — aceite offline da #26

Escopo exclusivo: #111, #112 e #113; entrega operacional **offline**.
Fonte final `b3b00a5b831650c994d3f524fe0d8a692198c251`.
Nenhum ensaio SIEM nativo, implantação ou autorização de laboratório é inferido.

## Comportamento entregue

- #111: catálogo host-only opt-in `DEFENSIVE_PROFILES`, formato fechado, IDs e
  revisões, CA/IP/TLS e credenciais por arquivos privados protegidos. Referências
  e valores não são devolvidos pela API nem persistidos no banco/auditoria.
  Proxies/redirects/DNS dinâmico não substituem o destino revisado. CA e principal,
  política, referências e revisão participam do hash público; senha não participa.
  Rotação de senha no mesmo arquivo exige incremento explícito da revisão.
- #112: seleção/revisão por hash, mudança invalida binding/escopo anterior,
  desativação com histórico preservado e diagnóstico limitado a um `GET /`.
  Lock/pré-requisitos do lab, RBAC/CSRF e limites existentes são reaproveitados.
  Diagnóstico retorna estado/data/hash e auditoria sanitizada; erro não significa
  zero eventos. Verifica drift antes do transporte e depois da resposta.
- #113: seleção de perfil conhecido/revisão/política/hash, confirmação descartada
  em troca, recarga ou falha, consulta Viewer e ações administrativas. Nenhum campo
  URL/caminho/credencial ou armazenamento local de token. Ações quebram linha no
  mobile e resultado sanitizado é legível. Configuração padrão continua opt-out.

Não foi necessária migração: o binding existente persiste somente o hash, e o
perfil atual é resolvido por correspondência exata. Não há fallback do catálogo
inválido para o ambiente legado. Sem opt-in, o fluxo de ambiente anterior continua.
Compose repassa a variável sem montar referências privadas automaticamente.

## Verificações locais executadas

- `pytest tests/test_defensive_profiles.py tests/test_wazuh_tls.py tests/test_wazuh_collection.py tests/test_wazuh_availability.py -q --tb=short`: **74passed**.
  Arquivos/PKI temporários, HTTP em memória e TLS loopback. Inclui permissões,
  symlink/FIFO/tamanho, duplicatas, destinos proibidos, drift, proxies, SNI e CA.
- `pytest tests/test_defensive_connector_api.py tests/test_wazuh_campaigns.py tests/test_binding_review.py tests/test_security.py tests/test_integrations.py -q --tb=short`: **95passed**.
  PostgreSQL/schema descartável e Redis15, credenciais somente no processo.
  Inclui RBAC/CSRF/limites, perfil ausente, diagnóstico positivo/indisponível/stale,
  auditoria, hashes e coleta/histórico legados. Runner fixture não é laboratório.
- React completo: **177passed/23arquivos** e **21checks glob**. Após o último ajuste
  de apresentação, componente Wazuh: **9passed** e21checks glob; CI final é prova
  distinta do conjunto completo da fonte publicada.
- Ruff, formato Python, mypy, TypeScript, Prettier e build aprovados.
  `docker compose config --quiet` validou somente a configuração; não iniciou stack.
- Antes dos commits: staged/diff/segredos revisados, `git diff --cached --check`,
  `scripts/check_staged.py` e `scripts/check_release.py` aprovados.

A credencial padrão local do PG foi recusada na primeira tentativa. A execução
válida selecionou credenciais dos serviços já existentes somente no processo;
nenhum `.env`, usuário, grant ou serviço foi alterado para resolver esse acesso.
Os primeiros fixtures novos tiveram erros de construção/CA; foram corrigidos e
reexecutados sem skips/exclusões. Os logs locais preservam os resultados.

## Firefox/API/TLS descartáveis

Comando: `.venv/bin/python scripts/defensive_profiles_e2e.py`, após build,
com credenciais de teste somente no ambiente do processo.

Pacote final host-only: `.local/defensive-profiles/acceptance-iscku_zq`.
Resultado **VERIFIED**, `synthetic=true`, `deployed=false`, `native_lab_contacted=false`.
Firefox real, API real sem interceptação no navegador, catálogo/conta/ativo/lab
somente de fixture, schema exclusivo e CA/servidor HTTPS temporários.

O processo de API exclusivo do harness mapeia somente o pin192.0.2.10 para o
servidor próprio em loopback; a CA e o SNI originais são verificados pelo transporte
HTTPX real. **Não comprova conectividade com Wazuh/Indexer nativo.**

Selecionou perfil, registrou revisão, descartou confirmação, consultou transporte,
recusou texto upstream na UI, capturou1440/390px sem overflow horizontal e removeu
o vínculo por interação real. **Zero erros JS**, duas capturas, servidor recebeu
exatamente **um `GET /`**, nenhuma pesquisa de eventos. Finally confirmou schema
removido e API/TLS próprios encerrados. PKI/credenciais temporárias ficam privadas
no host e não são anexadas ao Git/issue.

| Artefato local | SHA-256 |
| --- | --- |
| `summary.json` | `0c131dbf4166b895204996b8786aa35470476a2e00618919f9423c81659dcd9d` |
| `profiles-desktop.png` | `d648c2738266a89cf5c54ebd4fa08a8497721fc1b395cc41c27e64345a8c9401` |
| `profiles-mobile.png` | `dec0600a2bfc1e2629d72bbd57cb77dd8706d953530b32150bf99432660450fa` |

Falhas anteriores preservadas: rota do harness, reserva temporária de porta,
interação/scroll de checkbox e largura insuficiente das três ações no mobile.
A largura foi corrigida no produto com quebra de linha; a captura passou a usar
viewport para não redimensionar o dialog durante full-page em Firefox. Pacotes
anteriores `b3fd4gqm`, `kn2xat8k`, `btz4y86d`, `6e4o8v0j` ficaram FAILED e encerrados;
a tentativa de porta falhou antes de criar recursos. `wxucg3o6` e `mxhak6uy` tiveram
VERIFIED intermediário; o pacote acima verifica o último ajuste legível de data e
mensagem. Nenhum desses registros é apresentado como prova nativa.

## Fonte, preservação e limites

Commits de implementação, todos enviados diretamente para `origin/main`:

- `40507cb` — `feat(security): resolve defensive profiles from protected host references` (Refs#111).
- `fe6a94f` — `feat(api): review and diagnose bounded defensive connector profiles` (Refs#111/#112).
- `b3b00a5` — `feat(ui): manage reviewed defensive profiles without exposing credentials` (Refs#111/#112/#113).

Arquivos centrais: `integrations/defensive_profiles.py`, `integrations/wazuh_config.py`,
`integrations/wazuh.py`, `telemetry.py`, `schemas.py`, `api.py`, `WazuhBinding.tsx`,
`Management.tsx`, testes/roteiro E2E e [procedimento de operação](../../operations/defensive-profiles.md).

API/worker Demo continuam na imagem preexistente
`b8abe5e44af4bad90d2e302a045f38fb9cf268932be5ea0493fc72f078657a23`,
com início registrado em27/11 às12:21:25UTC, anterior a esta implementação.
Nenhum build Docker/deploy/reset de conta, migração de original, alteração qasrc,
abertura de volume Lab, marcador ou operação Linux/Wazuh/SIEM ocorreu nesta sessão.
A visibilidade pública preexistente diverge da política privada; não foi alterada.

A validação Sigma nativa mantém o escopo host-only legado separado: com catálogo
opt-in não escolhe perfil implicitamente e fica bloqueada, sem fallback. Nenhuma
autorização Sigma histórica é renovada por este cadastro.

## CI integral e aceite conjunto

[Workflow46007425372](https://github.com/Buraddomoon/AEGIS/actions/runs/46007425372)
**SUCCESS** na fonte `b3b00a5b831650c994d3f524fe0d8a692198c251`.
Quatro jobs Python e React conferidos individualmente, sem filtros/exclusões novos.

| Job | Resultado |
| --- | --- |
| Python partition0 | 1010passed / 2skipped |
| Python partition1 | 1053passed / 2skipped |
| Python partition2 | 1081passed / 1skipped |
| Python partition3 | 1111passed / 4skipped |
| React | 177passed / 23arquivos e21checks glob |

Total **4255Python / 9skips opcionais existentes**. Lint/tipos/auditoria de
Python e lint/formato/build/auditoria React aprovados no workflow. Runs anteriores
46005612465/46006710894 foram canceladas pelo avanço da fonte sob concurrency;
não são apresentadas como workflows verdes. Logs sanitizados e metadata final
preservados em `.local/issue26/ci-*`.

Aceite conjunto da #26 conferido em27/11: #111 define configuração segura sem
receber destino arbitrário; #112 entrega revisão/saúde limitada e desativação;
#113 demonstra a operação web, permissões e invalidação da confirmação. Os
critérios offline estão atendidos, com prova local, Firefox/TLS e CI distintos.
Não há pendência externa necessária a este escopo offline. Configuração, teste
por fixture e implantação/ensaio nativo continuam explicitamente separados.

Commit final de documentação e sincronização serão registrados nos comentários
das issues. **Parar nesta entrega**, sem nova feature ou autorização operacional.
