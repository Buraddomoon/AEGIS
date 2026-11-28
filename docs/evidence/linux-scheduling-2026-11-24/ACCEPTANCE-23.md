# Aceite conjunto — #23

Critérios da entrega e de #102/#103/#104 atendidos em27/11/2026
America/Sao_Paulo (28/11UTC nas provas finais). Escopo encerrado; não iniciar
outra feature, reutilizar pacote consumido ou habilitar operação contínua.

| Unidade | Resultado e prova |
|---|---|
| #102 — grant real delimitado | Opt-in desligado por padrão, marcador fixo, snapshot/hash, validade/orçamento/concorrência, aprovação segregada e revalidação de usuários/preflight/versões. Política/expiração/revogação/locks em testes e CI; grant real único nas duas ocorrências finais. |
| #103 — emissão e recuperação | Emissão/reserva/fila/approval/report atômicos, dispatch antes de RPC, lease/fences e reserva retida em ambiguidade/cleanup falho. Testes PostgreSQL de crashes/respostas perdidas; duas runs nativas distintas, recibos/cleanups e snapshots reais. |
| #104 — UI e recorrência autorizada | Proposta e revisão na UI por contas distintas, duas ocorrências reais43bytes,60s/30s/concorrência1. `NATIVE_RECURRENCE_VERIFIED_CLEANED`, JSON/HTML/PDF e1440/390px, zero erros JS. [Prova nativa](VERIFIED-104.md). |
| Integridade e encerramento | Originais preservados, nenhum efeito no Windows, históricos congelados idênticos após revogação. Agenda/lab revogados, contas inativas/zero sessões, workspace vazio e recursos próprios encerrados. [Tentativas anteriores](INCIDENTS-104.md) preservadas sem efeitos. |

## Validação final da fonte atual

Fonte `4812780c90c9f8aead155de5fe9fe17bef070d40`,
`fix(scheduling): reload native proposal UI and pin compatible fresh schema (Refs #104)`.
[CI46090184659](https://github.com/Buraddomoon/AEGIS/actions/runs/46090184659)
**SUCCESS** na primeira tentativa. Quatro jobs Python e React conferidos, sem
filtros/exclusões ou alteração dos limites da CI:

| Partição | Passaram | Skips previstos | Tempo pytest |
|---|---:|---:|---:|
| 0 | 1016 | 2 | 148,70s |
| 1 | 1096 | 2 | 264,25s |
| 2 | 1081 | 1 | 370,34s |
| 3 | 1111 | 4 | 268,32s |
| Total Python | 4304 | 9 | — |

React:186testes/24arquivos,21checks glob; lint/formatação/tipos/build e auditoria
passaram. Aviso upstream Starlette/TestClient-httpx e nove skips existentes não
foram ocultados. Localmente, preparação/política:56passaram; Ruff check/format,
mypy, sintaxe/Prettier Node e checks staged/release aprovados. Prettier inicialmente
apontou estilo do cliente; write seguido de check passou antes do commit.

[Ensaio nativo46090496469](https://github.com/Buraddomoon/AEGIS/actions/runs/46090496469)
**SUCCESS**, mesma fonte. Pacote `caa9078d…`, duas ocorrências e dois snapshots,
com conferência independente dos hashes, origem, grant, recibos, cleanup, PDFs e
encerramento. Efeitos totais de todas as tentativas desta entrega: **dois**.
Preparação46090198892 falhou no browser antes de criar qualquer pacote/Lab;
tentativa nova na mesma fonte passou, sem remover smoke ou afrouxar o gate.

E2E Demo histórico da implementação: [45504677648](https://github.com/Buraddomoon/AEGIS/actions/runs/45504677648),
fonte d46850c, SUCCESS,5runs/20testes sintéticos/2snapshots/5PDFs/zero erros JS.
Esse resultado não é atribuído à fonte atual. A CI atual exerce componentes e
regressões Demo; a prova atual da UI/recorrência Linux é o ensaio separado acima.

## Implementado, testado e implantado

Implementação original:03d7dd3 (grant/emissão),656caec (revisão/origem),d46850c
(modo confirmado). Preparação nativa:178e7df; correções de harness9af2139,
46d431d,5e4737a e4812780. Correções e falhas intermediárias estão registradas,
inclusive CI canceladas, sem reescrever planos, aprovações ou evidências.

Arquivos centrais: `apps/api/aegis/scheduling.py`, `linux_labs.py`, worker,
`scheduled_reports.py`, `scheduled_report_api.py`, API/config/schemas;
`apps/web/src/Scheduling.tsx` e `ScheduledReports.tsx`. Ensaio:
`.github/workflows/scheduling-native.yml`, `scripts/scheduling_assay.py`,
`scripts/scheduling_assay_service.py`, `apps/web/scheduling-native.mjs` e testes
de preparação/política/integração/origem. Procedimentos em
[scheduling.md](../../operations/scheduling.md) e
[scheduling-native.md](../../operations/scheduling-native.md).

Somente a VM nova recebeu a implantação temporária opt-in e migração explícita
f3b/36tabelas do banco vazio. Nenhuma implantação/migração em Demo ou originais,
nenhuma mudança de rede/sysctl/Docker do Windows, nenhum Wazuh/SIEM/Atomic/shell,
tag/release ou mudança de visibilidade. `synthetic=false` não implica eficácia
defensiva: resultados são INCONCLUSIVE, zero eventos e denominador elegível zero.

Artefatos sanitizados têm retenção7dias e cópia privada local; hashes e resumo
persistem nestes documentos/issue. Capturas full-page têm as limitações descritas
na prova nativa. Pacote/orçamento consumidos, sem replay, reativação ou operação
contínua. Commits finais documentais, último hash/mensagem e sincronização ficam
nos comentários finais das issues, após push direto em origin/main.
