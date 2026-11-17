# Base demonstrável consolidada — #12

Aceite em17/11/2026, código0.2.0; ensaios Demo em16/11. Escopo exclusivo
[#12](https://github.com/Buraddomoon/AEGIS/issues/12) e filhas#72→#73→#74.
Bloqueadores#2/#10/#11 conferidos fechados antes dos efeitos. Nenhuma próxima
feature, release publicada ou operação de laboratório decorre deste checkpoint.

| Unidade | Resultado / prova |
|---|---|
| #72 | [Revisão de controles](../evidence/release-2026-11-16/SECURITY.md),181testes aprovados, auditoria Python1finding revisado/npm0; limites e achados explícitos |
| #73 | [Instalação nova e dois percursos Firefox](../evidence/release-2026-11-16/INSTALL.md), cada um5runs/20Demo/2snapshots/4PDFs/zeroerrosJS; cleanup e fonte preservada |
| #74 | [Matriz corrente](../product/acceptance-criteria.md), README/release/guia/testes coerentes; texto anterior preservado em arquivo histórico, links/staged verificados |

## Fonte, CI e imagens distintas

Fonte inicial `c2bf012537c58f942ab1c5e551882159ff01a494`; commit executável mais
recente `a8db6daf83941fefcda93fa109f9a996d791c27e`. Commits desta entrega
alteram **somente Markdown**, sem dependências, aplicação, testes ou workflows:

- `590b0ea`: `docs(security): review current controls and dependency findings (Refs #72)`.
- `14143df`: `docs(qa): prove clean Demo install and browser flow (Refs #73)`.
- O commit de consolidação `docs(release): consolidate demonstrable acceptance and limits (Refs #74)`
  publica este checkpoint; hash final, push e source-review ficam nas issues#74/#12.

A [CI integral43954449487](https://github.com/Buraddomoon/AEGIS/actions/runs/43954449487)
terminou SUCCESS na fonte `a8db6da` em16/11. API/jobs/etapas/logs conferidos,
quatro grupos e React aprovados, sem alteração de filtros/particionador/timeout:

| Job | Passed | Skips | Tempo pytest |
|---|---:|---:|---:|
| Python0 | 858 | 2 | 122,11s |
| Python1 | 813 | 2 | 308,98s |
| Python2 | 918 | 1 | 180,47s |
| Python3 | 846 | 4 | 193,39s |
| Total Python | **3435** | **9** | — |
| React | **91** (15arquivos) | 0 | — |

Skips existentes:projeção opt-in de imagem, API/DB/rede Demo ausentes, ferramenta
PostgreSQL local indisponível e quatro inspeções Wazuh sem objeto próprio.
Nenhum objeto ausente foi criado para simular inspeção aprovada. Um aviso
Starlette/httpx por grupo. Lint/tipos/auditoria Python no0 e checks completos
React aprovados. Não somar181testes locais à suíte remota como casos distintos.

Equivalência dos inputs de CI verificada entre `a8db6da` e esta consolidação:
**441arquivos**, SHA256
`92b859e3ce7f062ce3613cda6ac3cfb5d1c8c7d225b2a289d61e8e5c58c3849b`.
Método: linhas de `git ls-tree -r COMMIT` na ordem Git, removendo paths `.md`,
`docs/images/**` e `LICENSE` conforme paths-ignore; juntar por LF com LF final.
Listas completas comparadas além do digest. Isso comprova os mesmos inputs,
sem afirmar nova execução integral da CI em cada hash documental. Source-review
é outro workflow; resultados finais/URLs são registrados nas issues.

Demo persistente:imagem
`sha256:b8abe5e44af4bad90d2e302a045f38fb9cf268932be5ea0493fc72f078657a23`,
sem label OCI de revisão, historicamente associada a0609ad2. Inspeção confirma ID,
não equivalência binária com a fonte atual. Sem atualização/restart/migração.
Inventário completo:33tabelas/3399linhas, hashes/IDs/imagens/mounts/estados e
configuração idênticos antes/depois dos ensaios e reconferidos em17/11.
Tag dedicada `aegis-preserved:issue12-20261116-b8abe5e44af4` retém a imagem.

Imagem atual construída/testada no Compose descartável:
`aegis-issue12:590b0ea`, ID
`sha256:1c7da571dfd19586a1f274c091d0e69c7b2cf55354d6656cf40f49629ef190c5`.
Retida localmente;0containers/redes/volumes do projeto ao final;0schemas E2E e
portas18784/18786 livres. Nenhum push de imagem/registry, tag Git ou release.

## Limites e handoff

A [matriz](../product/acceptance-criteria.md) aponta as provas atuais Linux/Wazuh
já encerradas, recuperação, PDF e Sigma; não reapresenta como faltante o que foi
entregue. Futuro opcional não bloqueia o MVP. GitHub informou PUBLIC também em17/11,
divergente da política privada; sem mudar visibilidade ou declarar privacidade
atendida. DiskCache mantém1advisory médio revisado, sem supressão. Sem promessa
enterprise-ready, eficácia geral defensiva, operação real contínua ou RPO/RTO.

Primeira rodada de segurança teve139passed/24errors por auth Redis omitida no
wrapper privado; configuração local também divergia dos serviços ativos. Corrigido
somente o transporte em memória, sem reset/senha/controle alterado;181passed na
rodada final. Dois percursos da #73 passaram sem correção de código. Testes não
foram repetidos na retomada de17/11; foi reconferida a preservação da fonte.

Logs, config, capturas, PDFs, HTMLs e inventários completos ficam privados em
`.local/issue12`. Somente resumos revisados vão ao Git/issues. Nenhum PROGRESS
inteiro ou chat antigo foi necessário. Para outra sessão, escolher explicitamente
uma issue no índice e seguir o guia; não reusar autorizações consumidas nem
iniciar outra capacidade a partir desta entrega. Encerrar após aceite das filhas,
registro final do pai e sincronização de main.
