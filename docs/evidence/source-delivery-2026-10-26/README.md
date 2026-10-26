# Consolidação de entrega — 2026-10-26

Escopo: configuração de instalação local, verificação de fonte/documentação e
apresentação do código 0.2.0. Sem atualização de dependências ou migração, novo
build/deploy de containers, ensaio Linux/Wazuh, acesso ao SIEM ou envio de backup.

## Validação efetivamente executada

| Comando/check | Resultado |
|---|---|
| `pytest tests/test_init_env.py -q` | 15 passed; temporários privados, sem tocar no .env humano |
| `pytest tests/test_repository_checks.py -q` | 6 passed; Git descartável, índice e redaction reais |
| `pytest tests/test_release_check.py -q` | 9 passed; inconsistências de versões/locks/links/PNG recusadas |
| `make test` |**744 Python passaram** em 256,64 s; **53 React passaram** em 3,52 s |
| `make lint` | Ruff/check/format, mypy domínio, TypeScript e Prettier aprovados |
| `make build` | SPA construída; sem alerta de chunk acima de 500 kB |
| `make audit` | npm: zero achados; Python: um advisory transitivo conhecido/revisado, visível |
| `pip check` | No broken requirements found |
| Gerador + Compose novos | Configuração temporária 0600/idempotente; cinco serviços, API 127.0.0.1:18780, DB/Redis não publicados, papéis SQL distintos e nenhum runner/coletor habilitado |
| `make release-check` | Índice Git, versões 0.2.0, links inline locais e 13 cabeçalhos PNG aprovados; contagens finais em PROGRESS |

Configuração de Compose apenas renderizada, com ambiente de subprocesso mínimo e
saída capturada sem segredos publicados; nenhum container foi iniciado. Esse check
não é um novo boot completo. Os três grupos de 30 casos novos estão também incluídos
nos 744 testes da suíte, não se somam a eles. Aviso upstream Starlette/TestClient/httpx
permanece visível.

CI principal do código executável 88e8c10: **SUCCESS**,
[run40392713839](https://github.com/Buraddomoon/AEGIS/actions/runs/40392713839).
Rodada remota: 740 passed / 4 skipped, 53 React, lint/tipos/build/auditoria. Os quatro
skips opcionais são projeções somente leitura do Docker próprio ausente na CI;
localmente passaram. Nenhum skip foi apresentado como validação externa.

CI leve documental de 0c99671: **SUCCESS**,
[run40393674005](https://github.com/Buraddomoon/AEGIS/actions/runs/40393674005).
Sem dependências/bancos/serviços, permissões read e cancelamento de redundantes.
Commits posteriores de evidência/progresso não alteram o código testado.

## Preservação do ambiente

Consultas somente leitura confirmaram schema a0d9c7e21b45,
32 tabelas incluindo alembic_version, 21 runs existentes, zero runs pendentes,
reservas ou agendamentos retomáveis; zero schemas pytest/E2E e nenhuma tabela
public com autovacuum desabilitado. API live/ready: 200, PostgreSQL/Redis saudáveis.

Imagem Demo preservada:
sha256:ef97abfdf122df5bd513f7a6e2a44c7ec84a3b89757e1698d04da0f0f8871a02.
API/worker não reiniciados; nenhuma conta/senha humana alterada. Os projetos
Linux/Wazuh continuam com zero containers; volumes/journals não foram removidos.

Capturas existentes overview/coverage foram inspecionadas visualmente. Não houve
nova rodada E2E nem alteração dos PNGs; a procedência das 13 imagens está na
[galeria](../../images/README.md). A presença de sintéticos nas imagens continua
explícita. O arquivo Linux representa somente consulta ao ensaio anterior fechado.

## Limites

Esta revisão não é pentest independente nem lançamento público. O scanner não
prova ausência de segredos; checker de PNG não prova procedência e links externos/
âncoras não foram testados. Versão continua 0.2.0, sem tag/Release ou visibilidade
alterada. Backups/chave continuam no host por decisão do usuário; nenhuma cópia
externa foi enviada. Não valida cutover, RPO/RTO, Windows ou conversão Sigma.
[Procedimento de entrega](../../operations/release.md) ·
[Revisão de segurança local](../../security/review-delivery-2026-10-26.md).
