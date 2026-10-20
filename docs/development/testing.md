# Testes e evidências

`make infra` é pré-requisito dos testes de integração. `make test-unit` não exige serviços. `make test` roda pytest e Vitest; `make lint` verifica Ruff/format, mypy do domínio e TypeScript/Prettier; `make build` constrói a SPA.

PostgreSQL real é usado com um schema aleatório por sessão. A fixture aplica Alembic e trunca apenas tabelas desse schema entre testes, removendo o schema criado ao finalizar. Redis utiliza DB 15 nos testes de API, com chaves somente do namespace ÆGIS. Não usar Redis DB 14/15 para dados importantes no ambiente de desenvolvimento.

Suíte cobre identidade/CSRF/RBAC, ausência de segredos nas respostas, limite de payload/login, aprovação e alteração de escopo, estado, concorrência de claim/entrega, cancelamento, timeout, cleanup, recuperação, classificação/correlação, persistência, duplicação, relatório HTML seguro, versão Sigma, YAML inseguro, pinning TLS, paginação Wazuh e upgrade de banco populado. Agendamentos cobrem grant original, limite persistente, expiração, busy, atraso, rollback, dispatcher concorrente, pausa/retomada, revogação ativa com cleanup e alterações de autorização/escopo.

## E2E real

`make e2e` constrói a aplicação, cria um schema descartável, aplica migrações e seed, cria administrador com senha aleatória em memória, inicia API/worker separados e utiliza Puppeteer Core com o Firefox do host. Nenhum navegador é instalado automaticamente. Variáveis opcionais: `AEGIS_BROWSER=chrome`, `AEGIS_BROWSER_PATH=/caminho/navegador`. Não desabilitar sandbox ou certificados para passar o teste.

Fluxo: login → catálogo → campanha → revisão/aprovação → início → worker → eventos/evidências → exportação → nova solicitação → nova aprovação → comparação → indicadores → criação e aprovação de agendamento → ocorrência automática no worker → relatório com grant de origem → páginas auxiliares → viewport móvel. O script valida respostas reais e produz `docs/images/*.png`. Schemas e processos do teste são removidos em finally; logs ficam em `.local/e2e/`, ignorados pelo Git. Capturas não contêm credenciais.

Fixtures Wazuh usam `httpx.MockTransport`, sem rede, e representam testes de contrato escritos manualmente, com identificadores fictícios; não comprovam integração real. Testes de componentes podem simular respostas para estados vazios/erro, enquanto o fluxo E2E não usa mocks.

## Resultado inicial observado

Na primeira rodada ampliada: 52 testes backend passaram; 3 testes frontend passaram; E2E Firefox concluiu 2 runs / 8 testes sintéticos com zero erros JavaScript. Docker build e Compose completo foram executados, health ready retornou database/redis true, runtime confirmou `aegis_app` sem superuser e sem UPDATE em auditoria. Consulte `docs/PROGRESS.md` para a validação final mais recente e limitações.

Existe aviso de depreciação do upstream Starlette para o transporte httpx de TestClient; os testes executam com sucesso, sem ocultar o aviso. Migração para httpx2 poderá ser avaliada separadamente.

## Marco de agendamento Demo

Na rodada ampliada: **85 testes Python** e **5 testes frontend** passaram; E2E Firefox concluiu **3 runs / 12 testes sintéticos**, incluindo agendamento automático, com zero erros JavaScript. O smoke Compose inclui run manual e agendada, verificação de grant, relatório e revogação usando API/worker com papel SQL restrito. Consulte PROGRESS para comandos e CI final.
