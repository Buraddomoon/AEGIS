# Revisão persistida do vínculo — evidência de 2026-10-27

Incremento sobre f42bfed, sem novo ensaio Linux/Wazuh ou ativação de certificados.
[ADR0019](../../architecture/decisions/0019-runner-binding-review.md),
[operação](../../operations/linux-binding-review.md) e
[plano futuro](../../operations/runner-pki-activation.md).

## Software e regressões

- Rodada completa local: **882 Python passaram em 314,96s**; quatro opcionais de
  projeção Docker incluídos. **79 React passaram em 3,93s**. Log privado
  `.local/pki-milestone/binding-test.log`.
- Depois, cinco casos de recibo SUCCEEDED foram acrescentados. Suíte de revisão
  repetida: **48 passaram em 33,20s**, incluindo os cinco. São **887 casos Python
  distintos exercitados** e 887 coletados no estado final; não afirmar uma única
  rodada local completa de887. Nenhum código runtime mudou após a rodada completa.
- Integração dirigida: **70 passaram em 90,79s** antes dos cinco últimos casos;
  Linux/Wazuh usam fixtures locais. Revisão nova proíbe criar cliente runner.
- `make lint` passou: Ruff/format145 arquivos, mypy4 arquivos, TypeScript e
  Prettier. Sem nova dependência/migração. Aviso Starlette/TestClient-httpx mantido.
- `make e2e`: Firefox real, API/worker/PostgreSQL/Redis em schema próprio,
  **PASS**, quatro runs/16 testes, zero browserErrors. Build SPA aprovado.
  Doze capturas novas ficaram privadas; imagens históricas publicadas intactas.
  E2E é Demo e não comprova browser/ativação do runner real.

Primeira execução dirigida ainda carregava o teste antigo que permitia remover
binding com solicitação pendente: uma falha/69 sucessos. Contrato e teste foram
atualizados para409 → cancelamento explícito → remoção200 com escopo preservado;
reexecução de70 passou. Falha inicial não foi contada como aprovação.

## Revisão especializada

Revisão estática independente confirmou predicado fail-closed e identificou que
`request_run` ainda podia criar pedido após uma revisão, pois não participava do
lock do laboratório. A versão do ambiente já impedia iniciar aquele escopo, mas
a ausência estrita de pendências não estava serializada. Corrigido em99b6758:
Linux adquire lab FOR UPDATE/populate_existing antes de criar o scope. Teste
PostgreSQL concorrente prova espera/rejeição409/zero runs. Revisão final confirmou
as três mutações sob lock e GET administrativo READ ONLY/REPEATABLE READ, sem
bloqueador concreto nesse delta. Não houve pentest nem inspeção do journal real.

## Backup e implantação do Demo

Backup anterior ao deploy:
`20261027T133323Z-45b5e62652f24170b4fd16035c268162`, dumpSHA256
`b78d9528476e49899edb1583afda190ed58c8a487b2330ba02ba8ef7e914e7fb`.
Restore próprio offline conferiu **32 tabelas/3.390 linhas**, network=none,
application_started=false, clone removido; verificação em5,759s. Backup privado
em claro; não equivale a nova cópia cifrada, custódia externa ou cutover.

Guard READ ONLY antes da implantação confirmou schema a0d9c7e21b45,32 tabelas,
23 runs e zero runs não terminais/reservas/agendamentos retomáveis. Nenhuma
migração/seed foi executada. Somente API e worker Demo recriados, imagem:
`sha256:92ffbc4e1de7f47aa6f6e53636cf3a3d9e153cf869228e669f8263368bcaff7d`.
Imagem anterior ec57c8c preservada em `aegis-before-binding-review:20261027`;
DB/Redis, imagens/dumps anteriores e credenciais humanas preservados.

Consulta autenticada real ao endpoint do Demo retornou200/blocked com not_linux
e laboratory_authorized; flags de runner/diário/ativação/operação normal false.
Papel runtime conseguiu executar o snapshot e auditoria não mudou durante GET.
Logout confirmou401; ambas as contas temporárias de verificação desativadas,
zero sessões próprias remanescentes, mesmas23 runs. Primeiro verificador local
esperava somente not_linux e falhou por expectativa restrita; ajustado para
aceitar o conjunto real de bloqueios e repetido só o GET, sem mutação do lab.

Health ready/database/redis true em localhost18780. Linux/Wazuh sem containers.
Candidato PKI anterior reverificado, manifesto24179f34…8d5f ainda válido no
instante da consulta, sem ativação/banco/diário/lab. Isso não prolonga sua validade.

## Limites que permanecem

O GET é diagnóstico, não grant. Acima de1.000 dispatches falha fechado; amostra25
não substitui revisão ampliada. Confirmação persistida não comprova volume/diário
intactos nem estado do runner sob usuário/root host ou administrador SQL hostil.
Ativação coordenada, harness próprio, banco/diário Linux parado e recuperação sob
confiança alterada continuam pendentes. Autorizações anteriores consumidas;
sem marcador, start de laboratório, consulta SIEM, expurgo ou upload neste marco.
