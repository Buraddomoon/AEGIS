# Contas, papéis e sessões — #24

Estado em25/11/2026: implementação e validação **locais** de #105/#106/#107.
A entrega não está encerrada no GitHub: sincronização bloqueada por avanço
concorrente de `origin/main`. Não fechar filhos/pai nem anunciar implantação.

- Base local `5f6f880`; API `c0a0aa8`, UI `e1efb92`, apresentação `11c7601`,
  QA/roteiro `e468e73`.166Python,161React/21glob, lint/build e Firefox aprovados
  localmente; três contas/capturas, zero erros JS, sete schemas próprios removidos.
- Contas existentes podem ser ativadas/desativadas e trocar papel; último admin
  protegido por lock PostgreSQL. Senhas Argon2id e sessões revogadas por conta.
- Senha própria exige senha atual; redefinição administrativa para outra conta.
  Viewer/operator gerenciam apenas a própria senha/sessões. RBAC/CSRF/limites
  são do backend; interface confirma efeitos e descarta identidade/cache em401.
- Start/fila/worker/cleanup revalidam as identidades sem reescrever aprovações,
  escopos, resultados ou históricos. Testes usam schemas/contas descartáveis.
- Provas, comandos, falhas, capturas privadas e limitações no
  [registro de evidências](../evidence/user-maintenance-2026-11-25/README.md).
  Contratos operacionais em [autorização](../security/authorization.md).

O push de `c0a0aa8` foi rejeitado (`fetch first`). Fetch apenas de leitura confirmou
`origin/main=5e4737a`, dez commits posteriores à base, com sobreposição em
`api.py`, `linux_labs.py`, `schemas.py`, `worker.py`. Conforme AGENTS, sincronização
interrompida; sem merge, rebase, force push ou sobrescrita do remoto. Os commits
seguintes permanecem locais. A combinação com a fonte remota ainda não foi validada.

Demo b8 anterior preservado; nenhum deploy, alteração de conta humana, operação
Linux/Wazuh, volume original, marcador ou migração original. O roteiro Firefox
inicia somente API própria e aplica Alembic em schema novo, removido ao terminar.
Não iniciar outra entrega; retomar somente para resolver a sincronização e
revalidar a fonte integrada sob as instruções vigentes.
