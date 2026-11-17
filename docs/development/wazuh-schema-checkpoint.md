# Consulta Wazuh com perfis explícitos — #8

Checkpoint17/11/2026. Escopo exclusivo: #61 → #62 → #63. A entrega pai
permanece **pendente**, pois a validação externa da #63 exige autorização
específica ainda ausente. Não iniciar laboratório a partir deste documento.

## Implementado e testado localmente

- `6ac9cca` — `feat(wazuh): add explicit 4.14.9 collection profiles (Refs #61)`.
  Perfis fechados para `timestamp` e `@timestamp`, fontes oficiais fixadas em
  v4.14.9, fixtures com identidade fictícia/offset explícito, recusa de perfil
  desconhecido/drift e paginação incompleta. Contrato legado preservado.
- `fbe192d` — `fix(wazuh): retain source availability and collection diagnostics (Refs #62)`.
  Disponibilidade por fonte, archives não configurados/vazios, HTTP401/403/404,
  timeout/transporte/schema/janela incompletos, motivos preservados em polling e
  persistência. Worker/API/relatório testados com perfil explícito. Regras de
  domínio1.1 preservadas, sem recalcular evidência histórica.

Contrato e matriz de suporte em [integração Wazuh](../integrations/wazuh.md).
Os perfis novos foram testados **por contrato local**, sem ensaio nativo ou
implantação. Evidência histórica4.14.9/alertas sob política legada não valida
retroativamente os perfis novos ou archives.

## Verificação executada

- `.venv/bin/pytest tests/test_wazuh_profiles.py tests/test_wazuh_collection.py tests/test_wazuh_tls.py -q`:
  **57passed**,2,23s, na #61.
- `make test-wazuh` atualizado: **98passed**,37,22s, na fonte da #62; fixtures
  HTTP, TLS real de loopback, PostgreSQL/schema descartável e Redis15. Sem SIEM
  externo. Inclui os testes de perfis; não somar às57aprovações anteriores.
- `.venv/bin/pytest tests/test_integrations.py tests/test_domain.py -q`:
  **36passed**,1,97s; executados após a suíte anterior.
- `make lint`: Ruff, formatação336arquivosPython, mypy e TypeScript/Prettier
  aprovados. Revisão staged/segredos, `git diff --cached --check`,
  `.venv/bin/python scripts/check_staged.py` e
  `.venv/bin/python scripts/check_release.py` aprovados antes de cada commit.
- Aviso upstream Starlette/httpx preservado. A primeira tentativa de integração
  teve50passed/10erros de setup por senha PG desatualizada no checkout. Selecionar
  credenciais dos serviços locais existentes **somente no ambiente do processo**
  resolveu o acesso; nenhum arquivo, conta, senha ou grant original alterado.

As98+36aprovações são validação local complementar. O estado da CI da fonte final,
quatro grupos Python e React, deve ser conferido nos comentários da issue; não
confundir source-review documental com CI integral. Sem novo E2E/build/imagem,
release, implantação ou ensaio Wazuh/Linux. Demo ativo preservado.

## Bloqueio externo — #63

Perfil selecionado para um futuro escopo específico: **`wazuh-4.14.9/1`**,
`timestamp`, alertas `wazuh-alerts-4.x-*`; archives permanecem opcionais e não
ativados. O segundo perfil permanece somente contratual. A escolha não concede
autorização de acesso, startup, ingestão ou marcador.

Não existe no corpo/comentários da #8/#63 uma autorização específica vigente
para consultar um alvo externo ou reabrir os laboratórios. Os pacotes históricos
descritos em AGENTS estão consumidos. Nenhum deles foi reutilizado.

Para remover o bloqueio, um escopo humano deve identificar infraestrutura/versão,
alvo/IP/CA e principal de leitura, lab/ativo/agente, índices disponíveis,
identificadores e intervalo temporal dos eventos que podem ser consultados,
limites/duração e destino protegido das evidências. Search/Scroll e cleanup de
cursor são operações do leitor; não habilitar archives, ingestão ou privilégios
de administração implicitamente. Se o alvo exigir startup, clone, abertura de
volumes ou efeito novo, esses efeitos precisam de autorização própria antes de
executar. Não há instalação/download de stack nesta preparação.

O futuro aceite deve registrar política/hash e versão real independentemente da
resposta raiz de compatibilidade, consultas/IDs/timezone, completude/shards/scroll,
ACL/TLS e cleanup, comparando comportamento observado com a matriz contratual.
Não reescrever runs/approvals/PKI/journals/fences nem converter fixture em prova
externa. Até esse ensaio, #63 e #8 ficam abertas. Parar aqui.
