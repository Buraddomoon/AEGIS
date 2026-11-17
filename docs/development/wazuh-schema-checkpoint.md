# Consulta Wazuh com perfis explícitos — #8

Checkpoint17/11/2026. Escopo exclusivo: #61 → #62 → #63. **Aceite conjunto
atendido**, após o usuário autorizar explicitamente a retomada da #63.
[Ensaio nativo NATIVE_PROFILE_QUERY_VERIFIED/CLEANED](../evidence/wazuh-schema-2026-11-17/README.md).
Pacotes/autorização consumidos; não iniciar laboratório a partir deste documento.

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
O perfil `wazuh-4.14.9/1` foi depois consultado nativamente no Indexer4.14.9,
com alerta original da #59, sem nova run/marcador. Perfil `@timestamp` e eventos
de archives permanecem **só contratuais**. Evidência histórica sob política
legada não foi renomeada/reclassificada; o novo ensaio tem registro próprio.

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
confundir source-review documental com CI integral. Na #63, `make test-wazuh-schema`
teve84passed/1,37s, lint completo aprovado e validação nativa separada. Sem novo
E2E/build/imagem/release ou implantação permanente. Demo ativo preservado.

## Bloqueio externo resolvido — #63

O bloqueio inicial era ausência de autorização específica. O usuário retomou
explicitamente a #63 após esse registro. Escopos e tentativas foram registrados
na issue antes dos efeitos; falhas anteriores preservadas/CLEANED, sem reutilizar
pacote. O [procedimento](../../labs/wazuh/SCHEMA-QUERY-ASSAY.md) descreve o escopo
histórico, correções do leitor/CLI e limites. Não concede autorização futura.

Final `f3297fc7b401419ebbcecb3c8a7d0451`, fonte executável3a758a6,
13:30:35–13:30:55UTC: somente Indexer e leitor; TLS1.3/CA/SNI/IP/ACL e perfil
`wazuh-4.14.9/1`/`timestamp` conferidos. Alerta original idêntico em índice/id/
conteúdo/tempo; total exato e negativa vazia completos, três DELETEs de cursor
confirmados. Archives404/indisponíveis, sem ativação ou inferência de falha.

Zero novas runs/marcadores/vereditos e requisições de escrita de documento;
histórico/bindings/contas/PKI intactos. Fonte/probes montadosRO, sem build/pull,
sem banco/API/worker da plataforma, runner/observador, manager/agente. Recursos
próprios removidos e nove volumes preservados/zero consumidores. Inicialização
normal do Indexer pode escrever estado/logs no volume; não alegar igualdade física.

CI fbe192d44086844300 concluída SUCCESS, quatro grupos Python e React conferidos.
CI da fonte final do probe44093362930 é outra execução, cujo estado está nos
comentários da #63/#8. Relatório lista hashes/tentativas/limitações. Não extrapolar
para archives, outras versões ou eficácia SIEM/EDR. Entrega #8 atendida; parar aqui.
