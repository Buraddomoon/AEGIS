# Revisão dos controles atuais — #72, 16/11/2026

Escopo da [#12](https://github.com/Buraddomoon/AEGIS/issues/12), fonte inicial
`c2bf012537c58f942ab1c5e551882159ff01a494`, código0.2.0. Dependências #2/#10/#11
fechadas, conferidas no GitHub. Revisão limitada ao Demo e aos contratos/testes
existentes; sem iniciar Linux/Wazuh, renovar autorizações ou alterar controles.

## Controles revisados

| Área | Fonte e prova executada | Resultado / limite |
|---|---|---|
| Auth/RBAC/CSRF | `security.py`, `api.py`, `main.py`, `test_security.py` | Argon2id, sessão por hash, expiração/conta ativa, papéis backend, origem exata, header de login, CSRF, limites e redação de input; recusas testadas |
| SQL/runtime ACL | Predicados SQLAlchemy em auth/campanhas; `operations/runtime_grants.py`, `test_linux_schema_compatibility.py`, `test_recovered_demo_cycle.py` | Schema/banco/papéis descartáveis reais; runtime sem administração, comprovantes append-only, updates de relatórios por coluna e proteção do baseline; sem mudar grants da fonte |
| SSRF/TLS | `integrations/wazuh.py`, `test_integrations.py`, `test_wazuh_tls.py` | HTTPS/IP revisado, SNI/Host, CA/hostname, sem proxy ambiental/redirect; destinos proibidos e TLS loopback testados, sem consulta a SIEM real |
| YAML/Sigma | `integrations/yaml_import.py`, `sigma_analysis.py`, `sigma_readiness.py`, `sigma_mapping.py` e testes correspondentes | SafeLoader, orçamento de bytes/eventos/profundidade/expansão, aliases/âncoras recusados; Atomic só metadados; backend/conversão continuam bloqueados |
| Evidência e histórico | `domain/validation.py`, `test_domain.py`, migrations/transações e `test_scheduled_report_storage.py` | Identidade/tempo/regra completos; alerta alheio não detecta; execução ausente não detecta; hash canônico e finais imutáveis; hash não é assinatura |
| Segredos/runtime | `init_env.py`, `check_staged.py --all`, `check_release.py`, Dockerfile/Compose | Configuração privada validada, usuário10001/read-only/tmpfs/cap_drop/no-new-privileges, sem socket Docker; scanner de padrões do índice não é atestado sobre todo histórico Git ou logs |

## Achados e tratamento

| Severidade / achado | Reprodução | Tratamento / estado |
|---|---|---|
| Média upstream: advisory herdado DiskCache5.6.3 | `make audit`: `PYSEC-2026-2447`, aliases em `dependency-advisories.json` | GitHub Advisory informa severity=medium (unsafe pickle deserialization). Finding mantido visível; caminho limitado do parser/análise/readiness não importa DiskCache. Teste em processo novo recusa import/cache/conexão/escrita. Nenhuma supressão ou alteração de versão. Habilitar validators/plugins/cache exige outra revisão; sem alegação de zero vulnerabilidades |
| Média operacional: visibilidade divergente da política/documentação | `gh repo view Buraddomoon/AEGIS --json visibility` retornou `PUBLIC` | Observação registrada; visibilidade não foi alterada. A política local pede privado. Corrigir alegações factuais nas docs correntes na #74; decisão de visibilidade permanece humana, fora da autorização desta entrega. Nenhum dado privado de runtime é incluído nas provas |
| Baixa documental: aceite desatualizado | `release.md` ainda exclui PDF e rotação já demonstrados; README/aceite tratam retomadas concluídas como pendentes | Consolidação documental da #74 deve apontar os checkpoints novos, preservando evidência histórica e limites de autorização |
| Configuração de desenvolvimento divergente | Conexões inicialmente recusaram PostgreSQL/Redis; primeiro wrapper de teste também omitiu auth Redis ao renderizar URL sem usuário | Nenhuma senha/conta foi redefinida. Credenciais dos serviços locais existentes lidas em memória, URL corrigida somente no wrapper privado. Primeira rodada:139passed/24errors; repetição final abaixo |

Nenhuma nova falha de código foi reproduzida nos controles revisados. Isso não
é pentest independente, análise exaustiva ou aprovação para exposição externa.
A divergência de visibilidade permanece explícita, sem declarar cumprida a
política de privacidade do repositório.

## Comandos e resultados reais

- `make audit`: Python1finding distinto explicitamente revisado; npm0vulnerabilidades.
- `.venv/bin/pytest tests/test_security.py tests/test_integrations.py tests/test_domain.py tests/test_migrations.py tests/test_transactions.py tests/test_wazuh_tls.py tests/test_sigma_analysis.py tests/test_sigma_readiness.py tests/test_sigma_mapping.py tests/test_scheduled_report_storage.py tests/test_init_env.py tests/test_release_check.py tests/test_linux_schema_compatibility.py tests/test_recovered_demo_cycle.py -q --tb=short`:
  **181passed**,0skips/0falhas,53,62s;1warning upstream Starlette/httpx.
- `.venv/bin/python scripts/check_staged.py --all`:613arquivos, padrões/paths/whitespace aprovados antes da edição documental.
- `make release-check`:0.2.0,155Markdown/489links/16PNGs, aprovado no índice inicial.

Suítes PG/Redis15 executadas em sequência, com recursos descartáveis próprios.
Os comandos pytest foram lançados por wrapper privado que passa as credenciais
existentes em memória; `.env` deste checkout não foi substituído. Logs e wrapper
ficam em `.local/issue12`, fora do Git. Versões locais conferidas:FastAPI0.156.0,
SQLAlchemy2.1.5, Argon2-cffi25.1.0, pySigma2.0.1, PyYAML6.0.3, httpx0.28.1,
redis8.1.0, psycopg3.3.6 e Pydantic2.14.1, além de DiskCache5.6.3.

Implementado nesta unidade: relatório de revisão e link no modelo de ameaças.
Testado: fixtures/API/PostgreSQL/Redis e TLS loopback. Nenhuma implantação,
ensaio real ou mudança de dependências/controles. Hash/commit, push e checks finais
são registrados na [#72](https://github.com/Buraddomoon/AEGIS/issues/72).
