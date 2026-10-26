# Prévia de campos Sigma — validação de 2026-10-26

Prévia de rename, nunca consulta, conversão completa ou implantação SIEM. API/UI
sobre RuleVersion real imutável e pipeline oficial core 2.0.1 já instalado. Sem
backend adicional, downgrade de parser, nova migração ou operação Linux/Wazuh.

## Pesquisa de compatibilidade

Reconsulta direta TLS a PyPI e conferência do SHA dos wheels e de METADATA:

| Pacote publicado | Versão | Restrição ao core | Resultado |
|---|---|---|---|
| pySigma | 2.0.1 |—|Mantido no runtime |
| pySigma-backend-opensearch | 2.0.3 |>=1.0,<2|Incompatível, não instalado |
| pySigma-backend-elasticsearch | 2.1.1 |>=1.4,<2|Incompatível, não instalado |

Os hashes conferidos continuam iguais a fixtures/sigma/backend-metadata.json;
o snapshot de 2026-10-22 não foi alterado para fingir compatibilidade atual. Fontes:
[core](https://pypi.org/pypi/pysigma/2.0.1/json),
[OpenSearch](https://pypi.org/pypi/pysigma-backend-opensearch/2.0.3/json),
[Elasticsearch](https://pypi.org/pypi/pysigma-backend-elasticsearch/2.1.1/json).
A prévia é uma etapa independente, possível sem esse backend. O campo
can_convert permanece false, assim como query_generated/siem_queried/
deployment_performed/index_mapping_verified.

## Verificações executadas

| Check | Resultado |
|---|---|
| test_sigma_mapping.py | 35 passed: pipeline oficial real, condições/listas/hashes, input recusado antes do parser/pipeline, drift e processo sem efeitos |
| test_sigma_mapping_api.py | 7 passed: PostgreSQL/API, viewer/anon, rate/Redis, perfil/SHA, histórico/auditoria/cobertura e erro sem echo |
| sigma-mapping.test.tsx | 13 passed: ação real, contexto/contrato/flags, unsupported, erro de refetch e resposta atrasada |
| `make test` final |**786 Python passaram** em 306,72 s; **66 React passaram** em 3,63 s |
| `make lint` | Ruff/format, mypy domínio, TypeScript e Prettier aprovados |
| `make build` | SPA construída, sem aviso chunk>500kB |
| `make audit` | npm: zero; DiskCache/PYSEC-2026-2447 revisado/visível, nenhum finding novo ignorado |
| `pip check` | Sem requisitos quebrados |
| `make e2e` | Firefox real: 4 runs / 16 testes sintéticos, 13 capturas, zero erros JS; UI/worker/SQL sem mocks, dois objetos detection conferidos, relatório antigo idêntico, 390 px sem overflow no modal |
| Docker build e atualização | Nova imagem própria; API/worker somente, sem recriar DB/Redis/migrate |
| `make smoke` na imagem final | Papel SQL runtime, API/worker, prévia positiva/hash/versão imutável, análise/preparação bloqueadas, run manual+agendada, grant/revoke e 8 resultados sintéticos/relatórios |
| Backup pré-deploy | Criado e restaurado em clone sem rede: 32 tabelas / 3.169 linhas, hashes/estrutura iguais e clone removido |

O E2E foi repetido após ajustar o enquadramento da captura e acrescentar a
conferência do modal em 390 px; ambas as rodadas passaram. Não somar suas runs ao
Demo em uso: os schemas E2E são descartáveis. A rodada final gerou 13 capturas Demo;
com a imagem Linux histórica são 14 PNGs. [Galeria](../../images/README.md).

Problemas de fixtures corrigidos: importação já normaliza whitespace da regra,
então a invariância compara o conteúdo salvo; a rota /api/v1 não pode ser
confundida com /versions/v1 no teste de resposta atrasada. Falhas iniciais não
foram contabilizadas como testes aprovados. Aviso Starlette/TestClient/httpx permanece.

CI do commit final executável e revisão de fonte: consultar o
[checkpoint](../../PROGRESS.md). Commits posteriores só registram documentação
ou capturas; não alegar validação de código novo pela CI de um commit anterior.

## Estado local preservado

Site http://localhost:18780 saudável; imagem API/worker:
sha256:ec57c8c9177fa8a4a8a5141bb958ed86e6bcf245f003dcb2f7972ea34a5d0314.
A imagem anterior ef97abf foi mantida nas tags de recuperação e pré-deploy.
Nenhuma senha/configuração humana alterada; administrador continua ativo.

Antes da troca: zero runs pendentes, reservas ou agendamentos retomáveis.
Depois do smoke: 23 runs, incluindo as 21 anteriores e duas novas inteiramente
sintéticas; conta temporária desativada, agendamento revogado e zero pendências/
reservas/planos retomáveis. Schema a0d9c7e21b45, 32 tabelas. Zero schemas de teste
restantes; autovacuum public intacto. Linux/Wazuh continuam com zero containers;
volumes/journals/backups/chaves anteriores preservados.

Backup privado 20261026T204444Z-b85ee5892de445f08a99c18a3e28e5b2,
dump SHA256 2253cab121564ccd2d2e9e36ab0fca44bbd9be0a095a6d00c69e8e9e65ce02f4.
Recibo verified, network=none, application_started=false, 32 tabelas/3.169linhas,
clone_removed=true, 4,752 s; não é RTO. Original permanece privado em claro;
criptografia/custódia seguem o procedimento anterior, sem envio externo.

## Limites reais

Subconjunto plano de strings literais e logsource próprio; não é conversão genérica
Sigma, verificação de mapping/analyzers ou eficácia de uma regra. Não valida regras
Windows/processos ou Wazuh além do marcador. Não transforma/reescreve histórico ou
altera resultados. Backends/core compatíveis, pipeline completo, mapping físico e
validação autorizada da consulta permanecem pendentes. Sem implantação automática.
[Política](../../integrations/sigma.md#prévia-de-transformação-de-campos) ·
[Revisão local](../../security/review-sigma-mapping-2026-10-26.md).
