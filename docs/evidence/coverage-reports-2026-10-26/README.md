# Cobertura por recorte — validação de2026-10-26

API/worker/PostgreSQL/Redis reais, somente dados Demo sintéticos. Nenhuma nova
campanha/execução foi criada no Demo em uso, nem iniciado Linux/Wazuh/consulta SIEM.
[Operação e contratos](../../operations/coverage-reports.md).

`make lint` passou; `make test` final:688Python/53frontend passaram. E2E Firefox
com processos próprios e schema descartável passou:4runs/16testes sintéticos,
12capturas reais, zero erros JavaScript e viewport390px sem overflow. Validou
exportação JSON de recorte/comparação, membros/evidências/denominadores,
legado desconhecido e período vazio; relatório individual/histórico preservados.
Capturas em docs/images são do E2E, sem mocks ou credenciais humanas.

Revisão especializada somente leitura encontrou bordas de filhos/resultados/
manifesto incompletos e cache após erro. Correções/regressões confirmadas;
[revisão e limites](../../security/review-coverage-reports-2026-10-26.md).
Rodadas anteriores com erro não foram anunciadas como sucesso: duas invariâncias
precisavam excluir o novo snapshot_at volátil; depois houve uma disputa NOWAIT
compatível com manutenção das tabelas de teste. Autovacuum só das tabelas dos
schemas/bancos descartáveis é desabilitado antes do seed. Locks/controles de
produção e testes com escritores concorrentes explícitos permanecem.
E2E também corrigiu esperas pelas opções e texto de não equivalência atualizado.

## Demo local e preservação

Preflight:21runs, zero pendências/reservas/agendamentos retomáveis, administrador
humano ativo. Backup20261026T153138Z-da45ceb4b6d748e0b66a5c0a0d8514a1,
SHA256ef90b2805c3e5bc6dae0a531d014c0f33d216bfac78ae2cdbca8843f33f84ab7,
restaurado/verificado:32tabelas/3.160linhas, clone offline removido,6,792s medidos;
não é promessa de RTO. Imagem anterior a160bed6... preservada em
`aegis-coverage-previous:demo-20261026`. Dumps/manifestos/backups anteriores intactos.

Somente API/worker próprios recriados; db/redis e schema a0d9c7e21b45 preservados.
Imagem Demo/recovery nova:
`sha256:ef97abfdf122df5bd513f7a6e2a44c7ec84a3b89757e1698d04da0f0f8871a02`.
Health ready database/redis=true. Conta temporária viewer confirmou exports reais
com papel SQL runtime e403 na auditoria administrativa; logout/desativação e
zero sessão temporária conferidos. Registro completo do admin humano (incluindo
hash de senha) idêntico antes/depois; nenhuma credencial humana foi usada ou
reescrita no ensaio.30tabelas históricas conferidas contra o manifesto, exceto
mudanças esperadas em users/audit_events, e21runs mantidas. Hashes dos relatórios
foram recalculados sobre os bytes JSON normalizados entregues, sem persistir ou
publicar payloads potencialmente sensíveis.

Resumo curado do recibo privado, sem segredos ou conteúdo de eventos:

```json
{
  "format": "aegis-scoped-analytics-deployment/1",
  "scope": "local Demo only",
  "backup_id": "20261026T153138Z-da45ceb4b6d748e0b66a5c0a0d8514a1",
  "new_campaign_or_execution": false,
  "external_lab_or_siem_accessed": false,
  "all_runs": 21,
  "legacy_runs": 20,
  "current_runs": 1,
  "valid_tests": 63,
  "outcomes": {
    "DETECTED": 21,
    "OBSERVED_NOT_ALERTED": 21,
    "INCONCLUSIVE": 21,
    "NO_TELEMETRY": 21
  },
  "detected_percentage": 33.3,
  "coverage_report_sha256": "c6fa1e01ae24b44bf25f897a57b5c6590aee565cc2242222c3f81fbd31137ac0",
  "comparison_report_sha256": "fb88d798295cae6983d6c851a0c3207544e2112d31e32e4ef9789ed0980d7504",
  "legacy_comparison_comparable": false,
  "legacy_delta": null,
  "stale_scope_export_refused": true,
  "runtime_viewer_exports_verified": true,
  "admin_audit_route_denied_to_viewer": true,
  "status": "passed",
  "historical_tables_unchanged": 30,
  "human_admin_record_unchanged": true,
  "temporary_viewer_disabled": true,
  "temporary_sessions_remaining": 0,
  "migration": [
    "a0d9c7e21b45"
  ],
  "new_migration_or_schema_change": false
}
```

Hash não é assinatura nem valida proteção empresarial. O ensaio não cobre escala
acima do limite5000runs, PDF, relatórios agendados, multi-workspace, recuperação
completa entre hosts ou configuração de armazenamento externo. Resultado final
da CI e continuidade constam no [PROGRESS](../../PROGRESS.md).
