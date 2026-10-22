# Roadmap baseado em critérios verificáveis

## 0.1 — Demo persistente

Fundação, fluxo completo, evidências, interface, relatórios e comparações. Testes locais e de navegador, Compose e documentação. O aceite é desse escopo, não de toda a plataforma futura.

### Extensão entregue — agendamento Demo aprovado

Planos imutáveis, autorização recorrente delimitada, slots transacionais, pausa/revogação, histórico e relatórios no fluxo existente. Apenas Demo, com testes PostgreSQL e navegador real. Política em [scheduling](../operations/scheduling.md).

## 0.2 — Laboratório Linux isolado

Entregue: runner fixo supervisionado, mTLS, diário/fencing, cadastro revisado de laboratório/ativo, preflight, autorização e aprovação segregada. Campanhas Linux na API/worker/UI, dispatch e comprovantes imutáveis no PostgreSQL, métricas por modo e recuperação sem replay. Ensaio integrado especificamente autorizado confirmou uma campanha, efeito benigno e cleanup; sem SIEM, INCONCLUSIVE. Pendente: rotação operacional de PKI/binding, retenção de recibos e expansão de testes apenas após revisão e autorização.

Exige infraestrutura própria e autorização específica antes de executar. Executor fixo por allowlist, identidade de endpoint, atestação de isolamento, limite efetivo de processo, cancelamento, lease/fencing, cleanup idempotente e recuperação de efeitos desconhecidos. Pelo menos uma simulação benigna validada e registrada. Importação Atomic jamais executa comandos automaticamente.

## 0.3 — Wazuh real

Implementados mapping WazuhBinding entre Asset.id e agent.id, política/hash/revisão,
coleta no worker, polling/prazo total, schemas/índices configuráveis, resumo imutável,
UI/relatórios e observador passivo. Em2026-10-22, o ensaio próprio autorizado
confirmou Wazuh 4.14.9, tmpfs/logRO/agentActive, regra 100200 no engine, FilebeatTLS,
ACLs, um evento/evidência original, DETECTED com synthetic=false e cleanup físico.
[Artefatos e limites](../evidence/wazuh-2026-10-22/README.md).

Laboratório revogado, contas desativadas, containers/redes encerrados e volumes
preservados. Autorização consumida; não repetir para capturas. Pendente: outras
versões/schemas, Windows, archives, regras operacionais além do marcador, rotação
de PKI e retenção/restore do laboratório. O teste valida somente seu pipeline,
sem técnica ATT&CK ou eficácia de EDR. Não é maturidade operacional geral do SIEM.

## 0.4 — Engenharia de detecção

Entregue: associação regra/teste como planejamento humano revisado, versões fixadas,
histórico monotônico, revisão necessária após nova versão, snapshot por execução e
comparação de diferenças de regras/vínculos/testes/ambiente. Nenhuma associação
altera veredictos ou implica implantação. [Operação](../operations/rule-test-reviews.md).

Pendente: análise semântica, backend/pipeline Sigma oficialmente compatíveis,
implantação validada de regras, análise de cobertura entre ambientes distintos e
atualização transacional do ATT&CK com depreciações preservadas.

## 0.5 — Automação e operação

Extensão do agendamento aprovado para Lab Mode, após isolamento efetivo; relatórios comparativos automáticos e PDF; retenção/arquivo, backup/restore verificado, isolamento por workspace e gestão de usuários mais completa.

Futuro: Caldera, outros SIEM/EDR, Windows em VM própria, CI/CD e assistência por IA sem controle autônomo sobre evidências/detecção/alterações críticas. Núcleo independente de IA comercial.
