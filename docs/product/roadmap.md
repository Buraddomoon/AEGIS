# Roadmap baseado em critérios verificáveis

## 0.1 — Demo persistente

Fundação, fluxo completo, evidências, interface, relatórios e comparações. Testes locais e de navegador, Compose e documentação. O aceite é desse escopo, não de toda a plataforma futura.

## 0.2 — Laboratório Linux isolado

Exige infraestrutura própria e autorização específica antes de executar. Executor fixo por allowlist, identidade de endpoint, atestação de isolamento, limite efetivo de processo, cancelamento, lease/fencing, cleanup idempotente e recuperação de efeitos desconhecidos. Pelo menos uma simulação benigna validada e registrada. Importação Atomic jamais executa comandos automaticamente.

## 0.3 — Wazuh real

Mapeamento Asset.external_id, instrumentação de marcadores, janela de ingestão com polling e prazo total, schemas configuráveis, TLS/credenciais de leitura e prova de um ciclo num laboratório autorizado. Evidência original preservada; nenhuma classificação DETECTED sem alerta correlacionado.

## 0.4 — Engenharia de detecção

Associação regra/teste, análise semântica, backend/pipeline Sigma oficialmente compatíveis, revisão de regra, histórico de cobertura por ambiente, atualização transacional de catálogo ATT&CK com depreciações preservadas.

## 0.5 — Automação e operação

Scheduler de campanhas sob aprovação com validade/limites, deduplicação e concorrência; relatórios comparativos automáticos e PDF; retenção/arquivo, backup/restore verificado, isolamento por workspace e gestão de usuários mais completa.

Futuro: Caldera, outros SIEM/EDR, Windows em VM própria, CI/CD e assistência por IA sem controle autônomo sobre evidências/detecção/alterações críticas. Núcleo independente de IA comercial.
