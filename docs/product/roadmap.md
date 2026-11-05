# Roadmap baseado em critérios verificáveis

Código atual0.2.0. Os números abaixo organizam marcos funcionais; não são tags ou
GitHub Releases publicadas. Ver [aceite por escopo](acceptance-criteria.md).

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

Entregue também: análise estática parcial por versão/hash, cinco checks locais
sobre o parser/modelo pySigma, fatos declarados e contexto histórico na UI.
Não comprova correção semântica completa ou eficácia.

Entregue também: preparação offline por versão/perfil/hash, campos candidatos do
schema de marcador e diagnóstico de requisitos de backends revisados. Compatibilidade
bloqueada por pySigma<2 nos backends versus core2.0.1. Perfil não é pipeline executável.

Entregue também: atualização transacional ATT&CK por candidato oficial fixado,
plano/hash/revisão, releases imutáveis, estados de retirada/ausência, contexto por
escopo e cobertura atual separada do histórico. Publicação do bundle20.0 completo
validada em schema descartável e no Demo local, sem nova simulação Linux/Wazuh.
[Operação](../integrations/mitre-attack.md).

Pendente: semântica completa e correspondência à telemetria, backend/pipeline Sigma oficialmente compatíveis,
implantação validada de regras e análise de cobertura entre ambientes distintos.
ATT&CK: experiência administrativa de revisão web, outras matrizes e evolução
para versões futuras após pesquisa/revisão. A fonte20.0 não virou uma versão nova
para demonstrar o fluxo.

## 0.5 — Automação e operação

Entregue: recortes de cobertura por modo/período/release/legado, relatórios
agregados e comparativos PDF/HTML/JSON, hashes/membros/denominadores explícitos e
snapshot coerente. Comparação exige manifesto e resultados completos/contexto
conhecido. Interface recusa ações sobre cache após erro de atualização.
[Operação](../operations/coverage-reports.md).

PDF de execução, cobertura e comparação entregue com testes de parser/API/UI e
E2E Demo, limites e avisos de origem. Estado de implantação/CI no checkpoint.
[Uso e limites](../operations/pdf-reports.md).

Extensão do agendamento aprovado para Lab Mode, após isolamento efetivo; relatórios comparativos automáticos; retenção/arquivo, backup/restore verificado, isolamento por workspace e gestão de usuários mais completa.

Futuro: Caldera, outros SIEM/EDR, Windows em VM própria, CI/CD e assistência por IA sem controle autônomo sobre evidências/detecção/alterações críticas. Núcleo independente de IA comercial.


Marco recuperação Demo: backup/restore e comparação de dados/estrutura em clone
sem rede foram executados; plano de retenção é somente leitura. Seguem pendentes
reativação operacional/roles/secrets, custódia criptografada
externa, política de RPO/RTO e gestão de retenção por ambiente. [Limites](../operations/backup-recovery.md).

Boot da API recuperada em quarentena implementado: SELECT e revisão agregada,
sem login normal/worker/scheduler ou retomada de sessões/autorizações. Não
substitui um novo ciclo Demo após recuperação. Reconciliação offline implementada
somente no clone descartável: sessões/contas/autorizações invalidadas, pendências
sintéticas encerradas, histórico preservado e recibo vinculado à API em recovery.
Ensaio de ciclo Demo novo com identidades/aprovação novas implementado em destino
descartável, incluindo worker, evidências e relatórios. Recuperação entre hosts,
custódia independente e cutover operacional continuam pendentes.

Backups cifrados locais entregues: age/X25519 opcional host-only, chave separada,
decriptação autenticada/hash consumido e mesma engine de restore offline. Cópia
real32tabelas/3.169linhas verificada com origem/usuários preservados. Retenção é
inventário/plano, sem exclusão. Chave/cópia no mesmo computador não protegem de
perda do host; destino externo, custódia, configuração/secrets/imagens e RPO/RTO
continuam pendentes. [Operação](../operations/encrypted-backups.md).

Consolidação de entrega concluída: instalação com configuração segura, README
centrado no fluxo, galeria com procedência e revisão offline de fonte em CI leve.
Custódia externa permanece adiada por escolha do usuário; sem novo ensaio real.
Próximo incremento funcional sugerido: reavaliar backend/pipeline Sigma em ambiente
de testes com constraints oficiais compatíveis, mantendo conversão bloqueada até
validar o contrato. Não envolve implantação de regras ou operação Linux/Wazuh.

Incremento de engenharia Sigma: prévia restrita de renomeação com ProcessingPipeline
oficial do core2.0.1, API/UI por versão e antes/depois em memória. Essa etapa
independente não reduz o parser nem instala backends incompatíveis; a consulta
atual confirmou que OpenSearch2.0.3/Elasticsearch2.1.1 ainda exigem core<2. Conversão
real de consultas, mapping físico do índice e implantação permanecem pendentes.

Preparação da rotação do runner entregue: inventário público e candidato separado,
duas CAs/quatro pares novos, mesmos IDs e verificação offline de cadeia/pares/
validade, com hashes revisados. Echo TLS em loopback valida confiança nova/recusa
antiga; não inicia runner. Ativação coordenada, binding/preflight e recuperação
de jobs sob vínculo alterado continuam pendentes. PKI dos serviços Wazuh não é
abrangida. [Procedimento e limites](../operations/runner-pki.md).

Revisão persistida do vínculo entregue na API/UI administrativa: pendências de
pais/filhos, validação de cleanup/spec/geração/identidades e bloqueio acima do
limite de histórico. Registro Linux e bind/unbind Wazuh impõem o predicado sob
lock; novas solicitações Linux participam do lock de revogação/revisão. Plano de
troca coordenada documentado; ativação/preflight e recuperação sob confiança
alterada continuam pendentes. O diagnóstico original já foi concluído, abaixo.
[Revisão](../operations/linux-binding-review.md) ·
[Plano](../operations/runner-pki-activation.md).

### Estado consolidado da rotação Linux — 2026-11-05

- **Concluído:** plan/recheck de metadados, intents/ownership, drivers de probes,
  transporte limitado e cleanup integrado ao diagnóstico. Em 29/10, o diagnóstico
  autorizado verificou uma prova SQL antes/depois e dois jobs/oito eventos do
  diário original; cinco recursos próprios removidos e volumes preservados.
  [Evidência e limites](../evidence/diagnostic-2026-10-29/README.md).
- **Implementado e testado, sem ensaio nativo:** servidor identity-only, cliente
  fixo, quatro controles TLS, coordenador, evidências e CLIs de execução/revisão/
  cleanup. A imagem foi construída e conferida; isso não comprova mTLS nativo.
  [Procedimento](../../labs/linux/IDENTITY.md).
- **Bloqueado no ambiente atual:** o preflight de 05/11 encontrou a rede Docker
  `qasrc` em `172.30.0.0/16`, sobreposta ao subnet fixo `172.30.88.0/29`. O usuário
  determinou preservá-la e concluir somente as correções. Nenhum novo ensaio,
  alteração dessa rede ou mudança de subnet está autorizado nesta rodada.
- **Ainda não entregue:** ativação coordenada da PKI, atualização do binding e
  preflight sob a nova confiança, com imagem de aplicação atual e evidência de
  encerramento. O sucesso histórico do diagnóstico não libera operação normal
  nem autoriza reutilizar os ensaios anteriores.

Windows, novas simulações e ampliação Wazuh continuam nos marcos futuros; não são
pré-requisitos adicionados para concluir as correções atuais. Resultados de CI
e commits desta rodada ficam no [checkpoint](../PROGRESS.md).
