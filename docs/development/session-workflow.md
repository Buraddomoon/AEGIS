# Trabalhar no ÆGIS em uma sessão nova

O [índice no GitHub](https://github.com/Buraddomoon/AEGIS/issues/1) organiza as
entregas e subissues. A conversa antiga não é requisito para desenvolver.

## Prompt para iniciar

```text
No repositório Buraddomoon/AEGIS, trabalhe somente na issue #NUMERO e nas
subissues dela. Leia AGENTS.md e docs/development/session-workflow.md.
Confira dependências, estado dos arquivos e critérios de aceite da issue.
Implemente e valide somente esse escopo. Se faltar ambiente ou autorização,
registre o bloqueio concreto. Ao concluir, informe testes/commits e pare.
```

Use o número de uma subissue para uma sessão ainda menor. O índice agrupa o
produto inteiro; não deve ser solicitado como uma sessão de implementação.

## Contexto mínimo e leitura por assunto

1. `git status --short --branch` e a issue escolhida, seu pai e bloqueadores.
2. `AGENTS.md` e este guia. Os arquivos técnicos de entrada estão na issue.
3. Abra só os ADRs/runbooks pertinentes. Para detalhe antigo, busque o assunto em
   [histórico técnico](agent-history-2026-11-10.md) ou [PROGRESS](../PROGRESS.md),
   sem ler os arquivos inteiros por padrão.
4. Confira o comportamento real: issue, roadmap e documentação são inventário,
   não substituem código/testes/artefatos atuais.

Cada pai é uma capacidade percebida pelo usuário. Cada filho é uma unidade
técnica com objetivo, contexto, escopo, dependências, aceite e testes. Relações
pai/filho e dependências de entregas usam recursos nativos do GitHub. Comentários
registram provas, bloqueios e handoff curto. Não duplicar status no Obsidian.

O modelo de corpo/nomenclatura foi consultado em memory-os/00 - padrões/
Padrao-Issue.md. Particularidades AEGIS prevalecem: privado, somente main,
Conventional Commits frequentes e push direto, sem branch/PR/fluxo de promoção.
Tipos nativos não estão disponíveis neste repositório pessoal; não simular
Feature/Task com labels. As subissues recebem apenas a área técnica do título.

## Planejamento não é uma lista de defeitos do MVP

V0.3 agrupa estabilização/retomada de laboratório; V0.4, engenharia de detecção;
V0.5, operação/administração; V1.0, possibilidades futuras **opcionais**.
São milestones de planejamento, não versões publicadas ou datas prometidas.
O código continua0.2.0. Caldera/Windows/IA/SSO/distribuição/outros SIEMs não são
exigências novas para considerar o Demo demonstrável. Seguir P0→P1→P2 e os
bloqueadores da entrega escolhida; não puxar a próxima feature automaticamente.

## Estado de partida em10/11/2026

- Base remota a644838: documentação da transição Linux;44a494f encerrou
  relatórios automáticos. Fonte executável implantada dessa feature:0609ad2.
- Demo em localhost18780: autenticação/RBAC, campanhas/worker, catálogo ATT&CK,
  regras/vínculos/análise Sigma, coverage/comparação, agendamento, PDF e snapshots
  automáticos já entregues. Não reimplementar essas capacidades por falta do chat.
- Imagem Demo b8abe5e... e schema b7 conferidos;23runs antigas preservadas, sem
  reset de conta.3060Python/2skips por grupos complementares local/GitHub,88React
  e E2E5runs/20Demo/2snapshots/4PDFs. A CI integral42671146994 falhou por erro
  interno; esse resultado não é apresentado como workflow verde.
- Já houve Linux integrado21/10 e Wazuh22/10 reais, encerrados. Falta retomada sob
  PKI/rede renovadas, identidade nativa e ativação/binding. Autorizações antigas
  consumidas; novo ensaio exige pacote específico e aprovação humana.

## Alterações locais pausadas — não misturar com outra entrega

Na mesma máquina existem cinco arquivos de preparação parcial de rede, fora do
Git remoto em10/11. A primeira entrega do índice é responsável por revisá-los:

```text
scripts/init_linux_lab.py                         modificado
scripts/runner_pki.py                             modificado
tests/test_runner_pki_tls.py                      modificado
apps/api/aegis/lab_runner/network_profile.py       não rastreado
tests/test_linux_network_transition.py            não rastreado
```

Esses arquivos tiveram66testes locais aprovados, apenas PKI/generation/TLS e
transição. Isso não valida a troca completa: Compose/receitas/probe ainda usam
a faixa antiga. Não houve commit de implementação, build/start de Lab, candidato
real, marcador ou mudança na rede qasrc. Há patch textual/hash em comentário da
subissue de PKI para recuperar em clone novo, se necessário. Confira divergências
antes de aplicar; nunca sobrepor trabalho local. Uma sessão de outra issue deixa
esses arquivos intactos e não os inclui no seu commit.

Retomada menor: [subissue42 de PKI offline](https://github.com/Buraddomoon/AEGIS/issues/42).
O [conflito das duas redes Wazuh](https://github.com/Buraddomoon/AEGIS/issues/149)
é uma entrega separada: corrigir a faixa Linux não corrige automaticamente as
faixas172.30.89/90 do Wazuh, também contidas na qasrc. Nenhuma delas foi alterada.

## Concluir uma unidade

Para retomar especificamente a issue4, o
[checkpoint de ativação](activation-checkpoint.md) registra o aceite conjunto das
#48/#49/#50/#51 e o ensaio nativo encerrado em12/11. Essa entrega não autoriza
nova execução nem replay; não iniciar outra feature a partir desse checkpoint.

Antes de commit, revisar somente os arquivos do escopo, testes pertinentes,
staged/segredos e checks do AGENTS. Referenciar a subissue; não fechar pai antes
de todos os filhos e do aceite conjunto. Push em origin/main após cada commit.

No comentário final, registrar resultado, comandos e contagens efetivos, arquivos,
commits/último hash/mensagem, sincronização, limitações e bloqueios. Diferenciar
implementado, testado por fixture, validado em ensaio real e implantado. Sem
aprovação/ambiente, não declarar concluída a parte dependente. Encerrar a sessão
sem iniciar outra entrega.

Entrega #5: [campanha verificada e encerrada](../../labs/linux/CAMPAIGN-VERIFIED-2026-11-12.md).
#52/#53/#54 atendidas; original b7, catálogo versionado inicializado sob aprovação
adicional, uma campanha real43bytes COMPLETED/INCONCLUSIVE/CLEANED. Lab revogado,
contas próprias inativas/zero sessões próprias e recursos encerrados. Histórico,
backup, diário/fences e pacotes consumidos preservados. Não iniciar outro ensaio
ou outra entrega a partir desse checkpoint. Conferir CI final e comentários.
