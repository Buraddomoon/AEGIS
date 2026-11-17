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

Entrega #6: [checkpoint PKI Wazuh](wazuh-pki-checkpoint.md). #55/#56 e dependência
#149 entregues; [ensaio real #57 verificado e encerrado](../evidence/wazuh-tls-2026-11-12/VERIFIED.md)
após autorização específica e reconciliação sem replay. Laboratório parado,
volumes/configuração antiga preservados; ambas as autorizações consumidas.
Sem novo marcador ou operação normal. Conferir CI final e comentários das issues;
não iniciar outra entrega.

Entrega #7: [checkpoint da revisão integrada](wazuh-cycle-checkpoint.md),
#58/#59/#60 concluídas em16/11. Campanha única atual COMPLETED/DETECTED/CLEANED,
43bytes/regra100200/zero técnicas ATT&CK; UI/JSON/HTML/PDF da mesma run verificados.
Lab revogado, contas próprias inativas e recursos encerrados. Pacotes/autorizações
consumidos; não repetir efeito ou inferir operação contínua.

Entrega #10: [checkpoint da validação integral](ci-validation-checkpoint.md).
#67/#68/#69 concluídas em sequência: diagnóstico do incidente GitHub, CI integral
da fonte fixada com3377Python/9skips e91React, evidências e implantação distintas.
Commits finais somente documentais; Demo anterior preservado. Não iniciar outra
entrega ou laboratório a partir desse checkpoint.

Entrega #11: [checkpoint de recuperação b7](backup-b7-checkpoint.md).
#70/#71 concluídas em sequência: cópia a0 e backup fresco b7 restaurados com
imagens compatíveis; reconciliação real e fixture não vazia de relatórios
validadas separadamente. Demo preservado/ready, clones removidos, sem cutover
ou retomada de campanhas. Conferir CI final nos comentários da #11 e parar.

Entrega #12: [base demonstrável consolidada](release-checkpoint.md).
#72 revisou controles/dependências;#73 demonstrou instalação nova e dois percursos
Demo;#74 consolidou matriz/docs sem reescrever evidência histórica. CI da fonte,
imagem temporária testada e Demo anterior ativo são distintos. Visibilidade
GitHub PUBLIC diverge da política privada; sem alteração de visibilidade nesta
entrega. Ver provas/limites, comentários finais e sincronização. Parar após esse
aceite; próxima issue é escolha explícita do usuário.

Entrega #8: [checkpoint dos perfis Wazuh](wazuh-schema-checkpoint.md).
#61/#62 implementadas e verificadas por contrato local. Após autorização
explícita de retomada, #63 consultou o Indexer real em
17/11, perfil `wazuh-4.14.9/1`, alerta original preservado e archives404; CLEANED.
#61/#62/#63 atendidas, sem nova campanha ou implantação permanente. Conferir
provas/limites/CI no checkpoint; pacotes consumidos. Parar após esse aceite.

Entrega #13: [checkpoint do catálogo Atomic offline](atomic-catalog-checkpoint.md).
#75/#76/#77 concluídas e pendências corrigidas na retomada: CI integral44151198083
SUCCESS na fonte0517d24,3525Python/9skips opcionais,98React e21testes de segurança.
Lint/build/auditorias e Firefox real aprovados; nenhum Atomic executado. Fork local
picomatch revisado/licenciado e inventário Wazuh b7 fixado, sem gates relaxados.
Demo/Labs originais preservados; sem implantação. Provas/falhas históricas no
checkpoint. Parar após esse aceite, sem avançar para outra entrega ou laboratório.

Entrega #14: [checkpoint da execução Atomic](atomic-execution-checkpoint.md).
#78 revisou/fixou um GUID e #79 entregou o adaptador próprio fechado, com CI
integral44168295232 aprovada (3575Python/9skips e98React). #80 retomada: imagens,
PKI e proposta91de0d6f verificadas offline, aguardando autorização específica
da tentativa. Conferir CI da preparação e prazo/estado no checkpoint/issue.
Metadados continuam não executáveis,
Labs originais preservados; não tratar a preparação offline como ensaio nativo.
