# Registro de laboratórios — #25

Fonte integrada `c419d4b`: #108 registro host-only fechado; #109 migração
explícita `f3b28c5d901a`, ativo de campanha/FK e resolução por lab; #110 seleção
por conexão/ativo, capacidade e histórico. Registro opt-in desligado sem
`LINUX_RUNNER_REGISTRY`; configuração legada preservada. Linux tem um runner/ativo
por registro, sem host/URL/comando livre ou equivalência Windows.

25testes puros, regressão inicial132, ampliada238/1falha e complementar62
aprovados após corrigir a simulação de drift;243casos distintos na coleta final.
172React, lint/build/checks aprovados. Firefox final VERIFIED, dois labs Demo/
duas runs sintéticas, cadastro Linux offline revogado/desconectado, Windows sem
capacidade,1440/390px/zero erros JS; processos/schema próprios encerrados.

[Provas e limitações](../evidence/lab-registry-2026-11-25/README.md),
[operação](../operations/lab-registry.md) e [testes](testing.md).
CI45684589411 falhou em compatibilidade histórica (três falhas/dez erros).
Correção preserva leitura b7 sem exigir a coluna nova e mantém sua validação
quando presente; fixture b7 usa projeção histórica explícita. Regressão local
complementar115/uma falha de preparação corrigida,27 e10 aprovados.
CI corrigida45686709531 SUCCESS, conferida em27/11/2026: quatro partições,
4234Python/9skips previstos,172React/23arquivos e21glob. Aceite offline conjunto
da #25 e das #108/#109/#110 atendido; commits executáveis publicados em main.
Demo ativo preservado; sem implantação, migração de originais ou operação
Linux/Wazuh/SIEM. Autorizações históricas não reutilizadas. Provas documentais e comentários nas
issues registram o fechamento e a sincronização. Parar nesta entrega.
