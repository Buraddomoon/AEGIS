# Sigma / pySigma

Fonte: [pySigma oficial](https://github.com/SigmaHQ/pySigma). AEGIS utiliza SigmaCollection.from_dicts da versão 2.0.1, após SafeLoader, limite de 64 KiB, complexidade limitada e bloqueio de âncoras/aliases. Um documento/regra por importação; UUID obrigatório. Tags `attack.tNNNN(.NNN)` precisam existir no catálogo.

Nova importação do mesmo UUID cria versão imutável; conteúdo idêntico é idempotente. UI apresenta YAML, técnicas, hash e comparação visual entre versão anterior/atual. Não há tradução, execução de consultas ou implantação automática. O snapshot de execução registra versões do inventário para contextualizar comparações; isso não significa que essas regras foram implantadas.

Sintaxe válida não comprova semântica, cobertura ou compatibilidade Wazuh. Conversão futura exige backend/pipeline oficialmente compatíveis e prova num laboratório autorizado. Associação revisada regra/teste é operacional como metadado de planejamento, com versões fixas, retirada e histórico. [Operação e API](../operations/rule-test-reviews.md). Análise semântica, conversão e implantação continuam no roadmap.

Dependência pySigma é LGPL-2.1-only e permanece biblioteca separada, sem código copiado/modificado. Regras importadas mantêm licença de seus autores. DiskCache 5.6.3 é uma dependência transitiva com advisory conhecido sem patch; AEGIS não importa nem usa seu caminho de cache. A auditoria mantém a ocorrência visível e testa essa premissa; habilitar plugins/cache exige nova revisão.
