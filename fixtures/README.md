# Proveniência dos fixtures

- `attack/enterprise.json`: derivado do bundle oficial MITRE ATT&CK Enterprise 20.0, sem técnicas inventadas; licença, URL e SHA-256 de origem preservados.
- `wazuh-alert.json`: fixture de contrato **escrita manualmente**, com identificadores fictícios e formato semelhante ao Indexer. Não foi coletada de um ambiente real e não constitui evidência operacional. O adapter real usa `synthetic=false` ao normalizar esse schema nos testes unitários; o fixture é fornecido por MockTransport, não integrado ao dashboard nem a uma execução real.

Os testes Demo em execução utilizam `synthetic=true` de ponta a ponta. Não há dados empresariais ou credenciais nestes fixtures.
