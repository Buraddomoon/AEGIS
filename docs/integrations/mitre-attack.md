# MITRE ATT&CK

Fonte oficial: [attack-stix-data](https://github.com/mitre-attack/attack-stix-data), Enterprise STIX 2.1. Snapshot distribuído: Enterprise 20.0, 706 attack-patterns ativos após excluir revoked/deprecated. Os dados não foram gerados por IA. Licença original em `fixtures/attack/LICENSE.txt`; URL de origem e SHA-256 do bundle em `enterprise.json`.

O cache mantém IDs, nomes, descrições originais, táticas, plataformas, relações de subtécnica, referência oficial, STIX ID e versão do dataset. O seed inicial importa os dados para tabelas; frontend consulta a API e distingue catálogo de avaliações concluídas.

`python scripts/update_attack.py --version N.N` baixa somente uma versão numerada do repositório oficial e regenera o cache; não aceita URL arbitrária e não roda no startup. Revise diff e licença antes de publicar. **O seed é idempotente e não sobrescreve técnicas existentes.** Atualização de catálogo de um banco populado exige migração de dados revisada; esse fluxo completo de substituição/depreciação ainda não está automatizado.

Mapeamentos Demo: shell Unix → T1059.004; PowerShell → T1059.001; enumeração de processos → T1057. O comportamento é representado sinteticamente, não uma avaliação real. Criação de marcador genérico permanece sem ATT&CK; não é usada para inflar cobertura.
