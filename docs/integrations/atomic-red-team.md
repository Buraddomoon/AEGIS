# Atomic Red Team

Fontes: [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team), [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam). A estrutura YAML traz `attack_technique`, `atomic_tests`, GUID, plataformas, inputs, dependências e executor/cleanup.

`AtomicMetadataProvider` importa somente metadados, com YAML seguro e limites. Retorna plataforma, GUID, dependências, presença de cleanup e necessidade de elevação. Todo item importado permanece `approved=false` e `executable=false`; o comando não é retornado como capacidade de execução. Inputs/dependências são dados não confiáveis, nunca instruções executadas pelo sistema.

Nenhum Atomic oficial foi instalado ou executado. A allowlist Demo é própria e não finge ser um subconjunto seguro de todos os Atomics. O YAML oficial T1059.004 inclui exemplos com rede/download de shell; importar esse documento não implica autorização para executá-lo.

Para evolução: fixar commit, GUID e hashes dos arquivos; revisar execução, dependências, cleanup e efeitos; substituir inputs livres por configuração delimitada; mapear teste revisado a executor fixo; exigir VM/lab isolado próprio e aprovação separada. Proibir mecanismos de evasão, persistência maliciosa, coleta de credenciais e exfiltração. Windows exige VM Windows; container Linux não representa endpoint Windows.
