# Atomic Red Team

Fontes: [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team), [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam). A estrutura YAML traz `attack_technique`, `atomic_tests`, GUID, plataformas, inputs, dependências e executor/cleanup.

`AtomicMetadataProvider` importa somente metadados, com YAML seguro e limites. Retorna plataforma, GUID, dependências, presença de cleanup e necessidade de elevação. Todo item importado permanece `approved=false` e `executable=false`; o comando não é retornado como capacidade de execução. Inputs/dependências são dados não confiáveis, nunca instruções executadas pelo sistema.

Nenhum Atomic oficial foi instalado ou executado. A allowlist Demo é própria e não finge ser um subconjunto seguro de todos os Atomics. O YAML oficial T1059.004 inclui exemplos com rede/download de shell; importar esse documento não implica autorização para executá-lo.

Para evolução: fixar commit, GUID e hashes dos arquivos; revisar execução, dependências, cleanup e efeitos; substituir inputs livres por configuração delimitada; mapear teste revisado a executor fixo; exigir VM/lab isolado próprio e aprovação separada. Proibir mecanismos de evasão, persistência maliciosa, coleta de credenciais e exfiltração. Windows exige VM Windows; container Linux não representa endpoint Windows.

## Catálogo persistente — #75,17/11/2026

A migration explícita `c8e4a6d21f90` acrescenta três tabelas ao schema b7
(36tabelas incluindo Alembic). Não migra Demo/Labs no startup. Documentos são
identificados por commit/técnica e SHA256 dos bytes UTF-8; repetir os mesmos
bytes é idempotente, bytes distintos sob o mesmo commit/técnica são recusados.
Versões, entradas e revisões têm proteção contra UPDATE/DELETE, inclusive owner.
Os grants preservam o suporte à recuperação histórica b7 sem tabelas Atomic.

A projeção retém GUID, técnica, plataformas, descrições, tipos dos inputs,
presença de defaults/pré-requisitos/setup/cleanup e elevação declarada. Não
retém command, cleanup_command, prereq_command, get_prereq_command ou valores
default. Descrições continuam dados não confiáveis; não renderizar como HTML,
Markdown executável ou instruções. Ausência de cleanup não demonstra segurança.

A importação é offline: commit e hash são declarações do operador; a aplicação
não busca nem autentica os bytes no upstream. O caminho oficial é derivado da
técnica. Hash não é assinatura. A fixture oficial fixada/licenciada em
[fixtures/atomic](../../fixtures/atomic/README.md) é usada só pelo parser/testes.
`test_definitions` e a allowlist continuam independentes do catálogo importado.
