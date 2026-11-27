# Checkpoint — retenção de histórico #27

Em 27/11/2026, fonte 46a03b1 implementa os artefatos de #114/#115/#116 no perfil
host-only de snapshots completos/cópias próprias cadastradas. Plano sem exclusão,
política explícita com holds/piso30 dias/sete inventários distintos verificados,
arquivo age com todos os membros e restore isolado, apply com hash/prazo/lock/
aprovação operacional/uso único/auditoria. Sem TTL ou DELETE nas tabelas. #114/#115 têm aceite técnico desse perfil;
#116 permanece parcial quanto ao controle de crescimento do banco ativo.

Validação final local:48 testes de retenção,1 roundtrip PostgreSQL real de fixture
reduzida (9 tabelas/10 linhas),235 testes de recuperação e lint completo aprovados.
CI da fonte final [46054659557](https://github.com/Buraddomoon/AEGIS/actions/runs/46054659557)
SUCCESS na tentativa 2:4303 Python/9 skips existentes e186 React/24 arquivos; quatro
partições e React conferidos. Primeira falha de expiração em teste Sigma
preexistente mantida nas provas; apenas o job falho foi repetido, sem alterar
Sigma/filtros/validade/timeout. Não confundir CI com o ensaio nativo local.

Falhas iniciais de configuração PG/Redis registradas, resolvidas somente no
ambiente do processo. Fonte/recibos preservados; recursos nativos próprios e
staging encerrados. Ver [provas e limites](../evidence/history-retention-2026-11-27/README.md)
e [operação](../operations/history-retention.md).

**#27 e #116 abertas para decisão e aceite do objetivo mais amplo:** o perfil remove
apenas cópias em claro cadastradas e mantém todos os arquivos cifrados e dados
do banco ativo. Não declarar que o crescimento das tabelas foi controlado.
Descarte desse histórico depende de política específica e autorização nova;
não introduzir bypass de append-only, TTL genérico ou exclusão no ambiente humano.

Demo anterior e originais Linux/Wazuh preservados; sem implantação/migração,
marcador, replay, operação SIEM, descarte de backups/chaves ou custódia externa.
Autorizações históricas não foram reutilizadas. Nenhum pacote humano desta
retenção foi aprovado. Encerrar a sessão neste escopo após registrar as provas.
