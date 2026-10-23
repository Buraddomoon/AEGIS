# ADR0011 — Boot recuperado em quarentena

Data: 2026-10-23. Complementa [ADR0010](0010-demo-backup-rehearsal.md).

Verificar linhas e estrutura não demonstra que a API consegue ler o banco
recuperado. Acrescentar um ensaio opt-in que restaura o mesmo backup em clone
descartável e inicia a imagem local da aplicação em **modo recovery**. Não iniciar
worker, scheduler, Redis, runner, Wazuh ou frontend operacional.

O modo é escolhido ao iniciar o processo; não existe endpoint para sair dele.
Montar somente health e uma revisão agregada protegida por segredo efêmero,
independente das sessões restauradas. Não montar rotas normais, login, OpenAPI
ou arquivos estáticos. Recusar também os entrypoints de worker, scheduler e CLI
administrativa antes de abrir conexão. Não invalidar ou reescrever histórico:
sessões, grants, filas e reservas são **dados a reconciliar**, não autorização
para retomada. O relatório nunca declara que a reconciliação foi realizada.

No clone, provisionar um papel novo somente SELECT, sem ownership/membership,
DDL/DML, TEMP ou funções da aplicação/large objects; ativar transações read-only e conferir
privilégios/revisão Alembic antes de declarar readiness. Read-only é defesa
adicional, não substituto dos privilégios, pois SET TRANSACTION pode alterá-lo.
Falhas retornam diagnóstico genérico sem SQL/credenciais/dados pessoais.

O PostgreSQL continua network=none; API compartilha somente esse namespace de
rede, ouvindo loopback interno, sem publicar portas ou montar caminhos do host.
Usar imagem própria local por ID, sem pull, filesystem read-only, usuário sem
privilégio e limites. Configuração Docker vazia/ambiente saneado. Intenções duráveis
e cleanup por nome/ownership para ambos, removendo API antes do banco mesmo após
create ambíguo. Recibo somente após leitura, bloqueios, inventário inalterado e
cleanup. Dump, manifesto e fonte permanecem intocados.

O ensaio valida boot restrito e planejamento de reconciliação, não login normal,
reativação, ciclo completo de execução, cutover, RPO/RTO ou recuperação de efeitos
externos. Imagem/configuração compatíveis são pré-requisitos; não atualizar imagem
em uso nem ligar labs para satisfazê-los. Permanece proibido repetir ensaios reais
Linux/Wazuh sem autorização específica.

Fontes oficiais consultadas:

- [PostgreSQL17: transações](https://www.postgresql.org/docs/17/sql-set-transaction.html).
- [PostgreSQL17: privilégios](https://www.postgresql.org/docs/17/sql-grant.html).
- [Docker: rede de containers](https://docs.docker.com/engine/containers/run/#network-settings).
- [FastAPI: teste do boot/lifespan](https://fastapi.tiangolo.com/advanced/testing-events/).
- [PostgreSQL17: funções de large objects](https://www.postgresql.org/docs/17/lo-funcs.html).
