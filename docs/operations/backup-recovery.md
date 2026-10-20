# Backup e recuperação

PostgreSQL é fonte de verdade; Redis não contém resultados ou jobs. Efetuar backup do volume via pg_dump usando conta administrativa de implantação, guardar de forma privada e testar restauração num projeto/banco separado. Não versionar dumps ou `.env`.

Exemplo local, com aplicação disponível:

```bash
mkdir -p .local/backups
docker compose exec -T db pg_dump -U aegis -d aegis -Fc > .local/backups/aegis.dump
```

Para um backup consistente do estado operacional, pausar novas solicitações, aguardar conclusão de jobs e parar API/worker durante o procedimento. Preservar configuração de ambiente separadamente, com acesso restrito. `make down` mantém volume; não usar down -v como rotina.

Restauração deve ser feita primeiro em banco vazio separado com pg_restore, aplicar somente migrações necessárias e verificar contagens, hashes de evidências, restrições e um ciclo Demo antes de trocar o destino. Não restaurar jobs ativos diretamente para execução: revisar reservas e estados abandonados; nunca repetir efeitos externos desconhecidos.

O teste automatizado E2E comprova reconstrução desde schema vazio. O backup de dump/restore do ambiente final deve ser verificado no processo operacional; não há garantia de recuperação, RPO ou RTO estabelecida nesta versão.
