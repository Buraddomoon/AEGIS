# Implantação local e preparação operacional

`make up` gera `.env` se ausente e executa Compose com build, migração, seed e configuração do papel runtime. `make bootstrap` solicita uma conta administrativa local. Porta pública padrão apenas `127.0.0.1:18780`; PostgreSQL/Redis ficam na rede backend interna. API usa rede ingress para publicação. Override de desenvolvimento adiciona portas loopback de banco/Redis e uma rede de desenvolvimento; ele não deve ser utilizado numa implantação externa.

Runtime é usuário UID 10001, filesystem read-only, /tmp temporário, cap_drop ALL e no-new-privileges. Não há montagem do socket Docker nem volumes do host na aplicação. Banco tem volume próprio. API/worker recebem credencial SQL runtime, distinta da credencial de migração; tabela de auditoria/evidências/versões tem privilégios append-only.

`PUBLIC_ORIGIN` deve corresponder à origem exata do browser. Para HTTPS: configurar proxy/TLS fora do escopo da instalação local, `SECURE_COOKIES=true`, origem HTTPS e rede/headers de proxy revisados. Não habilitar confiança genérica em X-Forwarded-*; o comando padrão usa no-proxy-headers. CORS está fechado por padrão.

Health: `/api/v1/health/live` informa processo; `/health/ready` verifica PostgreSQL/Redis. Estado de worker usa heartbeat Redis; jobs permanecem no PostgreSQL. `docker compose logs --tail=100 api worker` traz IDs de requests e erros locais, sem bodies/tokens. Observar disco, estado CLEANUP_FAILED e reservas pendentes.

Locks Python possuem hashes; imagem frontend usa npm ci. Tags de imagens recebem patches da linha 17/8/3.13/24 no build; registrar digests no processo de release antes de uso além do Demo. Não existem benchmarks ou garantia de alta disponibilidade. Não habilitamos infraestrutura paga, Wazuh completo ou publicação pública.

Linux opt-in: seguir [escopo e instalação](../../labs/linux/README.md), usando o overlay separado com API 18785 e banco próprio. Apenas API/worker desse projeto recebem configuração/certificado cliente, sem chaves de CA. Wazuh é explicitamente vazio no overlay de ensaio. make up padrão não inicia runner nem monta chaves Linux. Não confundir autorização de ensaio anterior com autorização permanente.


Backup e ensaio de recuperação: [procedimento operacional](backup-recovery.md).
A ferramenta host-only precisa do acesso administrativo loopback de desenvolvimento;
ela nunca é exposta à API e não publica portas no clone. Não usar um dump para
iniciar workers sem revisar jobs/agendamentos e efeitos externos do snapshot.
`make recovery-app-build` e `make verify-recovered-app BACKUP_ID=...` ensaiam
apenas API em quarentena numa imagem separada, sem reiniciar o Demo em uso.
Modo recovery mantém503 nas operações normais e não libera jobs/sessões do dump.
`make reconcile-demo-backup BACKUP_ID=...` aplica um plano fixo só num clone novo,
invalida acessos/autorizações restaurados e verifica novamente a API em recovery.
Não faz deploy, reativação de conta/lab ou retomada de worker no banco em uso.
`make verify-recovered-cycle BACKUP_ID=...` verifica o ciclo seguinte com conta,
lab e aprovação novos e API/worker/Redis somente no clone offline. Não publica
portas, muda o Demo ativo ou autoriza operações reais Linux/Wazuh.
