# Revisão da quarentena de recuperação — 2026-10-23

Escopo: ADR0011, seleção de rotas no boot, entrypoints, ACL/readiness, clone
offline, probes e cleanup; ferramenta host-only sem endpoint de restauração.

Modo recovery não monta API normal, autenticação, OpenAPI ou frontend. Token
efêmero independente é exigido para readiness/review; sessões restauradas não
autorizam nada. Worker/scheduler/CLI/migrations recusam antes de conexão/thread.
API não recebe Redis, configuração de runner ou credenciais SIEM.

Banco restaurado é comparado antes e depois da leitura. Role novo sem poderes
administrativos/membership/ownership, SELECT e transações read-only com timeout;
guard verifica grants de tabela/coluna, DB/schema e funções. Default read-only
sozinho não é barreira: probes fazem READ WRITE e exigem erro42501.
Autenticação TCP trust do initdb é substituída antes do boot por SCRAM somente
para role/banco/IP específicos e reject restante; socket administrativo não é
compartilhado com a API. Nenhum grant/revoke toca o banco ativo.

Revisão especializada independente, somente inspeção, encontrou e confirmou
correções de dois pontos:

- EXECUTE de funções large objects em pg_catalog permite escrita fora do
  inventário de tabelas. Clone revoga toda a família lo_/loread/lowrite; guard
  detecta grant residual; teste real de lo_create e grant drift, além da probe.
- Cleanup da API falhando deixava o finally externo remover o DB. Estado de
  tentativa/confirmação agora retém DB com retained_api_cleanup_unconfirmed,
  sem sucesso; regressão cobre isso. Recuperação manual deve tratar API primeiro.

Criar API usa imagem local por ID e namespace do DB network=none, sem publish,
bindmount, volumes, socket Docker ou privilégios; usuário10001, read-only,
cap-dropALL, CPU/memória/PIDs/tmpfs limitados. Dockerconfig vazio/env saneado,
segredos em env temporário0600 durante create, não argv/intent/recibo. Intenções
duráveis/cleanup por nome exato e ownership também após resposta ambígua.

SIGKILL/falha de daemon ainda pode deixar clones. observed_absent é observação,
não garantia sobre operação pendente no daemon. Não automatizar prune ou
remover recursos de outros projetos. Docker host/operador/imagens e dump precisam
ser confiáveis; hash não é assinatura, arquivos privados não são criptografia.
O administrador Docker pode inspecionar env enquanto clone existe.

Testes usam banco/papel PostgreSQL aleatórios próprios e cleanup específico;
nunca revogam PUBLIC na fonte. Probes internas recusam modo/URL/token fora do
escopo fixo antes de conectar. [Recibo de ensaio real](../evidence/recovery-2026-10-23/README.md)
registra4 negações SQL,9 rotas e5 entrypoints, inventário igual e clones removidos.
Consultar [PROGRESS](../PROGRESS.md) para suíte/CI final, sem confundir mocks de
falhas com execução Docker real.

Sem reativação/cutover, RPO/RTO, recuperação de efeitos externos ou nova
autorização real Linux/Wazuh. Armazenamento criptografado externo, guarda de
imagens/configuração e reconciliação explícita antes de worker continuam pendentes.
Nenhuma dependência foi adicionada. Advisory transitivo DiskCache revisado
permanece visível; não declarar ausência geral de vulnerabilidades Python.
