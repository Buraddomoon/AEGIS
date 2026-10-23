# Revisão da reconciliação offline Demo — 2026-10-23

Escopo: SQL fixo, ferramenta host-only, proteção histórica e review vinculada
ao boot. Nenhuma mutação de recuperação exposta pela API; nenhum destino, SQL
ou nome de container fornecido pelo usuário. Clone criado pelo próprio ensaio,
ownership/rede/mounts/portas conferidos antes de cada envio por stdin.

Fonte, dump e manifesto não são alterados. Plano SHA256 de dados/estrutura,
schema exato e PG17; locks de todas as tabelas em ordem fixa/NOWAIT, revalidação
sob lock e transação única. Ambiguidades reais impedem qualquer alteração.
Cancelamento limitado a dados comprovadamente sintéticos, sem replay de dispatch
ou classificação defensiva inventada. Sessões e permissões restauradas deixam
de valer; aprovações/scopes/evidências históricos permanecem preservados.

Revisão especializada somente leitura identificou pontos corrigidos:

- Auditoria histórica não comprova reconciliação atual. Boot agora recebe
  ID/hash esperados; review exige um único registro exato e fences atuais.
- Filhos precisam de transições válidas e steps próprios; agora seguem a mesma
  máquina de estados, com regressões em cada estado pendente de pai e filho.
- ended_at existente é fato de execução: COALESCE preserva o timestamp, sem
  substituir pela hora da recuperação. Nenhum cleanup externo é alegado.
- Conjunto de tabelas deve coincidir com o modelo revisado; tabela extra é
  recusada antes de aplicar. Estrutura também participa do hash contra drift.
- Review deve verificar filhos pendentes, além dos pais. Um filho reaberto faz
  falhar a verificação mesmo se o pai continuar terminal.

Regressões reais PostgreSQL verificam idempotência, drift, NOWAIT/concorrência,
rollback por falha final de auditoria, trigger que altera senha ou reativa conta,
integridade do histórico, terminalidade e recusa de dados reais/dispatchs/reservas
ambíguas. A fixture usa DB/role aleatórios próprios; substitui somente os literais
fixos do destino pelo teste. Guard original rejeita esse DB; ensaio Docker real
verifica o destino de implantação. Revisor não executou testes ou containers.

Provisão SELECT/SCRAM e bloqueios dos entrypoints continuam independentes do
registro de reconciliação. Nenhum sucesso antes de preservação, boot/probes e
cleanup API→DB; cleanup incerto retém DB. O recibo privado de aplicação não
substitui a verificação final. [Evidência](../evidence/reconciliation-2026-10-23/README.md).

Limites: operador Docker/imagens/dump confiáveis; hashes não são assinatura;
arquivos privados não são criptografia. SIGKILL/daemon indisponível pode exigir
revisão manual de intents/clones. Sem roles/ACLs originais, Redis, PKI ou journals
externos recuperados, sem retomada normal/cutover/RPO/RTO garantido. Autorização
Linux/Wazuh continua consumida. Nenhuma dependência adicionada; advisory
transitivo DiskCache previamente revisado continua visível.
