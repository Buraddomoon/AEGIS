# Revisão de backup e recuperação — 2026-10-22

Escopo: ADR0010, inventário operacional e CLI host-only. Revisão especializada
foi somente leitura, sem executar Docker, payloads ou testes. Os testes e os
ensaios operacionais descritos abaixo foram executados pelo agente principal.

Quatro achados médios corrigidos:

- Criação ambígua: intenção persistida antes do create; finally reconcilia nome
  exato/label inclusive se daemon criou o objeto mas resposta falhou. Não remover
  objeto com ownership divergente. Regressões create-before/create-after.
- Durabilidade: fsync de arquivo mais diretório e pai após criação/publicação.
  Uma escrita parcial não produz recibo de verificação aprovado.
- Estrutura parcial: incluir format_type/typmod/collation de colunas/arrays e
  flags de índices/tabelas; recusar RLS/policies, tipos customizados e procedures
  não cobertos. Teste prova que varchar(80)[]→varchar(90)[] não passa silenciosamente.
- Configuração herdada da CLI Docker: config temporário vazio e ambiente limitado
  a PATH/LANG, daemon Unix fixo. Evita injeção de proxies com credenciais do config
  global. Nenhuma configuração global do usuário foi alterada.

Controles preservados: fonte Demo exata, snapshot read-only compartilhado, arquivos
privados0700/0600/exclusivos, symlinks recusados, hash do dump antes de criar clone,
restore transacional, clone sem rede/portas/mounts/workers, imagem local porID,
sem pull. Falha de comparação/cleanup não grava sucesso. Erros com potencial
conteúdo de linhas ficam privados. Nenhum endpoint ou socket Docker na app.

O inventário não é equivalência SQL genérica: há normalização restrita, testada,
do cast de arrays de literais varchar→text reescrito pelo PostgreSQL. Demais
expressões comparam estritamente. ACLs/roles/secrets/PKI/journals externos não são
restaurados. Dump e manifesto não possuem assinatura; confiar na origem e guardar
cópias criptografadas fora do host continua pendente. A ferramenta não aceita
arquivos de upload ou destinos arbitrários de API.

Checks direcionados:45testes passaram após correções, com PG real para inventário,
snapshot e constraints; Docker é mockado nas regressões de falhas. Ensaio final
separado executou dump/restore real de30tabelas/2.884linhas e conferiu cleanup.
[Recibo público sem dados sensíveis](../evidence/recovery-2026-10-22/verification.json).

Interrupção abrupta/daemon indisponível ainda exige inspeção das intenções e dos
clones; observed_absent não garante término de uma operação ambígua futura. Não
houve failover, boot da aplicação recuperada ou definição de RPO/RTO. Não houve
nova execução Linux/Wazuh ou autorização ofensiva adicional.

Revisão estática final confirmou as quatro correções sem novo bloqueador concreto.
A observação menor sobre mudança do inventário foi tratada com versão explícita
aegis-pg-inventory/2, recusa de formato antigo antes de Docker e preservação
dos backups legados no plano de retenção. Nenhum manifesto foi migrado/regravado.

Uma rodada da suíte ampla falhou no rate limit porque dois processos pytest locais
compartilharam/limparam Redis DB15. Essa rodada não foi considerada aprovada; a
validação final precisa executar sem concorrência entre suítes. Não se modificou
o rate limit da aplicação para fazer o teste passar.

Validação exclusiva final concluída:423Python/35frontend passaram, lint/tipos
aprovados e CI [39854484061](https://github.com/Buraddomoon/AEGIS/actions/runs/39854484061)
SUCCESS, incluindo build/auditoria. A falha de interferência anterior não foi
mascarada ou usada como resultado aprovado.
