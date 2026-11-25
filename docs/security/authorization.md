# Autorização

| Operação | Administrador | Operador | Visualizador |
|---|---|---|---|
| Consultar catálogo/campanhas/resultados/regras/relatórios | sim | sim | sim |
| Criar campanha, solicitar/iniciar/cancelar execução | sim | sim | não |
| Importar/versionar Sigma | sim | sim | não |
| Aprovar/rejeitar escopo | sim | não | não |
| Autorizar/revogar laboratório e rever cleanup | sim | não | não |
| Gerenciar usuários, testar Wazuh e consultar auditoria | sim | não | não |

Aplicação de workspace único: autenticação permite consulta ao conjunto compartilhado. Não há promessa de isolamento por dono de campanha. RBAC é executado em cada endpoint; controles de frontend apenas refletem permissões.

Aprovação referencia uma solicitação, hash do escopo, aprovador, expiração e duração 10–300s; validade 1–60min. A UI oferece 15min por padrão. Start consome a aprovação e reserva o laboratório na mesma transação. Worker revalida aprovação/ambiente ao reclamar o job; expiração na fila rejeita o job. Duração inclui espera na fila. Mudanças de versão de ambiente, testes ou regras invalidam revisão anterior. Campanhas não são editáveis na versão inicial.

Demo permite que um administrador solicite e aprove sua própria simulação, para instalação local mínima. Linux exige administrador ativo diferente do solicitante ativo e confirm_real_execution=true. Registro de binding, revisão de isolamento, preflight mTLS vigente e autorização administrativa do laboratório também são obrigatórios; worker revalida usuários/allowlist/identidade/configuração antes do efeito. Não há execução real habilitada por uma simples variável de ambiente.


## Contas, senhas e sessões — #24

Configurações separa **Minha conta** (todos os papéis) de **Usuários e permissões**
(somente administrador). Senha própria exige a senha atual, nova senha de12–128
caracteres e confirmação. Redefinição administrativa é destinada a outra conta;
o administrador usa a troca própria para si. Espaços na senha são significativos.
Argon2id mantém os parâmetros existentes. Nenhuma API retorna senha, hash de senha,
token, hash de sessão ou CSRF na listagem de contas/sessões.

`PATCH /users/{id}` recebe exatamente `role`, `active` e `confirm:true`.
Troca efetiva de papel/situação, troca/redefinição de senha e encerramento de sessões
invalidam todas as sessões da conta afetada. Reativar uma conta não restaura seus
tokens antigos. O último administrador ativo não pode ser desativado nem perder
esse papel. Um lock transacional PostgreSQL serializa manutenção/criação e login;
o ator e sua sessão são relidos depois do lock, impedindo que uma permissão lida
antes da espera autorize a manutenção. Operações já iniciadas antes da revogação
não são desfeitas; as próximas requisições verificam a sessão no banco.

`POST /auth/password` recebe `current_password`, `new_password`, `confirm:true`;
`POST /users/{id}/password` recebe somente `new_password`, `confirm:true`.
`GET /users/{id}/sessions` lista vencimento e indicação da sessão atual, e
`POST /users/{id}/sessions/revoke` exige `confirm:true` para encerrar todas.
Própria conta ou administrador acessam sessões; viewer/operator não administram
outras contas. Não há exclusão de usuário nem revogação individual de um token.
Mutações exigem CSRF/origem e limite compartilhado de30ações/hora por ator;
login/criação mantêm seus limites adicionais. Redis indisponível recusa a operação.
Auditoria registra ator, alvo, papéis/situação e contagem de sessões, sem segredos.

Aprovação/escopo/histórico não são reescritos. Start, aquisição da fila e guard do
worker revalidam solicitante ativo com papel operator/administrator e aprovador
ativo administrator, também no Demo manual. Linux mantém os controles adicionais
e separação de identidades. Revogação interrompe novas fases; cleanup permanece
obrigatório e pode concluir com segurança. A conclusão revalida as identidades
mesmo quando a alteração ocorre durante cleanup, sem substituir veredictos já
registrados. Agendamentos mantêm sua revalidação própria.

A UI apaga os campos secretos após tentativa/envio ou fechamento, não os coloca
no cache de consultas e informa falhas reais. HTTP401 limpa consultas e a identidade
em memória; a identidade também é consultada a cada30s e ao recuperar o foco.
Mudança própria de senha/papel/situação ou revogação própria retorna ao login.
A manutenção não implica implantação, alteração de contas humanas do Demo ou
autorização de operação Linux/Wazuh.
