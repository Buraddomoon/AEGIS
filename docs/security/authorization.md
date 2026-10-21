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
