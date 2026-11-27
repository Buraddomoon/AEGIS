# Revisão de conexões defensivas

A entrega #26 é offline: provisionamento host-only, revisão e teste delimitado.
Não inicia Linux/Wazuh, não habilita ingestão, não implanta regra ou cria campanha.
O catálogo opt-in e as referências privadas seguem
[gestão de segredos](../security/secrets-management.md).

O administrador provisiona `DEFENSIVE_PROFILES` somente na implantação desejada.
Use um `id` estável, `revision` positiva e crescente e política exata do lab/ativo.
A API não permite editar destino, CA, referência ou credencial. Com catálogo
habilitado, ausência, erro de permissões/PKI ou ID desconhecido bloqueiam o perfil;
nenhum fallback para a configuração de ambiente é permitido.

Na UI Laboratórios → Revisar coleta Wazuh, selecione um perfil conhecido, confira
revisão, hash, agente, regra, índices e limites. Laboratório deve estar revogado,
sem reserva, execuções pendentes ou cleanup não confirmado. Registre a revisão
com confirmação explícita. O servidor relê o perfil e compara o hash esperado
sob lock do laboratório; muda a versão do ambiente. Nova autorização de execução
continua exigindo preflight e aprovação próprios.

O diagnóstico é ação administrativa separada, exige confirmação e o hash do
binding atual. Faz somente um `GET /` com TLS/SNI/CA e IP fixado, sem DNS dinâmico,
proxy ambiental, redirect, pesquisa de eventos ou scroll. Timeout total por
requisição segue a política (máximo5s), resposta até8MB; não retorna corpo,
versão, exceção, caminho ou credencial do upstream. Retorna `reachable`,
`unavailable` ou `stale` e data/hash, com auditoria sanitizada. Resultado é pontual,
não um estado de saúde persistente. Indisponibilidade significa quantidade de
eventos desconhecida; resposta de transporte não comprova ingestão ou detecção.

`GET /labs/{id}/wazuh-binding` permite consulta autenticada. `PUT` aceita somente
perfil conhecido/hash/revisão/confirmação. `POST .../test` aceita somente hash e
confirmação. `POST .../remove` desativa o binding e exige hash atual no modo de
perfis. Todas as mutações exigem Administrador/CSRF; revisão/remoção compartilham
10ações/hora/usuário, diagnóstico5/minuto/usuário. O endpoint legado de diagnóstico
global é recusado quando o catálogo está habilitado.

Troca de seleção, recarga, falha ou configuração alterada invalida a confirmação
na UI. Desativar preserva escopos/aprovações/evidências/relatórios históricos.
Rotação no mesmo arquivo de senha exige incrementar `revision`; o valor/hash da
senha nunca integra o documento público. Mudanças de perfil não autorizam
reativação de laboratórios nem reutilização de pacotes consumidos.

Sem `DEFENSIVE_PROFILES`, mantém-se o binding de ambiente legado. Não há nova
migração de banco nem alteração/implantação automática no Demo ou originais.
