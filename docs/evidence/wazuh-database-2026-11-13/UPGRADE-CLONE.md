# Upgrade Wazuh somente no clone — #58,13/11/2026

**CLONE_UPGRADE_AND_GRANTS_VERIFIED / CLEANED.** O usuário autorizou a proposta
de upgrade/grants apenas em clone ao responder **“tenta fazer entao”**, após a
explicação dos limites de384MiB por banco/helper. Operação realizada entre
13:29:35.121473Z e13:29:58.923610Z, sem exigir8GiB para o stack completo.

## Escopo e isolamento observados

Proposta8468ae93bc934550a10d7bf180f7fa36, SHA256 canônico
`3c7db2a52533a6b8448d5210a28aaddfa3f7dddcaed625a7e8207e994ba6ee45`.
Fonte: [backup frio verificado](README.md), montado RO/nocopy apenas para uma
cópia nova. Original e clones anteriores não foram montados. Os metadados e
consumidores dos nove volumes originais foram conferidos antes/depois.

Imagens locais fixadas, sem build/pull:

- PostgreSQL: `sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24`.
- Cópia: `sha256:b5ae5340f417ef3fce7ce25f8ec07d2dd92545b3a34d6db1982ac37fb108c593`.
- Helper Alembic: `sha256:b8abe5e44af4bad90d2e302a045f38fb9cf268932be5ea0493fc72f078657a23`.

Imagem conferida **antes de SQL**: dez arquivos de migração, modelos instalados
e definições de grants coincidem com a fonte revisada. O helper repetiu as
guardas antes de alterar o clone. Somente chain
4b72→ec302→977fd→a0→b7 aceita; nenhuma ação de seed/bootstrap/API/worker.

PostgreSQL e helper de migração:384MiB cada, memória+swap limitadas ao mesmo teto,
0,75CPU/48PIDs por container, root filesystem RO, caps removidas e
no-new-privileges. Só volumes próprios/arquivos individuais revisados.
Comunicação por socket Unix privado, UID70, diretório/socket0700; ambos com
network=none, sem TCP/portas publicadas. HBA local permite somente owner no clone.
Isso não demonstra autenticação da aplicação nem muda senhas armazenadas.

768MiB é a soma dos **limites configurados dos dois containers simultâneos**,
não uma medição do pico total de RAM do host. Helpers de inspeção/cópia/init foram
executados em sequência e removidos. Nenhum projeto de terceiro foi parado.

## Resultado nativo

- Schema **4b72c7bb8548/29tabelas → b7f3c2d91a06/33tabelas**, incluindo Alembic.
  `alembic check` aprovado na imagem fixada. Upgrade executado uma vez, sem retry.
- Todas as colunas antigas das28tabelas de dados preservadas, incluindo scopes,
  approvals, recibos, dispatches, cleanups, evidências, contas e verificadores.
  Nenhum dado histórico foi reescrito para obter aceite.
- Roles/verificadores e ACLs/owners antigos idênticos após DDL, antes dos grants.
  Todas as constraints antigas permanecem iguais; novas definições vêm das
  migrações fixadas e foram verificadas pelo Alembic.
- Quatro tabelas novas vazias:rule_test_links, attack_catalog_releases,
  attack_catalog_state e scheduled_reports. Sem publicação/adopção de catálogo.
  As colunas de ciclo de vida ATT&CK foram acrescentadas pela migração prevista;
 706entradas antigas preservadas na projeção de colunas originais.
- Grants mínimos de `aegis.operations.runtime_grants` aplicados **somente ao clone**:
  **231verificações de privilégios de tabela e277de UPDATE por coluna passaram**.
  Incluem Alembic inacessível ao runtime, recibos/cleanups/auditoria imutáveis,
  catálogo sem escrita e updates limitados nas tabelas administrativas.
- Grants não mudaram linhas ou verificadores; ACLs de papéis diferentes de
  aegis_app preservadas. Sem rotação de senha ou nova conta administrativa.

| Evidência JSON canônica | SHA256 |
|---|---|
| Inventário antes | `8e076899d9c90040fa4dabd7df8e1ba898b2d20db60ff582f05c09d2aea48dcf` |
| Linhas/colunas antigas antes e depois | `c708e83887e5a8a69825dfdbfe25771f38cb784f6d23a08596fcf5c1277aaf61` |
| Inventário depois de DDL | `6adb36b7f30dfe958610b43de15f8243aeb096f923e8257e99e8a8eca52efc07` |
| Inventário final após grants | `b04c7c04f4717b842b175a605d1388f27e81b33f0576ccd1be9ed21fe82ce33a` |
| Plano/escopo executado | `ef51fd95d7e8e1733b1202b7333868d442310f3d103bc197d30a9836e0046cd6` |
| Recibo final | `15ea361226e90fdc869be109c04ff28593cd2ac182c7787348f51591cd9fb4e9` |

JSON canônico usa UTF-8 de `json.dumps(value, sort_keys=True, separators=(",", ":"))`,
sem newline. SHA256 dos bytes do recibo:
`38eeb1ea29de1572eb250594dd401dcbadf197f496f7e86c4b761a97e98d17be`.
Hashes identificam conteúdo, sem equivaler a assinatura ou autorização.

## Encerramento e limites

Conferência independente final: zero containers próprios e zero consumidores
dos volumes originais, backup, clone novo e socket. Metadados originais
preservados; nenhuma rede criada. Backup frio relido após o ensaio conserva
51.673.168bytes/1.451entradas e SHA256
`f93cd36d483a25d30b2df11bce97dd331aaba1fb6bf8fb2ae33ce9d128a05085`.

Novos volumes working/socket retidos em `aegis-wazuh-upgrade-8468ae93bc93-*`.
Recibos, SQL/resultados privados e operadores congelados ficam host-only em
`.local/wazuh-schema-upgrade/8468ae93bc934550a10d7bf180f7fa36`, fora do Git.
Sem upload de dumps/logs/credenciais. O backup e os clones do diagnóstico seguem
preservados. Autorização utilizada neste ensaio; não autoriza operação permanente.

**Original continua4b72/29tabelas**, conforme o backup e sem intervenção nesta
etapa. Não foi iniciado, montado ou migrado. Nenhum journal, PKI, lab/binding,
Wazuh, API/worker, runner, observador ou marcador. Não há alerta novo nem DETECTED.

A compatibilidade em clone foi demonstrada, mas isso não implanta a mudança no
original. A#58 continua aberta para a intervenção original especificamente
aprovada e demais pré-requisitos do pacote integrado; #59/#60 continuam pendentes.
O escopo da próxima intervenção está em [CYCLE-ASSAY.md](../../../labs/wazuh/CYCLE-ASSAY.md).
