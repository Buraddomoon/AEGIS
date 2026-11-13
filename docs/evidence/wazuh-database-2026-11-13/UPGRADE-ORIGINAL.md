# Manutenção do banco original Wazuh — #58,13/11/2026

**ORIGINAL_UPGRADE_AND_GRANTS_VERIFIED / CLEANED.** O usuário respondeu
**“autorizo”** à proposta separada de aplicar no original a migração/grants
demonstrados no [clone](UPGRADE-CLONE.md), mantendo backup e sem Wazuh/campanha.
Execução entre13:39:58.721566Z e13:40:17.201522Z.

## Escopo executado

Propostaf202657f619840c99d0ff13f3438acb8, SHA256 canônico
`461edc2f2d692705e0b13d2328e3ce36679c0064d750a0d83c3d7a7c20c4677d`.
Volume original`aegis-wazuh-lab_postgres-data`. Os nove volumes foram
reidentificados por metadados/labels/nomes e tiveram ausência de consumidores
conferida. Backup frio e original foram lidos RO/nocopy e coincidiram no hash
`f93cd36d483a25d30b2df11bce97dd331aaba1fb6bf8fb2ae33ce9d128a05085`
**antes de iniciar PostgreSQL original**. Divergência impediria esse startup.

Mesmas imagens e mesmo helper congelado do ensaio em clone: PostgreSQLb0f9560a,
cópia/inventário b5ae5340 e helper Alembicb8abe5e4, por IDs completos registrados
no plano/recibo. Migrações/modelos/grants da imagem conferidos antes de SQL.
Intenção durável antes de startup, upgrade e grants; execução única, sem retry.

PostgreSQL original384MiB e helper384MiB, cada um com rootFSRO, caps removidas,
no-new-privileges,0,75CPU/48PIDs, sem swap além do limite de memória. Rede none,
sem TCP/portas, comunicação apenas por socket Unix privado UID70/modo0700 em
volume próprio novo. Owner local limitado a essa manutenção; nenhum segredo de
dono enviado à API/worker. HBA temporário externo não reescreveu o arquivo HBA
armazenado no original. Exclusividade de consumidor conferida antes dos efeitos.

## Resultado e preservação

1. Original confirmou exatamente4b72c7bb8548/29tabelas e o inventário lógico
   esperado. A mesma cadeia4b72→ec302→977fd→a0→b7 foi aplicada explicitamente.
2. **Original agora b7f3c2d91a06/33tabelas**, `alembic check` aprovado. Nenhum
   serviço genérico de migração, seed ou atualização implícita de senha.
3. Todas as colunas antigas das28tabelas de dados e os verificadores de senha
   permaneceram iguais. Inclui IDs, scopes, approvals, dispatches, recibos,
   cleanups, auditoria, sessões e evidências históricas. Nenhum relatório/run
   anterior foi reescrito para fazer o fluxo passar.
4. Quatro tabelas novas vazias:rule_test_links, attack_catalog_releases,
   attack_catalog_state, scheduled_reports. As706técnicas existentes foram
   preservadas nas colunas antigas; nenhuma release ATT&CK foi publicada/adotada.
5. Grants mínimos somente para aegis_app: **231checks de privilégios de tabela
   e277de coluna passaram**. Roles/verificadores e permissões de outros papéis
   preservados; dados não mudaram durante os grants. Sem conta nova.
6. Inventários completos do original após DDL e após grants coincidiram com os
   mesmos estados verificados no clone. Sem diferença adicional ignorada.

| Evidência JSON canônica | SHA256 |
|---|---|
| Plano/escopo executado | `9aa379a3ea24f6210243270eb1b3e86c38a5265a4c7f8b85de450bd502c81a67` |
| Inventário antes | `8e076899d9c90040fa4dabd7df8e1ba898b2d20db60ff582f05c09d2aea48dcf` |
| Linhas/colunas antigas antes e depois | `c708e83887e5a8a69825dfdbfe25771f38cb784f6d23a08596fcf5c1277aaf61` |
| Inventário depois de DDL | `6adb36b7f30dfe958610b43de15f8243aeb096f923e8257e99e8a8eca52efc07` |
| Inventário final após grants | `b04c7c04f4717b842b175a605d1388f27e81b33f0576ccd1be9ed21fe82ce33a` |
| Recibo final | `d7d292dd6d88ed523271feb3561b0adeb0632a59c6c79b2d9e967945f236d39b` |

JSON canônico: UTF-8 de `json.dumps(value, sort_keys=True, separators=(",", ":"))`,
sem newline. Recibo em bytes: SHA256
`d37790fffdf3f95184f7cec8cecaa220cd9379b9566d711035bad25429afff40`.
Hashes identificam os artefatos, sem equivaler a assinatura/autorização.

## Encerramento e limites

PostgreSQL original parado e containers próprios removidos. Conferência
independente: zero consumidores dos nove originais, backup frio e socket novo.
Nomes/labels/identidade dos volumes preservados; **o conteúdo físico do banco
original mudou como esperado na manutenção**. Não chamá-lo de byte a byte intacto.
Após shutdown:68.391.491bytes/1.475entradas, inventário físico SHA256
`2c19f3edf9ea9c176ed21dc75f78f23b52969b737ff9e0c449c6bb90d1704522`.

Backup frio continua51.673.168bytes/1.451entradas, mesmo SHA256f93cd36d completo
acima, schema4b72/29. Clone/restore antigos e clone atualizado b7 foram retidos;
socket da manutenção também retido. Operador, SQL/saídas privadas, intenções e
recibos em `.local/wazuh-original-upgrade/f202657f619840c99d0ff13f3438acb8`,
host-only0700/0600. Nenhum dump/log/credencial adicionado ao Git ou enviado fora.

Autorização desta manutenção utilizada e encerrada. Nenhum journal aberto,
ativação de PKI, alteração de lab/binding, usuário novo, catálogo publicado,
API/worker/Wazuh/runner/observador ou marcador. Nenhum alerta novo/DETECTED.
A migração não prova conectividade ou operação normal do laboratório.

Após cleanup, a leitura de recursos para o **futuro stack integrado** ainda
recusou: MemAvailable6.479.118.336bytes (~6,03GiB), mínimo8GiB. Isso não bloqueou
o trabalho de banco/helper de até768MiB configurados. Nenhum terceiro foi parado
ou guard reduzido. #58 permanece aberta para os demais gates; #59/#60 pendentes.

## Imagens atuais preparadas sem iniciar a plataforma

A revisão posterior, somente de arquivos, identificou diferenças nas imagens
recentes reutilizáveis: perfil de rede antigo e módulo novo Wazuh ausente; no
runner faltava também linux_campaign_readiness. Foram preparadas imagens locais
dedicadas a partir das bases existentes, copiando apenas esses arquivos atuais
e acrescentando um manifesto/checker separado. Provas antigas das bases foram
preservadas; não se reescreveu o manifesto de build histórico.

| Papel | Tag dedicada | ID atual |
|---|---|---|
| API/worker | aegis-wazuh-platform:review-df6670f91409 | `sha256:64112646c663933a81a3777adbac03ea439ee6ae923a74418996d8d370fba0fe` |
| Runner/observador | aegis-wazuh-runner:review-df6670f91409 | `sha256:0440049a28cb8799d350d1a646f470e6eed26cc0893384ab6cc211050cfaba54` |

Basesba50a78c/a893bdae retidas em tags próprias antes do build. Tags históricas
Wazuh`:local` e Demo`:0.1` conservaram seus IDs. Build local com
`--network none --pull=false --load`, sem instalação de dependências ou
publicação. Nenhuma mudança de versão/tag Git/release. Frontend herdado da fonte
752ad29; a árvore apps/web é idêntica à fonte atual.

Checker executado durante cada build e depois em containerRO/sem rede/128MiB:
**73arquivos Python e45versões runtime por imagem conferidos** contra fonte
a2378b1; perfil importado retornou runner192.168.253.10 e Indexer192.168.253.18.
Prefixos de camadas confirmam as bases retidas. Zero containers de inspeção ao
terminar; sem volumes de laboratório montados ou daemons de aplicação iniciados.

Manifestos/contextos/logs privados em `.local/wazuh-current-images/df6670f914094274855a191b14e8afab`.
Recibo JSON canônico SHA256
`f4ce94075ddec77f7d2934d7fd238dabd2a07c437c4aee1acab99cb6542f3542`;
bytes`eedfb907755d2a6ec28726bb30061fd6b526f7dbdb05f824748bb5668a1eef40`.
Imagem construída/conferida não é imagem implantada, ensaio TLS ou marcador.

Releitura após a preparação das imagens: MemAvailable5.586.509.824bytes
(~5,20GiB), gate integrado ainda recusado. Não foi necessário liberar8GiB para
esta manutenção ou os checks pequenos; não transferir esse fato para o stack.

Retomada: usar b7 e os IDs atuais na revisão do pacote, obter candidatos PKI
novos quando o gate permitir, revisar continuidade sem liberar replay, catálogo
versionado ainda vazio e identidade/regra/ACL/observer no runtime. Gerar pacote
específico de uma tentativa antes de solicitar aprovação do ensaio integrado.
Não reutilizar autorizações consumidas ou iniciar a próxima feature.
