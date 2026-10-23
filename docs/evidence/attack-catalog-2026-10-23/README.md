# Publicação ATT&CK e Demo local — 2026-10-23

Este marco valida metadados oficiais e simulações **sintéticas**, sem novo efeito
Linux/Wazuh. Enterprise20.0 já era a versão atual; a publicação acrescenta
proveniência fixada e registros retirados ao snapshot inicial, sem inventar uma
versão oficial posterior. [Operação](../../integrations/mitre-attack.md).

## Fonte e ensaio isolado

Download real pela CLI `prepare`, HTTPS do repositório oficial:
commit `c2494b29dd268c46a5d0ea0990553e4327cd2253`, arquivo
`enterprise-attack/enterprise-attack-20.0.json`,55.271.014bytes,
SHA256 `81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352`.
Licença corresponde aos bytes revisados no repositório. Bundle contém26.690
objetos e867técnicas:706ativas/149revogadas/12descontinuadas.
Fonte bruta/cache/planos privados permanecem fora do Git.

[Recibo oficial](official-publication.json) registra seed inicial conhecido,
CLI plan/apply efetivos em schema PostgreSQL17 descartável, duas execuções pelas
funções reais do worker, oito testes sintéticos, consulta autenticada de
evidências/relatórios/indicadores e comparação. HTTP é TestClient, sem processo
worker separado nesse ensaio; o E2E abaixo cobre processos separados.
Não foram usadas as fixtures STIX reduzidas neste ensaio oficial.

Plano:161 inclusões de técnicas retiradas e source_modified nas706ativas,
sem reserva/run/agendamento pendente. JSON do relatório anterior conservou o
mesmo SHA256 após publicação e após nova execução; seed não sobrescreveu a
release. Reaplicar retornou already_applied, com duas releases preservadas.
Cobertura da release atual ficou0 e depois3técnicas; indicadores históricos
mantiveram seis testes válidos e dois detectados nos dois ciclos,33,3% nesse escopo.
Comparação apontou mudança de catálogo e equivalência falsa. Schema removido,
chaves próprias em Redis13 limpas; nenhum serviço externo acessado.

## Implantação no Demo em uso

Antes da migração: schema977fd0c42ae8,20runs, zero pendências/reservas/plano
retomável. Backup privado `20261023T185409Z-1ee667a8a3b6449299cfe4dfa8cbda2b`
restaurado em clone offline:30tabelas/2.884linhas iguais, clone removido,
5,264s medidos, sem promessa de RTO. Imagens antigas por ID preservadas em tags
locais próprias, incluindo imagem recovery do marco anterior.

Imagem nova `sha256:f5dd7a0f9d1aff676fbdabef1c6314b16a28cadca3261d26b2e20fa7d3ee462b`.
Somente API/worker do Demo foram parados e recriados, mantendo db/redis próprios.
Migração/seed/grants aplicados, schema a0d9c7e21b45 com32tabelas; health ready
database/redis=true. Antes da publicação,27tabelas não afetadas pela migração
estavam idênticas ao manifesto anterior. Runtime não pode escrever no catálogo.

[Recibo da implantação](default-deployment.json): plano público local revisado,
sem bloqueadores/testes afetados; commit e SHA do bundle coincidem com a fonte
do snapshot anterior. CLI aplicou sob administrador temporário próprio e nova
release foi lida autenticada pela API18780 com papel SQL runtime. Conta temporária
desativada e sessão encerrada; não há credencial nova a compartilhar.
Vinte runs antigas preservadas;26tabelas históricas comparadas ao backup iguais,
excluindo as mudanças esperadas em usuário/auditoria/schema/catálogo.
Cobertura da release atual é0; legado continua no histórico com versão de escopo
desconhecida. Nenhuma nova campanha foi executada no Demo em uso neste marco.

Backup posterior `20261023T185803Z-e24dc58921054fef8aa4fdab4b4a2caf` também foi
restaurado/verificado em clone sem rede:32tabelas/3.055linhas,5,132s medidos,
clone removido. Dump/manifesto privados e backups anteriores preservados.
Isso valida restauração de dados; não repete boot/reconciliação/ciclo completo
com a imagem nova. A tag recovery atual aponta para a imagem nova; as antigas
continuam disponíveis pelos IDs/tags preservados, sem enfraquecer revisão.

## Testes e limites

- `make test`:654Python e43frontend passaram, com PostgreSQL/Redis reais.
- `make lint` e build passaram; aviso upstream TestClient/httpx permanece.
- `make e2e`: Firefox, API/worker separados,4runs/16testes sintéticos, zero erros
  JavaScript,11capturas reais incluindo proveniência e pesquisa histórica.
  Capturas usam o snapshot inicial distribuído e não fingem publicação oficial.
- 71casos de recuperação passaram após ajuste de fixture. Uma CI anterior
  recusou lock NOWAIT antes da mensagem de integridade esperada, compatível com
  disputa de manutenção de fundo. Autovacuum só das tabelas do banco descartável
  de testes foi desabilitado; controles de produção e conflitos explícitos
  continuam. Resultado remoto final fica no PROGRESS.
- [Revisão de segurança](../../security/review-attack-catalog-2026-10-23.md):
  prazo integral de HTTP e lock de TestDefinition corrigidos e testados.

Receitas JSON são resumos curados, sem dumps, senhas, tokens, usernames ou
conteúdo confidencial. Hashes verificam conteúdo, não assinatura. O marco não
valida todas as versões futuras de STIX, implantação de regras ou cobertura de
ambiente empresarial. Imagem/schema novos não podem abrir backups antigos
ignorando as guardas. Nenhuma autorização real anterior foi reutilizada.
