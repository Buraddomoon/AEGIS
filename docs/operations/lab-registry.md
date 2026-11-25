# Registro fechado de laboratórios — #25

`LINUX_RUNNER_REGISTRY` é opt-in e aponta para um JSON host-only absoluto,
protegido (0600, proprietário do processo ou root), fora do Git. Sem essa opção,
`LINUX_RUNNER_CONFIG` mantém o contrato legado. A presença do registro tem
precedência; configuração inválida nunca faz fallback para o legado.

Formato `aegis-linux-registry/1`, com `entries` (máximo100). Cada entrada tem
`id` estável (`[a-z][a-z0-9-]{2,63}`), `revision` positiva, `owner`, `isolation`
e `connection` no contrato `RunnerConnection` existente: `url`, UUIDs
`runner_id`/`laboratory_id`/`asset_id`, caminhos absolutos `server_ca`,
`client_cert`, `client_key` e `test_id` fixo revisado. Não contém comandos.
A chave privada exige0600; certificados públicos não podem ser graváveis por
outros. Arquivos devem ser regulares, limitados, sem symlinks/travessia nem
ancestrais graváveis por terceiros (diretório temporário sticky é permitido).

IDs, laboratório, ativo, runner e endpoint são exclusivos. Nesta versão cada
registro Linux tem um runner e um ativo; vários registros representam vários
laboratórios. Não existe cadastro livre de hosts, Windows ou múltiplos runners
no mesmo lab. O endpoint aceita somente HTTPS/IPv4 RFC1918 literal/8443,
sem credenciais, query, fragmento ou caminho; TLS/CA/SNI e isolamento continuam
obrigatórios. O administrador do host revisa também o destino real e a rede;
ser RFC1918 não comprova propriedade ou isolamento.

API/UI recebem IDs revisados e hashes públicos, nunca caminhos/chaves. Revisão
ou alteração de owner/isolamento/PKI/endpoint/identidade/perfil exige nova revisão
e invalida escopos antigos. Cadastro deixa o laboratório sem autorização;
preflight vigente e aprovação por outro administrador continuam necessários.
Uma leitura do registro ou seu cadastro não contata o runner e não executa testes.
Ausência/remoção/drift bloqueiam a operação; nunca redirecionar cleanup para
outro runner. Preservar registro e material originais para recuperação manual.

Nenhuma configuração real, autorização de ensaio ou implantação é concedida por
este documento. Não modificar Linux/Wazuh, qasrc, PKI, volumes ou históricos.

## Persistência, seleção e recuperação

A migração explícita `f3b28c5d901a` acrescenta `linux_lab_bindings.registry_id`
exclusivo e `campaigns.asset_id` opcional, com FK composta para o laboratório do
ativo. As colunas existentes e os JSONs históricos não são reescritos. Campanhas
legadas sem ativo explícito só resolvem um candidato inequívoco; Linux usa o ativo
exato da conexão revisada. Downgrade recusa apagar seleções já persistidas.
Aplicar somente em implantação explicitamente autorizada, com backup e código
compatíveis. Pacotes históricos fixados em outro schema continuam históricos;
a nova fonte não autoriza migrar ou reutilizar esses pacotes.

`GET /labs/linux/connections` é administrativo e paginado. A UI exige escolher
um ID e confirmar a revisão/hash (inclui fingerprints dos certificados públicos).
`POST /labs/linux/register` revalida seleção/hash/owner, isolamento host-only e
pré-requisitos de histórico sob o lock do laboratório. Sem registro opt-in, o
formulário legado continua disponível. Falha de leitura bloqueia o cadastro.

`GET /labs` e `/assets` têm `offset`/`limit`; `/assets?laboratory_id=UUID` filtra
pelo laboratório. Cada ativo anuncia plataforma, modo, autorização, estado de
conexão e `available_test_ids` revisados. Capacidade anunciada não é autorização
nem prova de efeito. A criação de campanha aceita `asset_id` somente daquele
laboratório/modo; Windows não recebe capacidade Linux. Históricos paginados em
`GET /assets/{id}/history` usam o ativo e laboratório exatos e apontam para a run
original. Identidade externa explícita é exibida separadamente do ID interno;
nenhum fallback cria um `agent.id` Wazuh.

Preflight, autorização, escopo/aprovação, fila, worker e recuperação resolvem o
laboratório exato. Escopos novos registram o perfil/hash revisado; drift de
identidade, revisão, owner, isolamento, endpoint ou certificados invalida o
binding sem atualizar aprovações/resultados anteriores. Reservas continuam por
laboratório. Cleanup usa o cliente original já aberto; recuperação posterior só
abre cliente se a configuração ainda corresponde ao escopo persistido. Remoção
ou drift exige recuperar manualmente a configuração original; nunca escolher
outro registro para liberar a reserva. Wazuh mantém sua política própria já
revisada, sem cadastro livre de agentes/conectores nesta entrega.
