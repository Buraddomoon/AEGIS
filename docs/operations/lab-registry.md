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
