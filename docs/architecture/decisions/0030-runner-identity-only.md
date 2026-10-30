# ADR 0030 — Superfície mTLS somente de identidade

Estado: aplicação e testes locais implementados; imagem revisada, executor de
rede/mounts e ensaio nativo ainda pendentes. Sem ativação ou permissão de startup.

## Decisão

A conferência de confiança da PKI não precisa disponibilizar rotas que preparem
ou iniciem jobs, nem abrir o diário original. Adicionar ao entrypoint existente
o opt-in de implantação `AEGIS_RUNNER_IDENTITY_ONLY=true`. Não é parâmetro de API
ou configuração de usuário. Valor booleano inválido impede boot, sem fallback.

Neste modo, `create_identity_app` só registra GET /v1/identity. Nenhum Runner,
Workspace ou Journal é instanciado; /state e /work não precisam existir e não são
abertos. Não há recuperação de jobs interrompidos, reserva, evento ou marcador.
Métodos diferentes de GET recebem503 antes de consumir payload; rotas de jobs,
docs/OpenAPI e consulta do histórico não são expostas. HTTPS continua obrigatório
no app e o mesmo entrypoint Uvicorn exige certificado de cliente, um worker e
proxy_headers=false. ASGI sozinho não comprova handshake TLS.

A resposta preserva IDs e protocolo, mas anuncia `tests=[]`, além do header
X-AEGIS-Runner-Mode: identity-only. Isso permite ao cliente normal recusar preflight
por allowlist vazia, mesmo se o header for removido: identidade válida não implica
capacidade de execução. Não marcar laboratório como operacional após essa revisão.
Cache-Control:no-store e nosniff permanecem no endpoint e nas recusas do modo.

Modo padrão mantém o runner completo e seu comportamento anterior, sem habilitar
o opt-in em Compose ou reiniciar serviços existentes. O futuro compilador deve
fixar a variável e revisar sua projeção, os três secrets folha/CA cliente e a rede.
Não montar chaves de CAs, diretório PKI inteiro, socket Docker ou volumes originais
neste servidor de identidade. Conferir identidade não prova continuidade do diário,
vínculo SQL, isolamento do host ou registro do novo binding.

## Verificação e limites

Testes de ASGI verificam rotas e métodos, allowlist vazia, recusa de payloads e
do cliente operacional. Testes do entrypoint verificam ausência de instância
Runner/diretórios de estado, TLS exigido, modo inválido e seleção padrão anterior.
Teste real Uvicorn/httpx somente loopback usa certificados temporários, aceita
cliente correto e recusa cliente sem certificado. Testes existentes de transporte
continuam verificando cliente incorreto e servidor não confiável no modo padrão.
Nenhum container Linux ou volume original foi iniciado.

A imagem6b9033b9 do diagnóstico histórico não contém esse recurso: é necessário
novo build selado/revisado antes de uso nativo. Preservar imagem/recibo anteriores;
não declarar um build velho como atualizado nem reutilizar a autorização consumida.
O coordenador deve comparar explicitamente o modo/allowlist e os IDs esperados.

## Compilador interno do container

runner_activation_identity_runtime aceita somente plano /2 íntegro/válido, header
de intent correspondente e network-isolated já OBSERVED por ID completo. Não faz
RPC ou leitura de chaves. Criação compilada exige runner REQUESTED sem ID, sem
reutilizar papel observado ou mudar intent. Conferência física ainda é separada.

Receita fixa Python-I/-B/módulo server, UID10001, readonly rootfs, caps removidas,
no-new-privileges,192MiB/0,5CPU/16PIDs/tmpfs16MiB, sem stdin/TTY/healthcheck/logs/
restart/ports. Rede somente pelo ID próprio fixado, IP172.30.88.2 e três bind
mounts folha/CA cliente RO/rprivate do candidato. Nenhum volume nomeado/anônimo é
pedido; imagem com VOLUME implícito precisará ser recusada pela revisão futura.
Não montar /state, /work ou Docker socket. CSV de mounts recusa vírgula/newline/NUL.
ENV fixa identity-only e três UUIDs; não há arquivo .env, senha ou comando livre.

Compilar não prova disponibilidade da imagem/secret, conteúdo atual, ambiente
herdado, configuração do daemon ou tráfego. Driver/gates/create/start e revisão
física ainda pendentes. Não fornecer argumentos compilados ao daemon real sem
coordenador/procedimento e autorização específica. Testes usam somente temporários.
Perfil público permanece executor_implemented=false e não amplia o diagnóstico /3.

Referências oficiais revisadas: [container create](https://docs.docker.com/reference/cli/docker/container/create/)
e [gateway modes](https://docs.docker.com/engine/network/port-publishing/#gateway-modes).

## Inspeção somente leitura

runner_activation_identity_inspection projeta image inspect e container inspect
por IDs completos. Conferência de imagem exige UID10001, sem VOLUME, ExposedPorts,
OnBuild ou env herdado não revisado. Isso não comprova fonte/proveniência nem
implementação do modo: esses flags permanecem falsos. Imagem histórica pode passar
no perfil básico sem conter o código novo; não a declarar atualizada por isso.

Container precisa estar OBSERVED/START_REQUESTED no intent e corresponder ao
ownership antes/depois do IO. Somente created/running, processo/labels/limits/env
exatos, nenhuma porta/volume declarado ou mount além dos três binds RO/rprivate e
tmpfs /tmp opcional efetivo. Conferência usa caminhos correspondentes como booleanos,
sem retornar fontes host/valores de env. Opções bind extras, chave RW, fonte errada,
predicados inteiros e mount duplicado bloqueiam. Opções omitidas no JSON Docker
usam index/defaults explícitos, sem relaxar valores esperados.

Endpoint precisa ser somente da rede própria/ID, IP configurado172.30.88.2, sem
IPv6/link-local/links/opções de driver extras. Antes do start, a projeção ainda pode
não ter endereço/ID alocados; após start exige IP/prefixo/ID reais exatos. Isso não
comprova conectividade/firewall ou mTLS. Releitura do plano/receita/intent após IO
recusa expiração e drift; não existem create/start neste módulo.

Testes executam o Docker CLI real contra daemon HTTP Unix falso, além de fixtures
adversariais e PKI/planos temporários. Nenhum container é criado nesses testes.
Inspeção nativa somente da imagem histórica6b9033b9 confirmou o formato básico,
mantendo identity_mode_implementation_verified=false/image_provenance_verified=false.
Runtime nativo, nova imagem, gates de start e coordenador continuam pendentes.

## Fence durável anterior ao start

O catálogo fechado de intents admite identity_start_requested apenas para runner
OBSERVED, sem start anterior, modo literal identity-only e rede isolada própria
OBSERVED por ID. Vincula recipe/gates/manifesto PKI e ID de rede. Qualquer outro
papel nãoABSENT, inclusive DB, backend, API ou probe pendente, bloqueia esse perfil.
Não ampliar isso para runner operacional: são procedimentos distintos.

O evento marca START_REQUESTED antes da RPC futura; retomada nunca repete start.
identity_runtime_observed só segue esse start, guarda hash da configuração e volta
a OBSERVED, preservando o fence: mesmo sucesso não permite segundo start. Não
comprova daemon/mTLS ou autorização. Cleanup aceita estado ambíguo e retém a rede
até ausência do runner; fechamento depende de ausência de todos os recursos.
Nenhum start é invocado por essas funções/testes e o limite64eventos é mantido.

## Membros exatos da rede durante a conferência

runner_activation_identity_network revisa configuração do bridge e os IDs dos
endpoints, além de ownership da rede/runner. Criar exige rede vazia e runner ainda
REQUESTED/ausente; antes do start aceita rede vazia ou somente o runner próprio
parado. Running exige start identity-only durável e um membro com ID/nome/IP/prefixo
esperados, sem IPv6/extra fields. Contagem igual com membro estrangeiro bloqueia.

Repete snapshots completos (incluindo endpoints), compara contagem de ownership,
reconfere receita/plano/intent e aplica orçamento integral20s com query limitada
pelo restante. Outros papéis nãoABSENT são incompatíveis. Saída só hashes/counts/
ID próprio, sem retornar endpoints de terceiros. Não consulta outros alvos ou
emite tráfego. Não comprova a quiescência global do projeto: inventário ativo ainda
deve ser combinado pelo gate futuro. Metadados não comprovam mTLS/firewall/alcance.

A revisão antiga da rede vazia continua recusando qualquer membro. Foi extraída
apenas a validação privada dos campos não relacionados a endpoints, permitindo
reusar o perfil exato sem fingir rede vazia ou relaxar o contrato público antigo.
Testes de rede vazia/lifecycle foram reexecutados junto às novas fixtures.

## Contextos ativos exclusivos para identidade

active_metadata/active_plan aceitam runner apenas nas fases explícitas
identity-create/identity-start/identity-running. Os nomes create/start/running
genéricos continuam negados para runner. Outros papéis não ganham fases identity.
O diagnóstico /3 conserva sua allowlist de cinco papéis e recusa todas essas fases
antes de consultar inputs/daemon. Isso não disponibiliza lifecycle do runner normal.

Somente network-isolated/runner podem estar nãoABSENT. Membership global inclui
parados, nomes de redes reservados e consumidores externos de ambos os volumes,
que precisam permanecer vazios. Runner em running exige start identity-only e
configuração observada duráveis. Recheck do plano compara os hashes de receita,
manifesto PKI e rede do start ao perfil atual antes de novas consultas; recibo
histórico errado permanece preservado e bloqueado, sem reescrita.

Os guards existentes mantêm dois snapshots, prazo integral20s, versão main limpa,
PKI/Compose/inventário/plan TTL e ownership após IO. Retorno identity_only_ownership_
context_verified não comprova implementação do modo, mounts físicos ou tráfego:
gates futuros devem combiná-lo com identity_inspection e identity_network. Sem
CLI/start ou nova autorização real neste incremento.

## Probe de identidade e controles TLS, com conclusão proporcional

`aegis.lab_runner.identity_probe` oferece entrypoint fixo PID1/UID10001/container,
stdin privado<=16KiB/contextSHA independente, sem URL/path/comando livre. Destino
único172.30.88.2:8443 e somente GET /v1/identity. TLS1.3 exige CA/hostname válidos e
pin DER da folha; identidade completa/allowlist vazia/header de modo precisam casar
o contexto. Certificados públicos montados são conferidos por hash, chave cliente
só pelo loader TLS. Não lê chave antiga, CA privada, diário ou PostgreSQL.

Prazo async integral12s/handshake2s, header8KiB/body32KiB, Content-Length explícito,
sem redirect/compressão/transfer encoding ou campos JSON duplicados. Arquivo público
é regular e<=64KiB; open nonblocking/nofollow rejeita FIFO/symlink. Overrides
SSLKEYLOGFILE/SSL_CERT_FILE/SSL_CERT_DIR são recusados antes de criar contexto.
Erros só em códigos estáticos, sem mensagens/bytes de resposta ou segredos.

Confere identidade com material candidato antes/depois dos controles e comprova
rejeição da CA anterior apenas por código TLS de issuer não confiável19/20/21.
Expiração10, timeout ou falha genérica de rede não contam como essa prova. Se a
tentativa sem cliente recebe alerta certificate_required explícito, há evidência
do requisito; reset/EOF sem razão TLS ficam **INCONCLUSIVE**, sem atribuir causa.
Se a mesma identidade puder ser obtida sem certificado, o probe recusa sucesso.

Uvicorn/asyncio reais no loopback retornaram reset, inclusive no experimentoTLS1.2.
Mantido TLS1.3 e registrada a incerteza, sem converter reset em autenticação
confirmada. A saída distingue identidade com material carregado de certificado
cliente autenticado: não afirma que o cliente foi apresentado/verificado sem
evidência do transporte do servidor. Próximo passo é instrumentar essa evidência.
Exit0 significa revisão concluída e pode conter status inconclusive; futuro
coordenador precisa validar status/flags, nunca autorizar por exitcode sozinho.
Flags de ativação, volumes, marcador e rejeição de credencial cliente antiga são
sempre falsas. Probe não é telemetria defensiva ou resultado ATT&CK DETECTED.

Testes usam TLS real somente loopback e diretórios privados temporários; nenhum
container/PKI/binding original é iniciado/modificado. Nova imagem/coordenador e
autorização específica continuam necessários antes de invocar o probe no lab.

## Evidência do peer obtida no transporte do servidor

`tls_peer.IdentityTLSProtocol` adiciona uma extensão ASGI privada por conexão.
Captura DER do peer diretamente de ssl_object somente quando o SSLContext real
está em CERT_REQUIRED; guarda apenas hash/version em dataclass imutável. O app
identity-only retorna headers de hash do cliente/política/versão TLS somente
para esse tipo de evidência. Headers recebidos do cliente não são fontes aceitas.
Sem certificado/contexto/política apropriados, não emitir prova.

Adapter usa o protocolo H11 já instalado, com wrapper ASGI próprio de cada
conexão antes de parsing ou agendamento de tasks. Extensão reservada é sempre
substituída, inclusive porNone, e scope/extensions são copiados por request.
Não depende de contextvars, TLS de conexão anterior ou ordem de task eager;
reutilizar a mesma instância de protocolo para outra conexão é recusado.

O campo per-connection self.app é um detalhe revisado do Uvicorn0.54.0. Compatibilidade
é guardada por versão exata no startup identity-only e no construtor do adapter;
upgrade deve rever código/contrato e repetir testes, sem simplesmente ampliar
allowlist. Não há nova dependência ou substituição do parser HTTP. Modo normal
continua auto; somente identity-only seleciona o adapter no entrypoint.

Testes TLS loopback reais conferem hash DER do cliente mesmo com header de request
falso, além de isolamento entre conexões, ausência de prova sem TLS/validação e
recusa de versão desconhecida antes de abrir servidor/diário. Nenhuma rede/container
de lab foi iniciado. O probe /1 ainda não consome esses headers: seu relatório
inconclusivo permanece proporcional; a próxima versão deve vinculá-los ao cliente
esperado e conservar a incerteza independente do controle negativo.

## Probe /2: autenticação observada e controle negativo separados

Request/resultado sobem para /2, sem upgrade implícito de /1. Request fixa também
DER do cliente e janela UTC positiva<=300s. Probe confere PEM e DER do material,
identidade/folha servidor e os três headers do adapter revisado: hash cliente
esperado, política required e versãoTLS1.3. Ausência/divergência da prova recusa a
revisão. O vínculo depende do servidor/imagem/transportes próprios verificados;
um header de servidor arbitrário não é atestado independente de origem.

candidate_client_certificate_verified e server_client_certificate_policy_verified
representam o peer e SSLContext observados. missing_client_rejection_verified
continua falso quando a tentativa sem certificado só produz reset/EOF. Resultado
global permanece inconclusive nesse caso, com fatos positivos preservados; nenhuma
flag de ativação/volumes/marcador/credencial cliente antiga se torna verdadeira.

Janela é conferida antes de abrir material/rede e de cada conexão. Timeout integral
é min(12s, restante da janela). decode_result confere até4KiB, formato fechado,
hash/contexto/folhas, tipos booleanos estritos e classificação coerente. Pode ler
recibo histórico após expiração, sem autorizar reutilização do contexto na rede.
Não autentica origem sozinho: coordenador deve capturar do runtime próprio.

## Fonte da imagem fixada ao código atual

runner_activation_identity_image usa o ID de imagem e commit fixados pelo plano.
Referências de build identificam provas de apoio, não escolhem outro executável.
Exige recibo de build já existente/íntegro com cliente terminado0; ausência não pode
ser suprida implicitamente por revisão de uma imagem presente. Reusa verificadores
de fonte/build do diagnóstico, sem chamar plano/run/SQL/diário desse procedimento.

Confere metadados locais do build/imagem e compara todos os arquivos do pacote,
requirements.lock e pyproject.toml aos blobs da main limpa atual. Novo commit com
pacote/dependências diferentes não transforma uma imagem velha em atual. Reconfere
commit/recibo após IO. Sem build/pull/start ou leitura de chaves. Essa evidência é
local sob confiança no host/daemon, sem assinatura de publicador ou execução do
modo comprovadas. TLS/comportamento efetivo ainda precisam de ensaio próprio.
