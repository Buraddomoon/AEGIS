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
