# Linux Lab — runner restrito e campanhas integradas

Runner e adaptador para **um marcador benigno**, integrados à API/worker/UI por opt-in. Sem integração operacional Wazuh; comprovantes do executor não são evidências defensivas. `make up` continua iniciando somente Demo. As seções iniciais descrevem o runner standalone; o segundo incremento integrado e seu escopo estão abaixo.

## Escopo concreto do ensaio

Projeto Compose `aegis-linux-lab`, imagem `aegis-linux-runner:local`, serviço `runner` e um `controller` temporário. Rede dedicada `172.30.88.0/29`, interna, com gateway mode **isolated** e sem portas publicadas. O bridge não recebe endereço do host. Nenhum container é conectado às redes da aplicação, da empresa ou de outros projetos; sem socket Docker, volumes de dados/diretórios do host ou host networking. Somente arquivos específicos de certificados/configuração são montados read-only como secrets; chaves de CA não são montadas.

Único teste: `linux-file-marker/v1`, sem técnica ATT&CK atribuída. Programa Python fixo cria `proof.marker` com `aegis-UUID` mais newline (43 bytes), lê/confere conteúdo/hash e registra `receipt.json`. Ambos ficam em diretório UUID sob `/work` tmpfs de 1 MiB. Cleanup remove somente esses dois nomes e o diretório, sem recursão. Arquivo desconhecido/symlink/erro mantém reserva e exige revisão.

Um efeito por vez, deadline máximo de 5 segundos para o filho e lease de 2 segundos renovado pelo controlador. O runner encerra/reap o grupo em cancelamento/timeout/perda do controlador. PID de arquivo nunca é reutilizado para kill. Reinício conserva diário/fence no volume e marca resultado ambíguo como INTERRUPTED; não repete execução.

A identidade runner/lab/ativo é UUID local persistente. O diário não aceita outra identidade. O protocolo exige hash de escopo e geração exata; requisições repetidas não mudam prazo nem repetem efeito. Diário limitado a 10.000 jobs, sem expurgo automático que apagaria fences.

Comprovante `synthetic=false`, `kind=execution_receipt` identifica um efeito real no container; **não é telemetria defensiva**. Sem SIEM consultado, a avaliação é INCONCLUSIVE. Não declarar DETECTED, proteção empresarial ou correspondência a Windows.

## Requisitos e preparação

Linux, Docker Engine **28+** (gateway mode isolated), Compose, Python 3.13/venv do projeto e OpenSSL. Host atual observado: Docker 29.8.1. Limites: runner 192 MiB/1 CPU/64 PIDs, controller 128 MiB/0,5 CPU/16 PIDs. Não são benchmarks. Containers compartilham kernel; testes mais complexos exigirão VM revisada.

```bash
make lab-init     # gera PKI/IDs locais; não inicia containers
make lab-config   # valida Compose, sem aplicar rede
make lab-build    # constrói imagem, sem executar teste
```

A configuração fica em `.local/linux-lab/` (diretório 0700, ignorado). Duas CAs exclusivas: server CA e client CA. Apenas a client CA dedicada a este vínculo é confiada pelo servidor; certificado de servidor não autentica cliente. TLS verifica cadeia, EKU e SAN do IP fixo. Sem verify=false, proxy ambiente, redirects ou URL recebida de API.

As chaves folha precisam ser legíveis pelo UID10001 ao serem montadas individualmente; usam 0444 dentro do diretório host 0700, que impede acesso de outros usuários ao caminho. Chaves privadas das CAs usam 0600 e ficam fora dos containers. Folhas expiram em 2 dias, CAs em 7; PKI de desenvolvimento, sem rotação automática. `lab-init` recusa sobrescrever configuração existente. Preserve IDs e planeje renovação offline; não apague diário para contornar fences.

## Ensaio após autorização específica

Revise o Compose e conflitos de sub-rede antes de iniciar. Não executar estas etapas em infraestrutura empresarial ou em outro host sem aprovação.

```bash
make lab-up
make lab-inspect    # verifica controles reais do container por docker inspect
make lab-preflight  # conexão mTLS/identidade; ainda sem efeito
make lab-smoke      # cria/confere/remove um único marcador benigno
make lab-down      # para/remove containers/rede próprios; preserva volume do diário
```

O controller imprime UUID do job antes de enviar preparação; depois imprime comprovante, hash, estado de cleanup e classificação conservadora. Pode salvar stdout em `.local/` para inspeção, sem publicar dados reais. Caso a rede caia, **não crie outro job para tentar novamente**: consulte o UUID original.

```bash
docker compose --env-file .local/linux-lab/ids.env -f labs/linux/compose.yml run --rm --no-deps controller inspect --job-id UUID
docker compose --env-file .local/linux-lab/ids.env -f labs/linux/compose.yml run --rm --no-deps controller cleanup --job-id UUID
```

Para verificar retry de uma execução concluída e limpa, use o mesmo comando com `controller retry-check --job-id UUID`; ele recusa jobs pendentes/ativos e exige recibo histórico inalterado.

Cleanup explícito só após término confirmado. Arquivos desconhecidos exigem inspeção manual do container/volume, preservando o diário e sem exclusão recursiva automática. Não disponibilizar essas ferramentas a usuários de API como shell.

## O que foi e o que falta validar

Testes de software usam diretórios pytest descartáveis e processos fixos, além de fixture bloqueante exclusiva de testes para timeout/cancelamento. Transporte testa handshake TLS real em loopback, recusa cliente sem certificado/incorreto e servidor não confiável; testes ASGI separados verificam mensagens/limites. Isso não substitui o ensaio Docker autorizado.

Estado efetivamente observado do build, testes, ensaio e autorização: [PROGRESS](../../docs/PROGRESS.md). O segundo incremento abaixo entregou registro/revisão/preflight, aprovação separada, comprovantes PostgreSQL/UI, recuperação verificada e separação de métricas. Wazuh requer configuração e validação próprias.

## Resultado observado em 2026-10-21

Ensaio autorizado: mTLS e identidade confirmados; marcador de 43 bytes criado/verificado/removido; SUCCEEDED+CLEANED com comprovante de execução; validação INCONCLUSIVE porque SIEM não consultado. Restart+retry preservaram o recibo original, workspace vazio e um único início no diário. Containers/rede removidos no finally; volume preservado. A correção posterior da race de publicação terminal/cleanup foi validada por regressão determinística, e a imagem final reconstruída. Esse ensaio não representa uma campanha Linux já integrada à aplicação.

## Integração com campanhas — segundo incremento

Código integrado pela mesma API/fila/worker do Demo; opt-in por `LINUX_RUNNER_CONFIG` apontando para JSON `RunnerConnection`. A API não aceita endpoint, comando, caminho ou script do usuário. Registro administrativo deriva IDs e certificados dessa configuração; revisão de isolamento, preflight mTLS de 5 minutos e autorização precedem a criação da campanha. Apenas `linux-file-marker-v1` é compatível. Um administrador **diferente do solicitante** confirma efeito real em cada aprovação. Agendamento Linux não é suportado.

Recibos e cleanup são registros imutáveis próprios no PostgreSQL, inspecionáveis na execução/relatório. Não são alertas defensivos. Sem SIEM, classificação **INCONCLUSIVE**, com `synthetic=false`. Overview permanece explicitamente Demo; cobertura e matriz permitem escolher modo.

### Escopo concreto do novo ensaio integrado

**Requer aprovação específica antes do primeiro up/smoke.** O ensaio standalone anterior não autoriza este fluxo novo.

Projeto separado `aegis-linux-lab`, preservando a aplicação Demo existente. Serviços próprios `db`, `redis`, `migrate`, `api`, `worker`, `runner`; API publicada somente em `127.0.0.1:18785`. Volume PostgreSQL próprio, diário/IDs/PKI Linux originais preservados. Rede de runner `172.30.88.0/29` isolated interna; somente API e worker desse projeto recebem acesso mTLS a ela. Backend interno e ingress próprios para HTTP local. Sem host network, Docker socket, diretórios de dados host ou Wazuh (variáveis explicitamente vazias).

O script cadastra duas contas temporárias aleatórias (admin e operador), revisa/cadastra o binding, faz preflight sem efeito, autoriza o Linux Lab, solicita campanha pelo operador e aprova pelo administrador. O worker cria/verifica/remove **um marcador de 43 bytes** em tmpfs, filho limitado a **5 segundos**, lease de 2 segundos. Script verifica recibo/cleanup, resultado inconclusivo sem telemetria inventada, segregação de indicadores e relatórios HTML/JSON. Ao final revoga a autorização e desativa ambas as contas. `down` encerra somente os serviços/redes deste projeto, preservando volumes e evidência local ignorada `.local/linux-lab/platform-assay.json`.

```bash
make linux-platform-config  # valida sem iniciar
make linux-platform-build   # compila sem ensaio
# Somente após aprovação específica do escopo acima:
make linux-platform-up
make linux-platform-smoke
make linux-platform-down    # executar também se smoke falhar; não usar -v
```

O overlay usa `!override` para substituir a porta 18780 por 18785, requer Compose 2.24.4+ conforme [documentação oficial de merge](https://docs.docker.com/reference/compose-file/merge/). Não executar `lab-up` standalone simultaneamente: compartilham identidade, rede e diário. Não usar volumes de outro projeto. O ensaio integrado ainda deve ser confirmado por evidência de runtime no PROGRESS; config/build e fixtures não bastam para declará-lo executado.

### Recuperação e rotação

Após crash real, `CLEANUP_FAILED` mantém reserva. Administrador usa a ação de recuperação para consultar/cancelar/limpar somente o UUID/spec/geração originais; nunca prepara ou inicia outro job. `404` remoto após RPC ambígua **não** autoriza liberação. Sem dispatch persistido, nenhum RPC foi permitido. Resposta perdida de cleanup pode ser confirmada por consulta e cleanup idempotente; journal deve ser preservado para recusar start atrasado.

Se identidade, endpoint ou certificados do binding mudaram/expiraram, recuperação automatizada recusa a configuração nova. Mantenha a quarentena e planeje inspeção/cleanup do runner original sob escopo próprio, documentando a intervenção; não restaure confiança antiga para contornar bloqueios, apague journal ou altere reserva manualmente. Reiniciar/renovar certificado não concede nova autorização de execução.

Resultado do ensaio integrado: uma campanha COMPLETED, marcador de 43 bytes, cleanup CLEANED e workspace vazio, INCONCLUSIVE sem eventos/alertas defensivos. Captura opcional falhou inicialmente por esperar pouco o login; corrigida e validada por consulta do histórico, sem outro efeito. Banco confirmou uma única campanha real. Admin, operador e visualizador temporário foram desativados; laboratório revogado/sem reserva; containers/redes encerrados e volumes preservados. Comando de captura não foi apresentado como execução integral com exit 0; passos de negócio, persistência e UI têm verificações separadas registradas no PROGRESS.

[Preparação PKI offline](../../docs/operations/runner-pki.md) disponível: inspect,
prepare e verify criam um candidato separado com novos pares, preservando IDs.
Não leem chaves/diário originais nem ativam a troca. Certificados candidatos têm
validade curta e precisam ser reverificados antes de qualquer uso. Ativação
coordenada, novo binding/preflight e recuperação sob vínculo alterado continuam
pendentes e exigem escopo próprio; os ensaios anteriores não os autorizam.

Administradores podem consultar [pendências do vínculo](../../docs/operations/linux-binding-review.md)
na API/UI antes de preparar a troca. Registro Linux e bind/unbind Wazuh também
verificam pais/filhos pendentes e cleanup íntegro, além da reserva. Solicitação
pendente precisa de cancelamento explícito antes da revisão, preservando scopes.
O [plano coordenado](../../docs/operations/runner-pki-activation.md) ainda depende
de harness e autorização específica; consulta positiva não prova o diário real.

[Diagnóstico único dos volumes preservados](DIAGNOSTIC.md): planejamento/recheck de metadados e executor opt-in, com novo escopo autorizado antes de qualquer startup original. Preparação não autoriza execução.

[Ensaio de identidade mTLS](IDENTITY.md): coordenador interno sem banco/diário/
marcador, com evidências persistidas e cleanup por ownership. CLI/escopo final e
ensaio nativo ainda pendentes; documentação ou fixtures não autorizam execução.
