# Linux Lab — runner restrito (incremento preparatório)

Runner e adaptador executáveis para **um marcador benigno**, separados da aplicação principal. Ainda não há campanha Linux no PostgreSQL/UI nem integração operacional com Wazuh. `make up` continua iniciando somente Demo; não há botão falso de execução real.

## Escopo concreto do ensaio

Projeto Compose `aegis-linux-lab`, imagem `aegis-linux-runner:local`, serviço `runner` e um `controller` temporário. Rede dedicada `172.30.88.0/29`, interna, com gateway mode **isolated** e sem portas publicadas. O bridge não recebe endereço do host. Nenhum container é conectado às redes da aplicação, da empresa ou de outros projetos; sem socket Docker, mounts do host ou host networking. Somente arquivos específicos de certificados/configuração são montados read-only como secrets; chaves de CA não são montadas.

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
make lab-preflight  # conexão mTLS/identidade; ainda sem efeito
make lab-smoke      # cria/confere/remove um único marcador benigno
make lab-down      # para/remove containers/rede próprios; preserva volume do diário
```

O controller imprime UUID do job antes de enviar preparação; depois imprime comprovante, hash, estado de cleanup e classificação conservadora. Pode salvar stdout em `.local/` para inspeção, sem publicar dados reais. Caso a rede caia, **não crie outro job para tentar novamente**: consulte o UUID original.

```bash
docker compose --env-file .local/linux-lab/ids.env -f labs/linux/compose.yml run --rm --no-deps controller inspect --job-id UUID
docker compose --env-file .local/linux-lab/ids.env -f labs/linux/compose.yml run --rm --no-deps controller cleanup --job-id UUID
```

Cleanup explícito só após término confirmado. Arquivos desconhecidos exigem inspeção manual do container/volume, preservando o diário e sem exclusão recursiva automática. Não disponibilizar essas ferramentas a usuários de API como shell.

## O que foi e o que falta validar

Testes de software usam diretórios pytest descartáveis e processos fixos, além de fixture bloqueante exclusiva de testes para timeout/cancelamento. Transporte testa handshake TLS real em loopback, recusa cliente sem certificado/incorreto e servidor não confiável; testes ASGI separados verificam mensagens/limites. Isso não substitui o ensaio Docker autorizado.

Estado efetivamente observado do build, testes, ensaio e autorização: [PROGRESS](../../docs/PROGRESS.md). Próximo incremento após aceite: registrar laboratório/ativo/revisão de isolamento na API, aprovação de escopo Linux por operação, receipts persistidos no PostgreSQL e UI, recuperação de worker real e separação explícita de métricas Demo/real. Só então habilitar campanhas Linux. Wazuh requer configuração e validação próprias.
