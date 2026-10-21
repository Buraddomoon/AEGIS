# ADR 0003 — Runner Linux restrito antes de habilitar Lab Mode

Status: implementado e validado como runner independente; integração de campanhas entregue posteriormente no ADR 0004. Data: 2026-10-21.

O primeiro incremento Linux entrega um runner executável separado, protocolo tipado, adaptador cliente e implantação opt-in. O fluxo atual de campanhas continua Demo até validar o runner em laboratório autorizado e integrar sua autorização/identidade/persistência ao backend. Não expor um botão de Lab Mode operacional antes desse aceite.

Allowlist inicial: `linux-file-marker/v1`. Cria um arquivo de conteúdo limitado em diretório temporário exclusivo do job; sem técnica ATT&CK artificial, shell, comando livre, rede no processo filho, download ou scripts importados. Parâmetros: UUID do job/lab/ativo, identidade esperada do runner, marcador UUID, hash de escopo e prazo. Nenhum caminho ou comando recebido de API.

Runner em container próprio não root, filesystem raiz read-only, capacidades removidas, no-new-privileges, limite de memória/CPU/PIDs, rede interna dedicada em gateway mode isolated (Docker 28+), sem porta publicada nem endereço do host no bridge, sem socket Docker nem diretórios do host. Containers compartilham kernel; isso não substitui VM para testes futuros mais complexos. O programa fixo roda em subprocesso com sessão própria, limites Linux e ambiente mínimo; watchdog encerra o grupo e reap processo em timeout/cancelamento/perda de lease. SIGKILL abrupto do pai encerra o filho via Linux PDEATHSIG. Falha desconhecida nunca provoca replay automático.

Diário SQLite local do runner (stdlib) mantém idempotência e fencing de start por job, snapshot/hash, estados, resultado e cleanup. Um processo servidor e um efeito simultâneo; lock de processo impede múltiplos servidores no mesmo diário. Reinício marca efeitos interrompidos e mantém recuperação explícita. O PostgreSQL da plataforma permanece fonte de verdade das campanhas; o diário é recibo local e fence contra RPC repetida, não uma segunda fila de campanhas.

Autenticação por mTLS com CA local dedicada e validação obrigatória. O cliente só aceita endpoint HTTPS explicitamente configurado em implantação, IP literal privado fixo, sem proxy/redirect ou URLs recebidas pelo usuário. Preflight compara runner/lab/asset IDs, versão do protocolo e allowlist. TLS protege o transporte; identidade declarada não prova sozinha o isolamento Docker, que também exige revisão da configuração/inspect.

Contrato separa comprovante do executor de telemetria defensiva. Comprovante pode demonstrar execução e cleanup do marcador; não demonstra coleta por SIEM, alerta ou DETECTED. Sem configuração, cliente permanece desconectado; nenhuma conexão externa automática. Os testes locais de software usam diretórios pytest descartáveis e processos benignos fixos; o ensaio no container de laboratório exige autorização específica antes de iniciar.

Fontes oficiais consultadas:
- https://docs.python.org/3.13/library/subprocess.html — sessão de processo, timeout, reap e limites de preexec_fn em servidores com threads.
- https://docs.docker.com/engine/security/ — namespaces, cgroups e superfície do daemon.
- https://www.python-httpx.org/advanced/ssl/ — SSLContext, CA e certificado cliente.
- https://www.uvicorn.org/settings/ — TLS e client certificate verification; flags verificadas também no CLI instalado.

Não adicionamos dependências Python nem serviço pago. SQLite não é aberto a clientes remotos; dados e certificados não entram no Git. A aprovação do ensaio deve listar container/efeitos/duração/limpeza concretos, após código, testes e imagem estarem disponíveis para revisão.

Fontes adicionais verificadas durante a implementação: [PR_SET_PDEATHSIG](https://man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html), [sqlite3](https://docs.python.org/3.13/library/sqlite3.html), [gateway isolated](https://docs.docker.com/engine/network/port-publishing/), [OpenSSL req](https://docs.openssl.org/master/man1/openssl-req/) e [x509](https://docs.openssl.org/master/man1/openssl-x509/). Duas CAs distintas e exclusivas separam autenticação de servidor e cliente. Metadados do diário prendem a identidade para impedir rebind de volume. Publicação do terminal e liberação do efeito são serializadas para cleanup não observar transição parcial.
