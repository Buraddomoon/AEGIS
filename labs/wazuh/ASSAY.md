# Ensaio integrado Wazuh — escopo autorizado e resultado

Para a entrega #6, seguir [inventário/candidato](../../docs/operations/wazuh-pki.md)
e [troca/rollback](../../docs/operations/wazuh-pki-rotation.md). São preparação
offline; o ADR0034 prepara redes novas e #57 exige escopo/aprovação próprios de TLS
sem marcador. O procedimento histórico abaixo não é autorização dessa renovação.
Ver [escopo TLS e bloqueios da #57](TLS-ASSAY.md) antes de qualquer retomada.

**Estado: executado e encerrado em 2026-10-22.** Campanha
`987bd48f-fafc-4a34-bf2a-2d310e7ca794`: uma execução, marcador43 bytes,
COMPLETED/DETECTED/CLEANED, synthetic=false, alerta original 100200 e uma evidência.
[Registro verificável e limites](../../docs/evidence/wazuh-2026-10-22/README.md).
Laboratório revogado, contas desativadas e senhas temporárias removidas;
containers/redes encerrados, volumes/journal preservados. **A autorização foi
consumida. Não repetir o marcador nem iniciar novamente o stack sem novo escopo.**

Em 2026-10-21 o usuário autorizou
**“Autorizar somente esse ensaio quando o preflight passar”**, respondendo ao escopo
integral abaixo. Essa autorização permitiu um único ensaio, sem repetição ou
ampliação, e não permite ignorar recursos insuficientes ou parar outros projetos.
Renderizar Compose e passar testes
locais não valida entrypoints, permissões efetivas, rules engine ou ingestão. O
usuário anteriormente escolheu **sem instalar**; a autorização específica posterior
permitiu os passos abaixo quando o preflight passou. O procedimento abaixo é
referência histórica/operacional, não autorização recorrente.

## Escopo proposto

Um projeto **aegis-wazuh-lab**, separado do Demo e dos ensaios Linux encerrados:

| Componente | Escopo e limite de memória |
|---|---|
| Wazuh Indexer | 4.14.9 oficial, linux/amd64, digest fixado; heap 1 GiB, container 3 GiB |
| Wazuh manager + Filebeat | 4.14.9 oficial, digest fixado; 2 GiB; regra local 100200 |
| Wazuh agent | 4.14.9 oficial, digest fixado; 256 MiB; somente log dedicado |
| Runner | imagem própria separada; UID 10001, read-only, 192 MiB, filho até 5s |
| Observador | mesma imagem própria; sem rede, workspace RO; 96 MiB |
| PostgreSQL / Redis | volumes e credenciais próprios; 384 / 128 MiB |
| API / worker / migração | imagem própria separada; 512 / 256 / 256 MiB |

O teto agregado é **7.03 GiB**, incluindo migração transitória; limites individuais
não reservam memória antecipadamente. Exigir **8 GiB MemAvailable**, 4 CPUs, 50 GiB
livres no armazenamento Docker e vm.max_map_count >= 262144. Não contar swap. Na
inspeção de preparação, a RAM disponível era cerca de **4–5 GiB**: início bloqueado.
Nenhum serviço de outro projeto será parado para liberar recursos. O preflight não
altera sysctl, swap, caches ou configuração Docker.

`images.json` fixa os três manifests linux/amd64 consultados no registro oficial,
sem baixar camadas nesta preparação. O download futuro pode consumir vários GB;
50 GiB livres é a margem de implantação, não uma medição do tamanho das imagens.
Builds da aplicação/runner podem consultar os registros de dependências já usados
pelo projeto. Nenhum serviço pago. Manager/agente têm licença GPLv2; Indexer tem
licença Apache-2.0 e dependências próprias. Não redistribuir imagens como código MIT.

Redes próprias: runner `172.30.89.0/29` e telemetria `172.30.90.0/29`, internas e
sem gateway host; conflito impede início. Runner só integra a primeira; agente,
manager e Indexer só integram a segunda. Observador sem rede. API/worker fazem a
ponte pelos contratos existentes. Backend/ingress seguem o Compose da plataforma;
somente a API publica **127.0.0.1:18786**. Não publicar 9200/1514/1515/55000, montar
socket Docker, usar host network, diretórios do host ou consultar alvos externos.
A rede ingress da API mantém o comportamento de bridge do projeto; não afirmar
isolamento físico total do host. Conferir mounts/rotas efetivos antes de aprovar.

O workspace é um volume tmpfs novo de 1 MiB, 0700/UID10001, noexec/nosuid/nodev.
Runner RW, observador RO, agente sem acesso ao workspace. Log dedicado em volume
próprio persistente, arquivo 0600, único escritor com flock, fsync por registro,
limite 1 MiB. Agente lê RO. Sem rotação destrutiva: atingir limite interrompe o
observador e exige revisão. Reinício recarrega identidades observadas; linha parcial,
links, conteúdo conflitante ou outro escopo bloqueiam reutilização. Não apagar o
log para mascarar falha. tmpfs não é evidência durável após desmontagem; log,
documento original e evidência na aplicação cumprem esse papel.

Agente `001/aegis-marker` é pré-provisionado somente nesse novo manager com chave
aleatória local. A identidade precisa aparecer **Active** no manager antes do
binding; o número gerado não é prova de inscrição/conexão. Enrollment, active
response, FIM, inventário e feeds desnecessários ficam desativados. API de gestão
fica em loopback **dentro** do manager e não participa da coleta. Sem archives no
primeiro ensaio: nenhum negativo comprovará ausência de telemetria em todo o Wazuh.

Credenciais e PKI ficam em `.local/wazuh-lab`, ignorado e 0700, sem reutilizar o
lab anterior. Folhas de desenvolvimento duram dois dias; conferir validade antes
do início. A CA privada não entra nos containers. AEGIS recebe somente CA pública,
política e **aegis_reader**; manager recebe **aegis_ingest**. Admin aleatório local
separado; nenhum segredo em relatório, auditoria, chat, argv ou saída de config.
O gerador de hashes usa a ferramenta da imagem oficial, sem rede, segredo via
stdin; três containers transitórios de até 256 MiB, em sequência.

## Preparação sem iniciar infraestrutura

```bash
make wazuh-lab-prepare       # recusa sobrescrever identidade existente
make wazuh-lab-config        # config --quiet, sem imprimir segredos
make wazuh-lab-preflight     # somente leitura; exit 1 se recursos insuficientes
make test-wazuh-preparation  # fixtures/arquivos locais, sem iniciar Wazuh
```

Não publicar `docker compose config` completo, inspect de Environment, arquivos
lab.env, client.keys, senhas ou chaves. O manifesto privado criado neste marco
ainda não possui hashes preparados no engine oficial: isso requer imagem baixada.

## Após autorização específica e preflight aprovado

```bash
make wazuh-lab-pull
make wazuh-lab-hash-users
make wazuh-lab-build
make wazuh-lab-up
make wazuh-lab-status
make wazuh-lab-inspect
make wazuh-lab-check-rule
```

Os flags de confirmação dos scripts evitam acidentes; não substituem autorização
humana. Lifecycle não executa marcador. Não executar o antigo linux-platform-smoke
contra este stack: ele tem outro projeto/objetivo e espera ausência de SIEM.

Antes de criar/aprovar qualquer efeito:

1. Inspecionar o **projeto exato**, limites, redes, nenhum endpoint SIEM publicado,
   mounts RO/RW, opções tmpfs reais, UID/caps, isolamento e ausência de Docker socket.
   Validar o isolamento não apenas pelo YAML. Imagens podem exigir ajustes que
   só serão conhecidos no runtime; não desabilitar TLS/controles para fazê-las subir.
   `make wazuh-lab-inspect` consulta somente ps/ls/inspect no daemon Unix local,
   filtra o projeto exato e compara os metadados efetivos com uma allowlist
   independente do Compose: membros/redes/IPs/portas, volumes/mounts, privilégios,
   usuários, limites, imagens fixadas, saúde e migração concluída. Recusa serviços
   extras, rede com outro container e volumes de outro projeto. Laboratório
   ausente ou divergente retorna exit1, sem iniciar/reparar nada. Não imprime
   Environment, credenciais, paths privados ou inspect completo. Ainda conferir
   dentro dos containers as opções de montagem e permissões do filesystem: a
   inspeção de metadados não demonstra isolamento do kernel, mTLS ou ingestão.
2. `check-rule` usa `wazuh-logtest -U 100200:3:json` com JSON **sintético de sandbox**,
   não gravado no log do agente nem no banco de evidências. Checar conflitos do ID e
   status Active do agente exato. Isso testa parsing/regra, não ingestão real.
3. Confirmar log vazio/observador saudável, logcollector acompanhando o caminho,
   relógios UTC, Filebeat conectado e índice de alertas disponível. Usar condições
   de prontidão e limites de espera, não sleeps presumidos.
   Conferir também API de gestão somente no loopback do container e rotacionar ou
   desativar usuários padrão desnecessários antes do ensaio; defaults da imagem não
   constituem a política de credenciais do laboratório.
4. Usar o conector da aplicação para comprovar CA/SNI, destino fixado e GET/search/
   scroll somente leitura; revisar permissões reais. Nunca passar credencial admin
   para API/worker. Confirmar que escrita e outros índices são recusados.
5. Criar contas temporárias aleatórias de administrador e operador, cadastrar novo
   Linux Lab/Asset, revisar binding ainda revogado, preflight mTLS e autorização.
   Política é derivada da identidade nova e agente verificado; janela/espera 60s,
   poll 2s, timeout de request 3s, somente índice de alertas.

Só então criar **uma campanha, uma execução e um teste linux-file-marker-v1**.
Operador solicita, administrador distinto aprova hash/efeito real por no máximo
**120s**, worker executa um marcador de **43 bytes**, filho até **5s**, coleta e
cleanup. Não alterar allowlist, conceder recorrência, acessar Wazuh corporativo,
outros endpoints ou habilitar comandos remotos. Persistir run ID e intenção local
antes de start; erro/timeout de resposta não autoriza criar outra execução.

`make wazuh-lab-assay` usa o harness `smoke_wazuh_platform.py` após essas revisões,
exclusivamente com autorização específica. Não inicia serviços. Cria uma intenção
privada append/fsync com O_EXCL antes de qualquer mutação, recusa banco com execução
prévia, registra runID e START_INTENT antes do único POSTstart e não repete respostas
ambíguas. Contas/senhas aleatórias passam por stdin ao container de migração, nunca
por argv ou ao processo API/worker. Captura relatório/detalhes antes de avaliar o
resultado, revoga laboratório e desativa contas; remove as senhas temporárias após
desativação confirmada. Ambiguidade/CLEANUP_FAILED mantém acesso para recuperação
do original e exige revisão antes do down. Intent existente impede novo ensaio;
não apagá-lo para contornar essa proteção. O ensaio registrado já consumiu esse uso.

## Critério de aceite e encerramento

- Preservar a linha do observador e documento **original** do Indexer com `_index`,
  `_id`, agent.id, rule.id, timestamp e data.aegis; conferir identidade completa,
  marcador/hash, relação temporal e regra 100200. Sem documento correspondente,
  não declarar DETECTED nem reconstruir payload com dados do receipt.
- Verificar resumo imutável da coleta, recibo de execução separado, workspace
  limpo, cleanup CLEANED, indicadores do modo Linux e relatórios HTML/JSON.
- DETECTED comprova **apenas o pipeline dessa regra de marcador**, não uma técnica
  ATT&CK, proteção empresarial ou eficácia de EDR. Preservar resultado inconclusivo
  se ingestão/coleta falhar. Não repetir efeito para corrigir screenshot.
- Revogar Lab, desativar contas temporárias e encerrar todos os containers/redes
  deste projeto com `make wazuh-lab-down`. Cleanup deve funcionar mesmo com pouca
  RAM. Preservar volumes próprios, diário/fences e evidências para revisão; não usar
  `down -v`, prune global ou apagar dados dos ensaios anteriores. Remoção definitiva
  desses dados requer revisão própria de retenção/backup.
- Se cleanup falhar ou estado for ambíguo: manter quarentena, preservar o diário e
  recuperar o job original conforme ADR0004, sem novo start. Encerramento não deve
  destruir o único acesso à recuperação antes de registrar o estado.

## Resultado observado e limites restantes

O ensaio confirmou entrypoints, hashes oficiais/roles, defaults API rejeitados,
listenerAPI127.0.0.1, tmpfsRW/RO/UID10001/0700, log 0600 lido pelo agente root,
163 verificações Docker, regra 100200 sandbox e agente 001 Active. Filebeat TLS 1.3,
reader Search/Scroll/Clear e negativas de escrita/acesso fora de escopo passaram.
O perfil ingest precisou de bulk no cluster; a alteração foi aplicada pelo admin
local e o bulk fora dos índices de alertas foi recusado por item403. Nenhum documento
fictício foi inserido no Indexer. Dois alertas reais de inicialização já existiam;
somente o alerta com identidade/marcador/hash/tempo/regra do teste virou evidência.

Persistidos um evento e uma evidência na aplicação, seis tentativas de coleta,
hashes conferidos contra recibo e observação independentes, workspace vazio,
aprovação distinta consumida de 120s, zero contas temporárias ativas e reserva liberada.
Archives ficaram desativados; o ruleset mínimo emitiu avisos por listas CDB não
habilitadas. Não demonstra cobertura de regras padrão, outras versões, Windows,
ATT&CK ou eficácia de EDR. Não houve nova rodada E2E de navegador ou screenshot
Wazuh. Consulte [ADR0006](../../docs/architecture/decisions/0006-real-wazuh-assay.md).
