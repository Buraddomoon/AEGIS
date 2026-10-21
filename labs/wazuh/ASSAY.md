# Ensaio integrado Wazuh — escopo para revisão

**Estado: preparado, sem execução Wazuh real.** Em 2026-10-21 o usuário autorizou
**“Autorizar somente esse ensaio quando o preflight passar”**, respondendo ao escopo
integral abaixo. Essa autorização persiste para um único ensaio, sem repetição ou
ampliação, e não permite ignorar recursos insuficientes ou parar outros projetos.
Renderizar Compose e passar testes
locais não valida entrypoints, permissões efetivas, rules engine ou ingestão. O
usuário anteriormente escolheu **sem instalar**; a autorização específica posterior
permite os passos abaixo somente quando o preflight passar. Não pedir a mesma
autorização novamente sem mudança material de escopo.

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

## Critério de aceite e encerramento

- Preservar a linha do observador e documento **original** do Indexer com `_index`,
  `_id`, agent.id, rule.id, timestamp e data.aegis; conferir identidade completa,
  marcador/hash, relação temporal e regra100200. Sem documento correspondente,
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

## Pendências que só o ensaio pode resolver

Compatibilidade efetiva das imagens/entrypoints, bootstrap dos usuários/roles,
API interna loopback, permissões de arquivos copiadas pelo Wazuh, montagem tmpfs,
wazuh-logtest, agent Active, Filebeat, schema indexado, scroll/clear, negativa de
escrita, classificação e cleanup reais. Não listar esses itens como aprovados com
base em renderização, mocks ou fixtures. Consulte [ADR0006](../../docs/architecture/decisions/0006-real-wazuh-assay.md).
