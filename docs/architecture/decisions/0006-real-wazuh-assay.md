# ADR 0006 — Ensaio Wazuh próprio e opt-in

Status: preparação; execução real ainda não autorizada nem validada. Data: 2026-10-21.

## Contexto

O próximo critério é comprovar o caminho arquivo real → observador passivo → agente
Wazuh → manager/regra → Filebeat → Indexer → correlação AEGIS. Fixtures e recibos
do runner não comprovam esse caminho. O usuário pediu priorizar essa pendência,
mas anteriormente escolheu preparar **sem instalar**; instalação/início do SIEM e
um novo marcador dependem de autorização específica, conforme a instrução original.

## Decisões

- Preparar um projeto Docker separado `aegis-wazuh-lab`, sem reutilizar banco,
  identidade, diário ou volumes dos ensaios Linux encerrados. Nunca iniciar via
  `make up`, testes ou CI. Sem instalação no host, Docker socket, host network,
  mounts do sistema ou acesso a ambientes corporativos.
- Referência atual: imagens oficiais Wazuh **4.14.9**, sem `latest`. Conferir
  arquitetura, digests efetivamente baixados e licenças antes do ensaio. AEGIS
  continua MIT; Wazuh é software separado com licença própria GPLv2.
- Primeiro verificar recursos sem alterar o host: quatro CPUs, 8 GiB de memória
  **disponível** e 50 GiB livres no filesystem do Docker, `vm.max_map_count` de
  pelo menos 262144. O piso de memória disponível é uma margem operacional local,
  mais conservadora que o mínimo oficial de RAM total. Falha impede início; não
  parar serviços existentes, limpar caches, mexer em swap ou sysctl automaticamente.
- Preservar o runner limitado à allowlist `linux-file-marker/v1`. Compartilhar o
  mesmo workspace em volume tmpfs de 1 MiB: runner RW e observador RO, UID 10001,
  modo 0700. O observador escreve somente um logfile dedicado e limitado, que o
  agente lê RO. Nenhum recibo vira entrada defensiva. Reinício não deve fabricar
  observações; duplicatas são identificáveis pela execução e hash.
- Manager e Indexer só em redes internas próprias; nenhum endpoint Wazuh publicado
  no host. A aplicação recebe somente CA e credencial de leitura restrita aos
  índices aprovados. Credenciais administrativas/ingestão nunca entram no worker.
  Certificados e segredos aleatórios locais ignorados; sem defaults publicados.
- Não ativar archives no primeiro ensaio: um alerta esperado correlacionado pode
  comprovar o pipeline; ausência de alerta permanece limitada pela disponibilidade
  de telemetria. Desabilitar inventário, vulnerability feeds, rootcheck, FIM e
  active response desnecessários nesse laboratório dedicado.
- Validar a regra com `wazuh-logtest` **antes** do marcador; conferir agente real,
  isolamento, TLS e permissões de leitura antes de aprovar a campanha. Um único
  marcador de 43 bytes, filho limitado a 5s; sem recorrência ou ATT&CK artificial.
- Fechar somente após inspecionar documento original do Indexer, agent.id,
  rule.id, IDs de laboratório/ativo/execução, marcador, timestamp, hash, resumo de
  coleta, cleanup e relatório. DETECTED fica condicionado às evidências reais.
  Falha de captura visual não autoriza repetir o efeito.

## Situação do host e autorização

A inspeção inicial encontrou 16 CPUs, cerca de 5 GiB disponíveis, swap bastante
ocupada e `vm.max_map_count=1048576`. Disco do projeto tem espaço, mas isso não
substitui medir o filesystem usado pelo daemon Docker. Não iniciar um SIEM pesado
nessa condição sem satisfazer o preflight. Não há autorização para interromper
outros projetos para liberar RAM.

Após preparar/revisar os artefatos, solicitar somente o escopo concreto que falta.
Uma autorização não elimina o preflight nem permite ampliar alvos/efeitos. Até
então, documentação/manifests/testes são preparação, sem alegação de validação real.

## Fontes oficiais consultadas

- [Docker e requisitos Wazuh](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html)
- [Deploy oficial fixado em v4.14.9](https://github.com/wazuh/wazuh-docker/tree/v4.14.9)
- [Teste de regras](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html)
- [Volumes tmpfs Docker](https://docs.docker.com/engine/storage/volumes/#use-a-tmpfs-volume)

A documentação oficial pede host com pelo menos 4 CPUs, 8 GB de RAM, 50 GB de
armazenamento e `vm.max_map_count >= 262144`. Não reproduzir os defaults de senha
ou exemplos de TLS sem verificação presentes em alguns tutoriais.
