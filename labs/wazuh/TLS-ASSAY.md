# Ensaio de renovação TLS Wazuh — #6/#57

**Estado em12/11/2026: preparado documentalmente, bloqueado, não executado e não
implantado.** A #55 e a #56 entregaram somente inventário/candidato e procedimento
offline. A #57 e o pai #6 permanecem abertos. O [ensaio de22/10](ASSAY.md) está
encerrado e sua autorização não pode ser reutilizada.

## Bloqueios comprovados antes de pedir startup

- Dependência #149 aberta. `wazuh_lab.network_gate()` consultou somente metadados
  do daemon local e recusou conflito das sub-redes atuais com rede existente.
  Não criou/removeu redes nem alterou qasrc. Resolver a dependência é outro escopo;
  ela não é uma subissue da #6. Após sua aceitação, revisar perfil/SAN/destinos,
  inspeção independente e fixtures antes de gerar candidato/plano novos.
- `scripts/wazuh_host_preflight.py` retornou exit1:16CPUs, MemAvailable
  **6.495.100.928 bytes (~6,05GiB)**, espaço Docker415.473.455.104bytes,
  vm.max_map_count1048576. São necessários8GiB MemAvailable; swap não conta.
  Leitura pontual, não reserva. Não parar outros projetos nem mudar sysctl.
- Não existe autorização específica para abrir esses volumes e iniciar estes
  serviços nesta retomada. A ordem genérica de implementar a issue não é essa
  autorização, conforme o corpo da #57 e AGENTS.md.

Não gerar candidato real que expire durante o bloqueio, abrir/migrar volumes ou
iniciar serviços para completar um formulário. Arquivos públicos da PKI antiga
foram inventariados sem leitura de chaves: folhas expiradas23/10 e CA28/10.
Resultados antigos e fixtures não provam TLS renovado no laboratório.

## Escopo a apresentar para autorização depois dos gates

Um único ensaio de startup/leitura/TLS, projeto exato `aegis-wazuh-lab`, sem
simulação ofensiva. Antes da solicitação, anexar privadamente IDs atuais,
labels/volumes/redes/mounts, imagens reais/digests e hashes do candidato/plano;
verificar que correspondem ao perfil pós-#149 e ao código disponível. Nenhum
placeholder de ID/hash deste documento concede permissão.

| Recurso/efeito proposto | Limite |
|---|---|
| Indexer | Wazuh4.14.9/linux/amd64, digest de `images.json`,3GiB/2CPUs; mesmo volume `indexer-data`; novo par/CA somente por mounts individuais RO |
| Manager/Filebeat | Digest fixado,2GiB/1,5CPU; preservar etc/logs/queue e credenciais; conexão `full` ao Indexer; API de gestão somente no loopback interno |
| Agente001/aegis-marker | Digest fixado,256MiB/0,5CPU; preservar client.keys/queue e log dedicado RO, sem enrollment novo |
| Leitor de verificação | Aprovar previamente imagem/ID, receita fixa, usuário, rede/namespace, mounts e limites; somente CA pública, política e reader; sem socket Docker, shell remoto ou chave de serviços |
| Operador no host | Consultas locais limitadas de ps/inspect e exec de verificação do manager/Filebeat/agente; sem imprimir ambiente/segredos |

Não iniciar runner, observador, API, worker, banco, Redis ou migração para este
ensaio. Não executar targets `assay`, `check-rule`, smoke ou campanha; nenhum
marcador, payload sintético, regra nova, documento fictício ou atualização de
catálogo. Se a verificação exigir outro serviço, receita ou imagem, parar e revisar
explicitamente o pacote antes de ampliar o startup. Sem pull/build/compra/instalação
ou alteração de portas/rede/sysctl por este escopo.

Subir serviços pode escrever logs/estado normais e reprocessar backlog real do
manager/Filebeat, mesmo sem marcador. Isso faz parte do efeito a aprovar sobre os
volumes identificados; não truncar logs/filas para obter um resultado conveniente.
Não atribuir alertas antigos/de startup a detecção de um teste novo.

## Sequência e observações de aceite

Aplicar apenas a [ordem coordenada](../../docs/operations/wazuh-pki-rotation.md),
registrando INTENT antes de cada efeito e observação real depois. Verificar antes
**e depois** de cada recriação os IDs/mounts/portas/limites/consumidores. Não usar
`make wazuh-lab-up`, que inicia mais serviços. Exigir gates reais atuais em vez de
sleeps presumidos ou JSON de fixture. Janela máxima proposta:15min, espera por
etapa até60s, timeout de request3s; qualquer limite atingido encerra a tentativa,
retém evidências e inicia reconciliação/cleanup, sem novo start automático.

1. **Indexer:** cadeia nova exclusiva, certificado observado/fingerprint igual ao
   candidato, DNS/SNI/IP/SAN e DN do nó corretos; versão de imagem/digest real4.14.9.
   A resposta HTTP7.10.2 de compatibilidade não é a versão do manager.
2. **Filebeat:** execução restrita de `filebeat test output`, conexão TLS efetiva
   com verificação `full`, destino/CA esperados, sem proxies ambientais ou fallback
   para trust antigo. Registrar somente versão TLS, identidade e resultado redigido.
3. **Agente:** `agent_control -i 001 -j` no manager e estado de conexão observado
   no agente exato;001/aegis-marker Active e identidade pré-provisionada preservada.
   É canal seguro AES, não apresentar isso como handshake X.509 do agente.
4. **Coletor:** usar o conector existente com CA/SNI e IP fixado, principal
   `aegis_reader`, GET de conexão e busca limitada no índice autorizado
   `wazuh-alerts-4.x-*`. Capturar só metadados/contagens necessários, sem registrar
   payloads de alertas no relatório público. Não criar binding, conta ou execução.
5. **ACL:** comprovar principal/roles reais e leitura restrita; negar leitura do
   índice de segurança. Não enviar requisição de escrita nem usar admin no
   coletor. Consultar privilégios por mecanismo de leitura permitido; se não for
   possível provar restrição de escrita sem efeito, registrar esse item inconclusivo
   e pedir revisão específica, sem inventar403. Bulk HTTP200 pode conter item403;
   resultados históricos não substituem a observação desta tentativa.
6. **Cleanup:** parar os consumidores iniciados, comprovar ausência de atividade
   e preservar volumes, configurações antigas, credenciais, logs, journals/fences,
   candidato/plano/diário e relatório. Rollback seleciona os caminhos originais com
   serviços parados; não tentar operar com os certificados antigos expirados.

Erro ou resposta ambígua impede aceite. Não repetir efeitos, remover volumes,
recriar identidades, desativar TLS ou misturar CAs para obter sucesso. Cleanup não
pode depender de recursos suficientes para novo startup. Falha/ambiguidade retém
quarentena e acesso à recuperação; a #57 fica aberta até reconciliação comprovada.

## Evidências já disponíveis e limite

Na fonte `0b65f70`,132testes locais passaram: certificados reais em temporários,
SAN/cadeia/permissões/drift, lifecycle/rollback por fixture, Compose renderizado
sem startup e TLS real de echo em loopback aceitando o novo par e recusando
CA/cliente antigos, hostname incorreto e ausência de cliente. Ruff completo,
format/mypy e checks staged/release passaram. Aviso Starlette/httpx conhecido.

Nada disso é um ensaio Wazuh nativo. O teste de echo exige mTLS como fixture de
pares/trust; não afirma que o HTTP do Indexer exija certificado de cliente nessa
configuração. Nenhum alerta, marcador, resultado DETECTED ou alegação de eficácia
é produzido por esta entrega. O relatório final real deve registrar aprovação,
hashes/IDs, horários, observações, falhas e cleanup antes do fechamento da #57/#6.
