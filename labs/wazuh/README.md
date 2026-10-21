# Preparação Wazuh — sem instalação automática

**Estado:** integração de coleta implementada e testada com fixtures locais. Nenhum Wazuh foi instalado, iniciado ou consultado nesta etapa. O usuário informou não ter Wazuh e pediu somente a preparação. XML, configuração e observador abaixo não constituem validação externa; precisam de ambiente próprio e autorização específica antes de qualquer ensaio.

## Contrato e configuração

`collection.example.json` contém IDs **fictícios**, não destinos autorizados. Copie para local ignorado, substitua IDs por Laboratory/Asset reais cadastrados e agent.id por agente inequivocamente pertencente a esse laboratório. `000` é manager, não endpoint. URL/IP/credenciais/CA ficam no ambiente de implantação, não no arquivo de política nem na API. Não envie segredos pelo navegador ou chat.

- `WAZUH_URL`: origem HTTPS do Indexer; Server API de gestão não é usada para pesquisar eventos.
- `WAZUH_ALLOWED_IP`: IP autorizado fixado; DNS rebinding, redirects, proxies ambiente, loopback/link-local são recusados.
- `WAZUH_USERNAME`/`WAZUH_PASSWORD`: conta com leitura restrita aos índices revisados, search e scroll/clear. Não usar conta admin do Wazuh.
- `WAZUH_CA_BUNDLE`: CA privada montada read-only; verificação TLS nunca é desabilitada.
- `WAZUH_COLLECTION_CONFIG`: caminho do JSON de política montado read-only. Sem ele e sem binding administrativo, worker não consulta Wazuh.

Política fixa agent.id externo → Asset.id interno, laboratório, regra esperada, índices, prefixo de campos e timestamp. Payload original preserva agent.id. O prefixo padrão é data.aegis; outra instrumentação precisa fornecer o schema configurado. Nenhum campo de identidade ausente é inferido a partir da consulta.

Janela temporal e espera padrão: 10s; espera precisa cobrir toda a janela antes de concluir ausência de alerta. Até 64 rodadas, 25 páginas por índice/rodada, 200 hits por página, 5.000 documentos únicos na coleta, 8 MB por resposta/16 MB acumulados e timeout total por request de até 5s. Corpo comprimido é recusado. Reserva de 5s para cleanup; orçamento insuficiente torna resultado INCONCLUSIVE. Timeout total inclui headers, TLS e corpo lento; cancelamento é verificado entre requisições/chunks/esperas. Cursores conhecidos têm tentativa limitada de clear; respostas perdidas podem deixar cursor expirar em 1 minuto.

## Fluxo administrativo futuro

1. Preparar Wazuh próprio/isolado e revisar agente, TLS, permissões, instrumentação e índices. Isso **não foi realizado** nesta entrega.
2. Disponibilizar variáveis/arquivos ao runtime. `infra/compose.wazuh.example.yml` é somente referência de montagem; não inicia Wazuh nem pertence ao make up padrão.
3. Cadastrar Linux Lab/Asset pelo fluxo existente; manter laboratório revogado e sem reserva.
4. Abrir Laboratórios → Revisar coleta Wazuh, conferir política pública e registrar a revisão. Isso não consulta o SIEM.
5. Renovar preflight mTLS do runner e autorizar laboratório; solicitar campanha por operador, aprovar como outro administrador e conferir escopo/hash, agent.id, regra e limites.
6. Somente após autorização específica do ensaio, executar um marcador. Worker consulta Indexer, persiste eventos e resumo imutável da coleta; veja tentativas, disponibilidade e janela. Recibo/cleanup não são alertas.
7. Conferir evidências, relatório e cleanup; revogar escopo e encerrar infraestrutura própria conforme plano aprovado.

Revisar/remover binding exige laboratório revogado/sem reserva e aumenta versão do ambiente. Alterar agente/regra/índices/destino/CA/principal/janelas invalida escopo anterior. Rotação de senha mantendo a mesma conta não publica hash de segredo nem muda destino aprovado. A lógica aprovada é versionada; upgrade incompatível exige nova solicitação, sem executar silenciosamente lógica diferente.

## Observação passiva do marcador

`python -m aegis.marker_observer` somente lê proof.marker real, com 43 bytes, UUID e hash verificados, dentro do workspace privado do runner. Aceita diretórios físicos UUID.hex produzidos por Workspace; emite execution_id em UUID canônico. Recusa symlinks, hardlinks, FIFO, arquivo estranho, tamanho/conteúdo inválido; não cria, remove ou executa o marcador. Saída JSON descreve marker_file_read e não contém rule.id, sucesso de execução ou alegação de detecção.

Em laboratório futuro revisado, o observador precisa ter acesso read-only ao **mesmo workspace físico** do runner e sua saída deve chegar a um logfile dedicado lido pelo agente. O tmpfs privado atual do runner não é automaticamente compartilhado. Montagens/UID, retenção, rotação do log e ciclo de vida do observador precisam ser desenhados e autorizados no ambiente real; não montar Docker socket nem liberar acesso ao host para facilitar isso. Nenhum sidecar, agente ou processo observador é iniciado por make up/test/CI.

Exemplo de comando futuro (somente em ambiente/paths revisados):

```bash
python -m aegis.marker_observer --workspace /work --laboratory-id UUID_DO_LAB --asset-id UUID_DO_ATIVO
```

O agente pode coletar JSON usando o exemplo localfile, e o manager pode ter a regra de pipeline exemplificada. **Não copie receipt.json para logs como se fosse observação defensiva.** A regra de nível 3 existe apenas para validar o transporte/correlação desse marcador; não demonstra eficácia contra ataques, não representa uma técnica ATT&CK e não é uma regra Sigma convertida. Checar conflito do ID 100200 e validar com wazuh-logtest antes de instalar manualmente qualquer regra. XML foi validado estruturalmente, não no engine Wazuh.

## Archives e conclusões

Alertas são indexados pelo fluxo próprio do Wazuh; archives exigem configuração/indexação explícitas no manager e Filebeat. Não presumir que existem ou ativá-los automaticamente: volume de logs, retenção e privacidade precisam de revisão. Sem archives, um alerta esperado correlacionado ainda confirma a detecção desse teste; ausência de alerta fornece apenas ausência de evidência de telemetria, não falha de controle confirmada.

DETECTED exige execução confirmada + alerta correlacionado da regra aprovada. Observação com consulta final completa e janela cumprida, sem regra esperada, pode resultar em OBSERVED_NOT_ALERTED. Índice inexistente, zero shards, 403, timeout, truncamento, conflito de documento ou janela incompleta => INCONCLUSIVE. Eventual alerta posterior ao limite aprovado não está coberto; repetir a coleta/teste exige fluxo próprio aprovado, sem alterar evidências históricas.

## Fontes oficiais e validação local

[Indexer](https://documentation.wazuh.com/current/user-manual/indexer-api/reference.html), [archives](https://documentation.wazuh.com/current/user-manual/manager/event-logging.html), [JSON decoder](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html), [regras](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html), [HTTPX async](https://www.python-httpx.org/async/), [timeout integral Python](https://docs.python.org/3.13/library/asyncio-task.html#asyncio.timeout).

`make test-wazuh` usa fixtures, HTTP local de teste e PostgreSQL descartável; não instala Wazuh nem inicia laboratório real. Consulte PROGRESS para checks executados e limitações.
