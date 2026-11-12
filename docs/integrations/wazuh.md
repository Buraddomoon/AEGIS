# Wazuh Indexer — coleta aprovada e pipeline local validado

Renovação de serviços (#6): [inventário/candidato offline](../operations/wazuh-pki.md)
e [troca/rollback coordenados](../operations/wazuh-pki-rotation.md). Não renovam a
PKI do runner nem autorizam startup. A #149 preparou o perfil ADR0034 e recusas
de rede/SAN antigos. O [ensaio TLS sem marcador](../../labs/wazuh/TLS-ASSAY.md)
(#57) aguarda recursos/autorização e é separado do resultado histórico abaixo.

**Estado real:** em 2026-10-22 foi concluído o único ensaio Wazuh próprio autorizado: uma campanha, um marcador real de 43 bytes, um alerta original 100200, COMPLETED/DETECTED/CLEANED com synthetic=false. [Evidências e limites](../evidence/wazuh-2026-10-22/README.md). Sem associação ATT&CK, archives ou alegação de eficácia de EDR.

O [ensaio próprio](../../labs/wazuh/ASSAY.md) usou imagens oficiais4.14.9 fixadas,
PKI própria, TLS 1.3, agente 001 Active, regra validada em sandbox, mounts efetivos,
contas de leitura/ingestão separadas e negativas de ACL. Preflight passou com
8,78 GiB disponíveis. Laboratório revogado, contas desativadas, containers/redes
encerrados; volumes/diário preservados. A autorização foi consumida.

No runtime foi necessário acrescentar `indices:data/write/bulk*` no nível cluster
do perfil de ingestão, mantendo documentos limitados aos índices de alertas.
Aplicação continuou reader; create-index e acesso ao índice de segurança retornaram
403. Bulk de ingestão fora dos alertas retornou HTTP200 com item403, conferido
explicitamente. Templates/pipelines são privilégios de bootstrap globais do perfil
de ingestão, não da aplicação; não afirmar restrição total a um índice em toda
operação administrativa. A REST Security API foi habilitada somente para aegis_admin.

A API raiz respondeu versão 7.10.2 por `compatibility.override_main_response_version`
do Indexer. Isso não é a versão do Wazuh manager; as imagens verificadas são 4.14.9.

O fluxo usa Indexer Search/Scroll para alertas e archives opcionais; Server API administra agentes e não substitui busca de eventos. TLS verifica CA e hostname original com SNI; destino é IP fixado na implantação, sem DNS rebinding/proxy ambiente/redirect, URL ou credencial recebidos pela API. HTTPX AsyncClient é usado por facade síncrona com asyncio.Runner privado e timeout integral de conexão/headers/corpo; sem threads de requests abandonadas. Compressão recusada e limites de bytes/documentos/páginas/rodadas protegem memória/tempo.

`WAZUH_COLLECTION_CONFIG` fixa schema, índices, laboratório, Asset.id, agent.id externo, regra e janelas. Binding administrativo em Linux Lab revogado/sem reserva é obrigatório; variáveis de ambiente sozinhas não ativam coleta. Escopo/hash inclui política, destino, IP, CA e fingerprint do principal, nunca senha/token. Worker revalida binding/versão antes dos efeitos e queries. Senha pode ser renovada para o mesmo principal sem divulgar hash de segredo; alteração de identidade/destino exige revisão.

Normalização traduz somente agent.id **exatamente igual** ao mapping; até um valor que coincida com UUID interno é rejeitado se não for o agente externo aprovado. Campos ausentes/errados nunca são preenchidos com contexto solicitado. Preservados `_index`, `_id`, `_source`, timestamps e rule.id; conflitos de conteúdo por mesmo documento não são reutilizados como evidência.

Polling aguarda ingestão e exige espera que cubra a janela temporal para uma conclusão negativa. Guarda espaço para cleanup e verifica cancelamento entre requests/chunks/esperas. Rodada final completa/janela cumprida são necessárias para ausência de alerta; shards zero/falhos, índice inexistente, truncamento, 403, timeout ou orçamento insuficiente => INCONCLUSIVE. Um alerta esperado correlacionado pode confirmar resultado positivo antes da janela fechar. Um alerta de regra diferente, mas com identidade/comportamento correlacionados, é observação, sem afirmar detecção da regra esperada. Lógica versionada 1.1; aprovações de lógica antiga são rejeitadas, sem replay.

`TelemetryCollection` é append-only: provedor/hash/schema, período, tentativas, disponibilidade, completude, janela e motivo público. Recibo do executor e cleanup continuam tabelas próprias, separados de eventos/evidência defensiva. Relatório distingue SIEM não consultado de consulta tentada/indisponível, sem extrapolar resultado para risco de negócio.

[Instalação, política, observador e XML](../../labs/wazuh/README.md). Observador não inicia automaticamente; no ensaio teve acesso somente leitura ao workspace tmpfs do runner, log 0600 e agente root somente no logfileRO. A regra de instrumentação foi validada no engine real. Regras padrão que dependem de listas CDB omitidas pelo config mínimo emitiram avisos; não foi avaliada a cobertura desse ruleset. Archives precisam de configuração/indexação próprias; não os habilitamos automaticamente.

Fontes: [Wazuh Indexer](https://documentation.wazuh.com/current/user-manual/indexer-api/reference.html), [alertas](https://documentation.wazuh.com/current/user-manual/manager/alert-management.html), [archives](https://documentation.wazuh.com/current/user-manual/manager/event-logging.html), [SNI HTTPX](https://www.python-httpx.org/advanced/extensions/#sni_hostname), [HTTPX async](https://www.python-httpx.org/async/), [timeout Python](https://docs.python.org/3.13/library/asyncio-task.html#asyncio.timeout). Sem novas dependências; locks existentes preservados.
