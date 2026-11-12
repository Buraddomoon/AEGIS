# ADR0034 — Duas redes fixas Wazuh sem alterar qasrc

Data:2026-11-12. Estado: preparação offline autorizada da #149; startup proibido.
O usuário ampliou explicitamente a entrega #6 para incluir a dependência #149
somente offline. A #2/ADR0033 não muda as redes Wazuh antigas172.30.89/90.0/29,
ambas sobrepostas à qasrc172.30.0.0/16. Nenhuma delas será reutilizada/criada para
contornar o conflito; redes/volumes/PKI/journals/IDs antigos permanecem intactos.

Consultas somente leitura de redes Docker e rotas IPv4 de todas as tabelas em
12/11 encontraram duas faixas candidatas livres, separadas do Linux253.0/29:

| Capacidade | Subnet/gateway | Endereços fixos |
|---|---|---|
| Execução |192.168.253.8/29, gateway192.168.253.9 | runner.10, controller manual.11, API.12, worker.13 |
| Telemetria |192.168.253.16/29, gateway192.168.253.17 | Indexer.18, manager.19, agente.20, API.21, worker.22 |

As duas bridges continuam internas com gateway mode isolated, sem hostnetwork,
IPv6 ou portas SIEM publicadas. Runner/controller acessam só execução; os três
serviços Wazuh, só telemetria; observador sem rede. API/worker mantêm seus papéis
na plataforma e acessam ambas; somente API127.0.0.1:18786 fica publicada.
Não aceitar subnet, URL ou endpoint de entrada do usuário/API.

Definição central em `aegis.lab_runner.wazuh_network_profile` e overlay fixo
`labs/wazuh/network.yml`, sempre depois do Compose Wazuh e antes de um overlay
PKI. O Compose base legado conserva os endereços antigos para referência;
consumidores atuais precisam selecionar explicitamente o overlay e alinhar SAN,
destino permitido e inspeção (#151). Definição/renderização não permite startup.
Não editar .local/lab.env, certificados, binding ou histórico para simular migração.

Preflight `scripts/wazuh_network_preflight.py`: reutiliza leitores locais limitados
de Docker Unix e rotas, parse estrito e dois snapshots; cobre ambas as faixas,
colisões parciais/supernets/host routes, drift e indisponibilidade. Default route
não é colisão por si só; isso não demonstra reachability. Nem labels próprias
isentam uma rede que ocupe a faixa. Não remove/reconfigura terceiros. Executar
de novo imediatamente antes de qualquer criação futura; observação não reserva IP.
Cleanup deve continuar disponível quando o preflight de criação recusar o ambiente.

Novos materiais de preparação precisam do endpoint runner192.168.253.10 e
IndexerDNSwazuh.indexer/IP192.168.253.18; preservam agent.id001 e regra/índices.
A renovação PKI da #6 deve manter inventário histórico do SAN antigo, mas exigir
transição explícita/versionada para gerar o novo candidato, sem trocar manifests
antigos por rehash. A PKI do runner é separada da PKI dos serviços; este ADR não
renova, ativa ou liga nenhum dos dois. Ensaio TLS da #57 não inicia o runner.
