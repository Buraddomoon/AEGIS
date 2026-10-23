# Revisão do ciclo Demo recuperado — 2026-10-23

Escopo: ADR0013, bootstrap em clone reconciliado, permissões runtime, baseline
privada, probe/API/worker/Redis e fechamento/cleanup. Nenhuma interface web de
restauração nem parâmetros de destino/SQL/comando fornecidos pelo operador.

O clone passa primeiro pelo inventário, reconciliação e quarentena dos marcos
anteriores. Nova preparação exige recibo exato e fences vazios, catálogo Demo
revisado e schema/PG17 exatos, numa transação com locks em ordem fixa/NOWAIT.
Conta/lab/ativo/credenciais novos; nenhum grant ou identidade antiga reativado.

RUNTIME_PERMISSIONS extraído sem alterar as10instruções SQL anteriores. Mesmo
papel restrito da implantação normal: sem administração/ownership ou DELETE/
reescrita de evidências/auditoria. Baseline de hashes fora de public, sem USAGE
para runtime; comparação EXCEPT ALL exige todas as linhas antigas idênticas.
Estrutura public também comparada depois do ciclo. Não há migração nova.

API/worker e Redis novos só no namespace network=none do DB, sem publish/mount
persistente/socket Docker ou configuração de runner/SIEM. Imagens locais por ID,
limites de memória/CPU/PIDs, usuário10001, read-only/cap-drop/no-new-privileges.
Redis autenticado/loopback, config privada em tmpfs e save/AOF desligados. HBA
limita o SQL runtime por SCRAM, sem TCP administrativo. Senhas aleatórias em
env0600 somente durante create/stdin, não argv, intents ou recibos.

Probe fixa loopback e recusa outro DB/Redis/modo ou configurações Linux/Wazuh
antes de I/O. Payload limitado ao novo ID/senha. API faz autenticação, CSRF/RBAC,
autorização do lab, campanha, aprovação e fila normais. Worker real e adaptadores
Demo normais, sem mocks no ensaio Docker. Valida eventos/hashes, evidências,
quatro resultados sintéticos, indicadores e relatórios. Fechamento SQL exige
aprovação própria consumida, run única/4testes/regras de validação, nenhum dispatch
runner e zero autoridade/pendências/sessões; conta nova desativada.

Intenção antes de cada create, nomes/labels exatos inclusive em erro ambíguo,
cleanup worker→API→Redis→DB. Falha retém dependências/DB e impede recibo final;
nenhum prune/limpeza global. SIGKILL/daemon indisponível pode exigir revisão
manual. Docker/operador/imagens/dump precisam ser confiáveis; hash não é assinatura,
0700/0600 não é criptografia e o operador Docker pode inspecionar envs em execução.

Revisão especializada independente somente leitura não identificou bloqueador
concreto. Não executou testes, Docker ou acesso a .local. Testes locais usam DB/
role aleatórios próprios e Redis DB15 serial; simulam processamento da fila com
funções reais do worker. Mocks de Docker só para falhas de lifecycle e segredos.
[Ensaio separado com processos reais](../evidence/recovered-demo-2026-10-23/README.md)
confirma ciclo e remoção. Não confundir essas formas de validação.

Sem cutover, failover, nova autorização ofensiva real, recuperação entre hosts,
roles/secrets/Redis/PKI/journals originais ou RPO/RTO garantido. Nenhuma dependência
adicionada; advisory transitivo DiskCache revisado continua visível.
