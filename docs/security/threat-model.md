# Modelo de ameaças do MVP

Ativos: senhas/sessões, aprovações, identidade do laboratório, integridade de eventos/resultados, disponibilidade da fila e segredos de conectores. Fronteiras: browser/API, API/banco, worker/adaptador, Indexer externo e importação YAML.

| Ameaça | Controle implementado | Limite residual |
|---|---|---|
| Sequestro/força bruta de sessão | token opaco aleatório por hash, expiração, Argon2id, limites Redis e cookie HttpOnly/SameSite | Sem MFA; HTTP é somente loopback |
| CSRF/escalada de privilégio | header login não simples, origem exata, CSRF vinculado à sessão, RBAC backend | Workspace único, sem tenant/ABAC |
| Execução arbitrária | API não aceita comandos; único adapter habilitado é Demo | Adaptador real exige nova revisão e isolamento |
| SSRF/rebinding | destino somente ambiente administrativo, HTTPS, IP fixado, SNI/Host preservados, sem redirect/proxy ambiente | Conector externo não validado com infraestrutura real |
| Falso positivo de correlação | identidade completa, marcador, comportamento, regra e janela; indisponibilidade explícita | Instrumentação real precisa transportar marcadores confiáveis |
| Eventos adulterados | payload original/hash, role runtime append-only para evidências/auditoria | Dono/superuser do banco ainda pode alterar dados; sem assinatura externa |
| YAML hostil | 64 KiB, limite de eventos, SafeLoader, proibição de aliases/âncoras, pySigma | Importação não comprova semântica ou implantação |
| Corrida/duplicação | constraints, locks, claim SKIP LOCKED, fence de entrega, uso único de aprovação | Throughput não foi benchmarkado |
| Worker morto/cleanup falho | deadline, heartbeat, recuperação sintética sem replay, reserva retida em falha | Adaptadores bloqueantes reais precisam de limite em processo separado |

Não há shell, montagem de Docker socket, payloads ofensivos ou execução de Atomic. Segredos via ambiente, sem persistência em auditoria. Pacotes são travados com hashes; CI identifica novos avisos. O aviso DiskCache herdado é analisado em `dependency-advisories.json`, com teste do caminho de execução; ativar cache/plugins invalida a análise.

Antes de exposição externa: TLS e cookies Secure, proxy revisado, limites operacionais, gerenciamento/rotação de segredos, usuário de migração com menor privilégio, backups testados no ambiente, MFA/SSO se necessário e revisão independente. Esta versão não é declarada pronta para produção empresarial.
