# Modelo de ameaças do MVP

Ativos: senhas/sessões, aprovações, identidade do laboratório, integridade de eventos/resultados, disponibilidade da fila e segredos de conectores. Fronteiras: browser/API, API/banco, worker/adaptador, Indexer externo e importação YAML.

| Ameaça | Controle implementado | Limite residual |
|---|---|---|
| Sequestro/força bruta de sessão | token opaco aleatório por hash, expiração, Argon2id, limites Redis e cookie HttpOnly/SameSite | Sem MFA; HTTP é somente loopback |
| CSRF/escalada de privilégio | header login não simples, origem exata, CSRF vinculado à sessão, RBAC backend | Workspace único, sem tenant/ABAC |
| Execução arbitrária | API não aceita comandos; padrão Demo, Linux opt-in admite somente programa fixo revisado | Não é sandbox para código arbitrário; novos testes exigem revisão/escopo |
| SSRF/rebinding | destino somente ambiente administrativo, HTTPS, IP fixado, SNI/Host preservados, sem redirect/proxy ambiente | Wazuh validado somente no laboratório4.14.9; não generalizar para outros ambientes |
| Falso positivo de correlação | identidade completa, marcador, comportamento, regra e janela; indisponibilidade explícita | Instrumentação real precisa transportar marcadores confiáveis |
| Eventos adulterados | payload original/hash, role runtime append-only para evidências/auditoria | Dono/superuser do banco ainda pode alterar dados; sem assinatura externa |
| YAML hostil | 64 KiB, limite de eventos, SafeLoader, proibição de aliases/âncoras, pySigma | Importação não comprova semântica ou implantação |
| Corrida/duplicação | constraints, locks, claim SKIP LOCKED, fence de entrega, uso único de aprovação | Throughput não foi benchmarkado |
| Worker morto/cleanup falho | deadline, heartbeat, recuperação sintética sem replay; Linux tem supervisor/lease/diário e reserva retida na ambiguidade | Kernel compartilhado; rotação PKI/binding e recuperação manual continuam limitadas |
| Vazamento da configuração local | Criação0600, owner/tipo/nlink/limite/lock conferidos; recusa de links e segredos vazios/exemplos | Usuário/root do host pode ler; acesso ao daemon Docker deve ser protegido |
| Perda/adulteração do backup | age/X25519 host-only, chave separada, autenticação integral/hash esperado, restore offline verificado | Chave/cópia ainda locais, sem assinatura do remetente; originais em claro e sem RPO/RTO |

Não há shell, montagem de Docker socket, payloads ofensivos ou execução de Atomic. Segredos via ambiente, sem persistência em auditoria. Pacotes são travados com hashes; CI identifica novos avisos. O aviso DiskCache herdado é analisado em `dependency-advisories.json`, com teste do caminho de execução; ativar cache/plugins invalida a análise.

Antes de exposição externa: TLS e cookies Secure, proxy revisado, limites operacionais, gerenciamento/rotação de segredos, usuário de migração com menor privilégio, backups testados no ambiente, MFA/SSO se necessário e revisão independente. Esta versão não é declarada pronta para produção empresarial.
