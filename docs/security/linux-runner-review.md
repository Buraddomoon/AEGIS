# Revisão do runner Linux — 2026-10-21

Revisão especializada somente leitura, correções e testes locais. Não constitui pentest independente nem garantia de isolamento de código arbitrário.

| Achado/requisito | Tratamento e evidência |
|---|---|
| Resultado SUCCEEDED publicado antes da liberação de ownership podia recusar cleanup por race | Transição terminal e active=None sob mesmo lock após reap; regressão com barreira força intervalo |
| Motivo INTERRUPTED/CANCELLED sobrescrito por snapshot antigo no cleanup | Preservar motivo atualizado do journal |
| CA compartilhada aceitaria certificados de papéis diferentes | CAs dedicadas e distintas para servidor e cliente; TLS real rejeita cliente ausente/incorreto e CA servidor não confiável |
| Threaded server com preexec_fn seria inseguro | Nenhum preexec_fn; child instala PDEATHSIG, confere retorno e getppid; testes de pai inválido e SIGKILL com subreaper |
| SQLite bloqueado poderia atrasar timeout | Watchdog independente de transações; kill/reap antes de journal; teste com write lock ativo |
| Reinício/UUID repetido poderia duplicar efeito | Intenção durável antes de spawn, start fence, identidade presa ao journal, estado ambíguo INTERRUPTED sem replay |
| Cleanup poderia apagar arquivos alheios | UUID directory/0700, dir_fd, NOFOLLOW, nomes fixos, recusa symlink/hardlink/arquivo desconhecido; sem rmtree |
| Rede internal comum ainda permite gateway do host | Gateway mode isolated Docker 28+, sem endereço host no bridge; runtime inspect confirmou configuração, sem sondar alvos |
| YAML separava opções tmpfs por vírgula em itens inválidos | String entre aspas; teste de manifest e confirmação no Docker runtime |
| Resposta de prepare perdida/finish durante renew | Adapter conserva escopo para recuperação e consulta estado sem retry de start; testes de contrato |

Ensaio Docker autorizado confirmou um efeito benigno e cleanup, mTLS/identidade, inspeção de configuração e fence após reinício. O recibo é do executor e não sustenta detecção defensiva. Nenhuma conexão Wazuh ou campanha real na aplicação foi habilitada. Diário/PKI permanecem locais e ignorados; recursos de laboratório foram desligados.

Limitações: trust anchors e chaves de desenvolvimento locais, expiração curta/renovação offline; um runner/efeito por vez, quota de 10.000 jobs, sem retenção que elimine fences; containers compartilham kernel; supervisor não interrompe criação de processo bloqueada pelo kernel. O programa fixo não contém operações de rede nem aceita código arbitrário. Integração com aprovações/RBAC da plataforma, persistência de receipts no PostgreSQL e recuperação do worker ainda são requisito antes de campanhas Linux.
