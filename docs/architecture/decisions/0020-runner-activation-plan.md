# ADR 0020 — Plano verificável antes da ativação da PKI Linux

Data: 2026-10-27. Status: plan/recheck implementados; não autoriza ativação.

O candidato PKI e a revisão persistida são pré-requisitos distintos. Antes de
implementar um executor que inicie o laboratório, preparar uma ferramenta host-only
`runner_activation.py plan/recheck`. O primeiro perfil é exclusivamente o Linux
integrado `aegis-linux-lab`, IP172.30.88.2 e API loopback18785. Não aceitar projeto,
daemon, porta, serviço, comando ou destino de rede fornecidos livremente.

O plano fixa SHA do manifesto PKI, identidade antiga/nova, caminhos dos secrets,
hashes dos três Compose revisados e IDs de quatro imagens já presentes. Consultar
somente metadados do daemon Unix local: identidade Linux/arquitetura, ausência de
containers/redes do projeto, volumes existentes com labels/datas/driver/options
esperados e ausência de consumidores dos dois volumes. Volume ausente, ocupado,
externo ou ambíguo aborta; nunca criar substituto. Labels/datas não provam conteúdo.

Docker CLI absoluto, config temporária vazia, ambiente mínimo e catálogo fechado
de consultas, sem shell/Compose/configuração do usuário. Projeções não incluem
Config.Env, conteúdo/mountpoint do volume ou inspect bruto. Tempo e saída limitados.
Nenhum pull/build/create/start/exec/stop/rm e nenhuma conexão ao runner, banco ou SIEM.

Publicar artefato exclusivo0600 em diretório0700 com fsync e hash canônico. Recheck
exige hash revisado independente, formato/política exatos, no máximo15min de idade,
PKI ainda válida e todos os metadados/hashes atuais idênticos. Não confiar em recibo
antigo nem assumir que snapshot impede alterações concorrentes. Hash não é assinatura
e Docker/root/usuário local continuam fronteiras de confiança.

O plano mantém explicitamente falsos: autorização, ativação, journal/banco/mounts
verificados, proveniência das imagens e operação normal. Não recebe credenciais e
não concede aprovação ou prontidão operacional. O executor futuro deverá recalcular
os gates, verificar o banco/diário originais sob escopo próprio, manter worker parado,
preservar volumes/IDs e registrar intenção/cleanup duráveis antes dos seus efeitos.
Plan/recheck não substituem esses passos e não incluem um apply escondido.

Testar consultas permitidas e recusadas, projeção, ambiente, limites, drift,
validade, invariância do histórico e publicação interrompida. Fixtures do daemon
não provam Docker real; uma inspeção real somente leitura pode comprovar a forma
das projeções, sem iniciar qualquer laboratório. Sem nova dependência/migração/UI.

Fontes oficiais consultadas:

- [Docker volume inspect](https://docs.docker.com/reference/cli/docker/volume/inspect/)
- [Docker image inspect](https://docs.docker.com/reference/cli/docker/image/inspect/)
- [Docker container ls e filtros](https://docs.docker.com/reference/cli/docker/container/ls/)
- [Labels Docker e seus limites](https://docs.docker.com/engine/manage-resources/labels/)

Complementa [ADR0018](0018-offline-runner-pki.md) e
[ADR0019](0019-runner-binding-review.md). O runbook de ativação continua separado.
