# Diagnóstico

| Sintoma | Verificação e recuperação |
|---|---|
| Tela de login sem usuário | `make bootstrap`; não existe credencial padrão |
| Login HTTP 503 | Verificar Redis e `/api/v1/health/ready`; limitador falha fechado |
| Login HTTP 429 | Aguardar TTL de até 5 minutos; não desativar limite global |
| Mutação HTTP 403 | Conferir papel, cookie/CSRF e PUBLIC_ORIGIN; usar a mesma origem, não alternar localhost/IP |
| Campanha permanece na fila | `docker compose logs worker`; banco conserva o job; aprovação/deadline podem expirar antes do claim |
| Worker offline no dashboard | Ausência de heartbeat recente ou Redis indisponível; não concluir que os jobs foram perdidos |
| Início HTTP 409 | Aprovação vencida, configuração mudou ou laboratório reservado; inspecionar execução anterior e criar nova solicitação quando necessário |
| CLEANUP_FAILED | Ler erro/instrução e revisar ambiente; Demo permite confirmar revisão em Laboratórios; não apagar a reserva via SQL sem análise |
| Wazuh desconectado | Configuração ausente é estado esperado no Demo; não criar dados de conexão fictícios |
| Wazuh teste falha | Verificar IP fixado, certificado/hostname, CA e credenciais de leitura; nunca usar verify=False |
| Portas de dev não aparecem | Redes internas Docker não publicam portas em algumas versões; usar `infra/compose.dev.yml`, sem abrir portas em 0.0.0.0 |
| E2E Firefox falha | Confirmar Firefox instalado e AEGIS_BROWSER_PATH; logs em .local/e2e e screenshot failure.png; não desabilitar sandbox |
| Novo advisory no audit | Revisar origem, versão e caminho; corrigir ou documentar análise concreta. Não ignorar IDs desconhecidos |

O Redis do host inicial emite aviso sobre overcommit de memória. Não alteramos sysctl do host nem controles de segurança. A demonstração utiliza Redis pequeno, sem persistência necessária; PostgreSQL mantém a fila. Avaliar configuração do host em implantação administrada própria.
