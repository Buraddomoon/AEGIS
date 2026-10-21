# Execução segura

Allowlist atual: quatro definições Demo versionadas em `seed.py`. O adapter em memória não cria arquivos reais, subprocessos nem conexões de rede. Todos os registros Demo mantêm synthetic=true. Linux usa synthetic=false e recibos próprios. É proibido transformar entrada de API/YAML em comandos executáveis.

Uma solicitação percorre estados validados; worker revalida pré-requisitos, marca execução, coleta e aplica correlação independente de fornecedor. Cancelamento ativo é cooperativo e leva ao cleanup; cancelamento antes da preparação não tem efeitos a limpar. Cleanup sempre é tentado para contextos preparados, inclusive na falha de execução. CLEANUP_FAILED mantém reserva e expõe erro/instrução para revisão administrativa.

Após morte abrupta, finally não é garantido. Worker identifica run sintético sem heartbeat e com deadline vencido há 30s, registra cleanup de contexto sem efeito externo e TIMED_OUT. Não reexecuta simulações automaticamente. Jobs QUEUED têm deadline absoluto e não bloqueiam o laboratório indefinidamente após o worker retornar.

Os adaptadores Demo retornam imediatamente; deadline e cancelamento não interrompem uma chamada síncrona arbitrariamente bloqueada. **Antes de Lab Mode:** usar executor fixo isolado, prazo efetivo por processo, lease/fencing para efeitos externos, cleanup idempotente revisado, revisão de allowlist e teste em ambiente explicitamente autorizado. Não habilitar shell genérico nem executar comandos importados.

## Runner Linux e campanhas opt-in

O runner opt-in do ADR 0003 admite somente linux-file-marker/v1, sem comandos, caminhos ou scripts importados. Executa programa fixo em subprocesso com deadline monotônico (máximo de 5s), lease de 2s, cancelamento de grupo, reap e PDEATHSIG. O watchdog mata/recolhe o processo antes de tocar o diário SQLite, para locks de persistência não prolongarem efeitos. Lease expirado não renova; UUID/hash/geração impedem replay.

Workspace privado, arquivo fixo exclusivo/NOFOLLOW e cleanup restrito por dir_fd; arquivos inesperados mantêm reserva. Journal sobrevive ao container e não repete efeito ambíguo. mTLS exige CA cliente exclusiva, distinta da CA servidor. Rede Docker usa internal+gateway isolated, sem portas/rotas externas nem gateway de host. Esses controles são verificados por inspect; não constituem sandbox para código arbitrário nem substituem VM.

Ensaio específico autorizado pelo usuário em 2026-10-21 confirmou marcador de 43 bytes, hash, remoção e fence após reinício. Runner/container/rede foram parados/removidos, preservando diário/PKI. O incremento seguinte ligou o adapter ao worker, com identidade fixada, aprovação segregada, synthetic=false, dispatch durável, comprovantes imutáveis e recuperação verificada. Segundo ensaio autorizado confirmou uma campanha integrada, efeito de 43 bytes e cleanup, sem SIEM. Crash ou RPC ambígua conserva reserva; recuperar nunca reenvia start. A configuração padrão continua Demo. Ver [procedimentos](../../labs/linux/README.md).

Coleta Wazuh segue ADR 0005 e exige binding próprio. Query só usa destino/política fixados, com mapping agent.id exato, IP pin/TLS/SNI e timeout integral; mudança de configuração revoga validade do escopo. A coleta não executa nem reexecuta marcador. Observer passivo só lê arquivo fixo/UUID.hex privado e verificado; não é iniciado no deployment padrão. Exemplos XML são preparados, não implantados. Nesta etapa nenhum Wazuh ou Linux Lab real foi iniciado.
