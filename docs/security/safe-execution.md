# Execução segura

Allowlist atual: quatro definições Demo versionadas em `seed.py`. O adapter em memória não cria arquivos reais, subprocessos nem conexões de rede. Todos os registros mantêm synthetic=true. É proibido transformar entrada de API/YAML em comandos executáveis.

Uma solicitação percorre estados validados; worker revalida pré-requisitos, marca execução, coleta e aplica correlação independente de fornecedor. Cancelamento ativo é cooperativo e leva ao cleanup; cancelamento antes da preparação não tem efeitos a limpar. Cleanup sempre é tentado para contextos preparados, inclusive na falha de execução. CLEANUP_FAILED mantém reserva e expõe erro/instrução para revisão administrativa.

Após morte abrupta, finally não é garantido. Worker identifica run sintético sem heartbeat e com deadline vencido há 30s, registra cleanup de contexto sem efeito externo e TIMED_OUT. Não reexecuta simulações automaticamente. Jobs QUEUED têm deadline absoluto e não bloqueiam o laboratório indefinidamente após o worker retornar.

Os adaptadores Demo retornam imediatamente; deadline e cancelamento não interrompem uma chamada síncrona arbitrariamente bloqueada. **Antes de Lab Mode:** usar executor fixo isolado, prazo efetivo por processo, lease/fencing para efeitos externos, cleanup idempotente revisado, revisão de allowlist e teste em ambiente explicitamente autorizado. Não habilitar shell genérico nem executar comandos importados.
