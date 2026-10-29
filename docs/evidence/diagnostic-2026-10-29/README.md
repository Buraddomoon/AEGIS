# Diagnóstico Linux autorizado — 2026-10-29

Resultado mais recente: **diagnóstico completo verificado e encerrado**, quarta
tentativa especificamente autorizada, descrita ao final. As três tentativas
anteriores e seus limites permanecem abaixo, sem reescrever recibos históricos.

Resultado: **interrompido antes do start e encerrado**, sem conclusão sobre
continuidade SQL/diário. Autorização específica recebida como “aprovado” em resposta
ao escopo de [DIAGNOSTIC.md](../../../labs/linux/DIAGNOSTIC.md), uma única execução
com orçamento300s, sem campanha, marcador, Wazuh, alteração PKI ou binding.

Plano /3 `faea59ae780747cbb2cb3b1dcceeb72a`, código `7ce1c7d`, recheck passou antes
da execução; operação `de7aabdff5b04c5da116a86bb2d10496`. PG criado como
`f96e91bcffc740f2c8ea63d1e942868417abf831f4757a382f16c20348f01b73`.
Gate create passou; a revisão anterior ao start não confirmou o container.
Recibo: `diagnostic_failed_and_closed`, database_start_requested=false,
readiness_attempts=0, diagnostic_verified=false. Nenhum leitor SQL/probe foi criado.

Cleanup confirmou ausência e fechou a operação. Nova leitura de metadados confirmou
zero containers/redes Linux e zero consumidores, inclusive parados, dos volumes
originais journal/postgres-data; ambos continuam existentes. Nenhum volume removido,
nenhuma consulta ao SIEM ou mudança de credencial. Demo permaneceu em operação.

Recibo completo privado em `.local/pki-activation-runtime/OPERATION_ID/diagnostic-receipt.json`,
SHA256 dos bytes:
`efdab22c39de406d17de24d073004b55e0b7c3c13cab46becaea488c742f08d7`.
Intenção/pedido/recibos preservados; não repetir ou apagá-los para contornar uso único.

O erro legado foi registrado apenas como database_server_startup_unconfirmed, sem
detalhe suficiente para afirmar a exceção exata. Investigação posterior somente de
metadados reproduziu um defeito compatível: campos opcionais ReadOnly/BindOptions/
VolumeOptions acessados diretamente pelo template Docker falham quando omitidos.
A correção e seus testes serão registrados no progresso; não provam retrospectivamente
o erro exato nem um diagnóstico nativo bem-sucedido. Próximo ensaio exige outro plano
e autorização específica. Nenhum dado bruto SQL, segredo ou chave foi publicado.

## Segunda tentativa autorizada, após correção e CI

Código `ea2c61d`, plano `ef77bb4c21b04bc6af696c46d2730024`, operação
`e6566b9db97d47e88f9e8197a0f85c15`, autorização específica recebida como “aprovado”.
Condição CI atendida: [40896470899](https://github.com/Buraddomoon/AEGIS/actions/runs/40896470899)
SUCCESS sobre5379c63, 2.148 Python passaram/sete inspeções nativas opcionais puladas,
79 React passaram; lint/tipos/build/advisory review passaram. Advisory DiskCache
previamente revisado e aviso Starlette/httpx permanecem visíveis.

Recheck do plano passou, host com3.892MiB disponíveis e402GiB livres. Operação
durou cerca de28s (15:12:24–15:12:51UTC). PG iniciou uma única vez, inspeções de
mount/HBA/rede/portas e runtime confirmadas; pg_isready passou na primeira tentativa.
Isso valida startup/isolamento, não autenticação nem provas SQL.

Primeiro leitor foi criado e teve start solicitado; terminou sem prova validada,
`database_reader_execution_unconfirmed`. Não houve captura de bundle, probe de
diário ou leitor final. O erro genérico ainda não identifica se a causa ocorreu
no transporte, processo, inspeção após saída ou validação; não inferir falha de
credencial ou schema sem evidência. Nenhum grant/migração/reset foi tentado.

Recibo final `diagnostic_failed_and_closed`, diagnostic_verified=false,
database_start_requested=true, managed_resources_absence_verified=true. Dois
containers próprios removidos; reconferência externa confirmou nenhum container/
rede Linux ou consumidor dos volumes originais, ambos ainda existentes.
Startup PG pode escrever WAL/metadados, conforme autorizado. Sem marcador,
worker/API/Redis/Wazuh, PKI/binding ou remoção de volumes.

SHA256 dos bytes do segundo recibo privado:
`ae9df81d79228f47c2420f60fc77bd657951b796b720d2885d93f72ba33f3eef`.
Preservar todos os pedidos/intents/recibos; a segunda autorização foi consumida.
Continuidade SQL/diário e ativação continuam pendentes. Investigações posteriores
são offline até outro procedimento concreto e autorização específica.

## Terceira tentativa: rejeição SQL identificada, regressão reproduzida

Usuário respondeu “continuar” diretamente à autorização única do plano
`0388cd1e43bb4b50bec287130cd86326`, condicionado à CI aprovada; essa interpretação
foi explicitada antes do efeito. [CI40902712786](https://github.com/Buraddomoon/AEGIS/actions/runs/40902712786)
SUCCESS sobrec41ff43: 2.175 Python passaram/sete opcionais pulados/688,45s,
79 React passaram e lint/tipos/build/advisory review passaram. Main limpafccc6b9,
recheck passou e host com3.632MiB disponíveis/402GiB livres, sem alterar host.

Operação `9bb5b0847b8543548cd0db8373128b4d`, 17:30:25–17:30:49UTC. PG passou
inspeções/readiness. Novo leitor informou failure_code=
persisted_probe_database_profile_mismatch, failure_phase=start,
reported_failure_phase=collect. Não houve prova SQL validada nem diário.
Recibo diagnostic_failed_and_closed, ambos os recursos removidos; leitura externa
reconferiu nenhum container/rede Linux ou consumidor e os dois volumes existentes.
Nenhuma migração/grant/reset/marcador/PKI/binding/SIEM. Autorização consumida.
SHA256 dos bytes do terceiro recibo privado:
`9c8519db15e75a71e62c735eaf407612dfd9b3c9eeab5b3386b7fe06d78723c4`.

Investigação posterior somente no PostgreSQL de desenvolvimento, sem reabrir Lab,
reproduziu um erro determinístico da consulta: inet::text inclui a máscara (/32
em IPv4), enquanto a guarda exigia127.0.0.1 sem máscara. Confirmado pela função
[host(inet) do PostgreSQL17](https://www.postgresql.org/docs/17/functions-net.html).
Teste novo executa o SELECT de produção em conexão de schema descartável e valida
o endereço com ipaddress: falhou antes, passou após a0591af trocar o cast por host().
**67 testes do probe passaram/4,20s**. Guarda continua exigindo endereço/porta/papel/
schema/transação exatos; outros endereços não foram liberados. O defeito corrigido
explica uma rejeição inevitável do perfil, mas só outro ensaio autorizado poderá
validar o fluxo completo e revelar eventuais bloqueios posteriores.

## Confirmação completa após a correção

Autorização: “Autorizar essa confirmação após a CI passar”, para plano
`54f5b12d062f48b49df361efb9650f1a`, planSHA
`b52ce2a33a0669d98d40e0bddc0972b0bc968cf0050ebcedb263b2f837bb5150`, scopeSHA
`325cccbfe897d4d65b13871c72b5817c6efd967e1381f781fda5e7818985729b`.
[CI40922479654](https://github.com/Buraddomoon/AEGIS/actions/runs/40922479654) SUCCESS:
**2.176 Python passaram/sete opcionais pulados/847,90s, 79 React passaram**;
lint/tipos/build/advisory review passaram. Aviso e advisory conhecido permanecem.
Código funcional a0591af, main limpa a283b6a e plano revalidado antes do efeito.
Host com3.743MiB disponíveis/402GiB livres, sem mudar host ou parar serviços alheios.

Operação `4c28e0bfdb2a4d5f9d88076e55628b86`, 17:50:17–17:51:47UTC, dentro de300s.
PG iniciou uma vez e passou nas inspeções físicas/readiness. Os quatro probes
completaram e foram removidos; nenhuma falha reportada. Fonte/imagem da correção
conferidas conforme PROGRESS/build02204960...; sem afirmar assinatura de publicador.

- SQL: **uma prova conhecida**, binding/histórico/provas iguais antes/depois.
  Somente review.reviewed_at UTC foi ignorado como volátil; não é dump ou comparação
  de todas as tabelas. comparisonSHA248be2b947683b9af012d91244fa69554354857b5cc4a7aa5c221f62613aa0b8.
- Diário: **dois jobs/oito eventos**, incluindo um job adicional revisado;
  uma prova conhecida correspondeu. Inventários lógicos iguais nas duas leituras,
  implicit_restart_histories=0 neste volume. inventorySHA
  0597294eae36dff8f4920483976834260b4973621e415e75afbb9c8a5ff25f12.
- Cleanup: **cinco recursos próprios removidos**, operação fechada e ausência
  reconferida. Nova consulta externa confirmou nenhum container/rede Linux,
  nenhum consumidor dos dois volumes e ambos os volumes ainda existentes.

Resultado final diagnostic_verified_and_closed, diagnostic_verified=true,
managed_resources_absence_verified=true. Startup PG escreveu metadados/WAL conforme
o escopo; SQL e diário foram lidos pelo fluxo fixo. Sem marcador, worker, Wazuh,
migração, alteração de grants/senhas, ativação PKI/binding ou remoção de volumes.
normal_operation_permitted=false. Isso não é detecção SIEM nem autorização de
ativação; continuidade só comprovada nesse escopo/instante.

SHA256 dos bytes do recibo final privado:
`0be41f1dfedd58c23222a7e96538150bc43fbe851cccccf0553f07b63d343a88`.
SQL/capturas/recibos completos permanecem privados. A autorização única está
consumida; não repetir o plano, remover pedidos ou reutilizar o sucesso como lease.
