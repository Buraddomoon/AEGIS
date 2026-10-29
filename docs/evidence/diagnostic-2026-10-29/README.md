# Diagnóstico Linux autorizado — 2026-10-29

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
