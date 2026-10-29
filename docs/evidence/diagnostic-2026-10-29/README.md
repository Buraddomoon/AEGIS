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
