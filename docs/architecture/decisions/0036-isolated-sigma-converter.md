# ADR 0036 — Conversor Sigma oficial em processo isolado

Data: 2026-11-18. Decisão de retomada da entrega#16 após pedido explícito de
resolver o bloqueio e entregar#85/#86. Substitui somente a condição de esperar
publicação futura do [ADR0035](0035-sigma-published-backend-compatibility.md).
A pesquisa e os resultados históricos daquele ADR continuam válidos.

Manter pySigma2.0.1 no processo da API/worker e seus locks originais. Instalar o
conjunto oficial compatível pySigma1.5.1/OpenSearch2.0.3/Elasticsearch2.1.1 em
venv separado, sem acesso aos site-packages da API. Não é downgrade do parser
da aplicação nem instalação incompatível: os requisitos do conversor são
resolvidos integralmente, com18pins/wheels/hashes em lock próprio e pip check.
Não copiar/alterar backend ou seus METADATA. Bibliotecas LGPL2.1/LGPL3 continuam
separadas, com LICENSE nos wheels instalados; incluir o lock em builds/auditorias.

É um subprocesso fixo dentro do monólito, não serviço de rede ou executor remoto.
O único programa aceita JSON inerte limitado; nunca argumentos, destinos,
índices, scripts, plugins ou YAML de pipeline do cliente. Python -I/-B, ambiente
limpo, stdin64KiB,3sCPU/512MiB de espaço virtual/5s de prazo, saída8KiB de query.
Imports de cache/discovery/validators/data, rede, subprocessos e gravações são
recusados por audit hook antes do backend. DiskCache permanece dependência
transitiva com advisory conhecido; sua importação é proibida, não sanitizada.

Perfil novo `aegis-marker-lucene/1`, política literal-boolean/1 e hash próprios.
O candidato/hash `wazuh-aegis-marker/1` e a prévia2.0.1 permanecem independentes.
Somente strings literais/listas, campos nomeados e AND/OR/NOT/parênteses limitados;
modificadores, fieldref, números, selectors e keywords retornam unsupported com
motivo. Não remover semântica silenciosamente. Pipeline oficial fixo de rename,
modelo novo, invariância da detection e golden queries do backend oficial.

Disponibilidade do conversor é verificada ao gerar uma consulta da versão exata.
Ausência/drift/timeout/saída inesperada falham fechado. Nenhuma evidência é criada
pela conversão e nenhum scope, hash histórico, cobertura ou veredicto é alterado.
Query com procedência não significa índice físico validado, regra implantada ou
eficácia; essas dependem de entregas/autorização próprias. Conversão não consulta
Wazuh e não inicia laboratórios. UI só libera download após conferir contrato,
contexto completo e hashes do artefato; respostas stale/erro não mantêm sucesso.
