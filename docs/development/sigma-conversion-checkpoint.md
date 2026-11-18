# Checkpoint — entrega #16: conversão Sigma

Retomada em18/11 após pedido explícito de resolver o bloqueio: o
[ADR0036](../architecture/decisions/0036-isolated-sigma-converter.md) substitui
a espera por publicação por um conversor oficial em venv/processo separados.
Parser da API continua2.0.1; conjunto1.5.1/2.0.3/2.1.1 com18pins/hashes e
pip check próprios, auditado separadamente.25testes do processo passaram e
auditoria manteve somente o finding DiskCache já revisado, cujo import é proibido.
#84 retomada para essa solução;#85/#86 em implementação. Estado anterior abaixo
é preservado como histórico, sem alegar conversão/UI entregue nesta etapa.

18/11/2026: **#84 pesquisada e concluída com resultado negativo; #85/#86
bloqueadas e #16 aberta, sem aceite conjunto.**

OpenSearch2.0.3 e Elasticsearch2.1.1 publicados continuam exigindo pySigma<2.
O runtime2.0.1 e a atualização candidata2.1.0 falham com ResolutionImpossible.
Core1.5.1 resolve18wheels com hashes conferidos, mas é downgrade vedado, não
instalação aprovada. A declaração core^2.1.0 no main do Elasticsearch não está
no wheel publicado. Não instalar fontes/editar METADATA para ignorar o conflito.

[Matriz, hashes, fontes e resultados](../evidence/sigma-compatibility-2026-11-18/README.md).
[ADR0035](../architecture/decisions/0035-sigma-published-backend-compatibility.md).
91testes locais passaram após ajustar somente o ambiente do processo de teste
às credenciais dos serviços de desenvolvimento existentes; a primeira rodada
teve76passed/15errors de autenticação PostgreSQL, preservados no relatório.
Pip check/Ruff/mypy passaram. Sem CI integral nova, UI/E2E ou implantação.

Runtime, locks, snapshot22/10, perfil/hash e histórico preservados; nenhum backend
instalado/importado. Readiness continua blocked/can_convert=false; a prévia de
rename não gera consulta. Sem operação SIEM ou Linux/Wazuh, acesso a volumes
originais, novo marcador ou mudança de autorização.

Retomar somente quando houver distribuição oficial compatível, com nova
conferência de wheels/METADATA, pins/licenças/imports/segurança. Isso libera a
implementação de#85, não a presume concluída;#86 depende da API e seus testes.
Bloqueios e commits/sincronização registrados no GitHub. Sessão encerrada no
bloqueio externo desta entrega; não avançar automaticamente para outra feature.
