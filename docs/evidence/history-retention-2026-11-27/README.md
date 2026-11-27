# Retenção de histórico — evidências de 27/11/2026

Escopo: #27 e suas filhas #114/#115/#116. Dependência #11 conferida encerrada,
com aceite registrado de recuperação b7. Entrada97795fc; AGENTS e guia de sessão
lidos, sem carregar PROGRESS inteiro nem usar conversa anterior.

## Resultado técnico e limite do pai

Implementado um perfil host-only de **snapshots completos e cópias cadastradas**.
Eventos, evidências, auditoria, recibos, relatórios e contexto permanecem juntos;
contagens vêm do inventário, bytes vêm dos arquivos completos, tamanho de linhas
é explicitamente desconhecido. Política fornecida pelo operador, piso30 dias/
sete inventários distintos verificados, holds por ID, incompletos e formatos
não suportados preservados. Plano possui membros/hashes/motivos/validade/área.

Arquivo age/X25519 com índice versionado, manifesto/dump/recibos originais e
hashes completos. A extração manual rejeita links, caminhos, duplicatas, tipos
especiais, falta de membro, índice adulterado e excesso. Verificação usa o
coordenador existente para restaurar em clone PostgreSQL17 offline; recibo só
sai após cleanup de clone e staging. Hash e recibo local não são assinatura.

Aplicação exige plano íntegro e vigente, aprovação operacional exata, confirmação,
lock exclusivo e intenção durável de uso único. Todos os candidatos são
restaurados novamente antes do primeiro unlink; inventário, prazo, holds e
ownership são reconferidos. Somente arquivos explícitos das cópias próprias
podem ser removidos, por descritores e sem recursão. Falha deixa auditoria e
cópia incompleta protegida; staging pendente bloqueia operações posteriores.

**O pai #27 e a #116 permanecem abertos.** Esse perfil reduz apenas as cópias em claro
cadastradas. Não reduz tabelas ativas nem descarta arquivos cifrados. A política
para esses históricos e o aceite do objetivo mais amplo ainda precisam de
decisão explícita; não foram substituídos por um TTL arbitrário ou por autorização
inferida deste pedido. O aceite técnico de #114/#115 e a preparação parcial de #116 são registrados
com esse limite. Não há pacote de aplicação humana preparado ou aprovado nesta sessão.

## Verificações locais realmente executadas

| Comando | Resultado final | Alcance |
| --- | --- | --- |
| `make test-retention` |48passed,1aviso upstream|Arquivos privados temporários, age real, callbacks de restore explícitos de fixture; plano/holds/mínimo/drift/locks/prazos/uso único/cleanup/exclusão/CLI|
| `make test-retention-native-fixture` |1passed,1aviso upstream|Dump/age/restore PostgreSQL17 real em recursos descartáveis;9 tabelas/10 linhas, relações e triggers imutáveis, relatório com duas runs, synthetic/proveniência/versão|
| `make test-recovery` |235passed,1aviso upstream|Regressão existente, PG/schema próprio e Redis15, sequencial; credenciais vigentes somente no processo|
| `make lint` |Aprovado|Ruff/formato/mypy/TypeScript/Prettier completos|
| staged/segredos, `git diff --cached --check`, `check_release.py` |Aprovados antes de cada commit|Revisão suplementar de fontes/documentação; não prova ausência universal de segredos|

As contagens sobrepostas não devem ser somadas como casos distintos. O aviso é
a depreciação upstream Starlette/httpx. Não houve mudança de filtros/skips,
timeout, dependências, workflow ou guardas para obter sucesso. O teste nativo
fica opt-in e fora da coleta padrão; CI não inicia esses contêineres.

O fixture nativo contém evento, evidência relacionada, recibo, auditoria,
synthetic=true, versão e relatório congelado com duas runs. É uma fixture
relacional reduzida, **não o schema inteiro da aplicação**, nem dado humano ou
ensaio de laboratório. Inventários reais de dados/estrutura antes/depois iguais;
manifesto/dump/recibo histórico byte a byte iguais; fonte original preservada.
Clone e fonte PostgreSQL removidos por ownership, nenhum contêiner
`aegis-recovery-*` remanescente após a rodada final; staging vazio.

Tentativas anteriores preservadas:

- Primeira regressão com `.env` antigo:171passed/64erros de preparação por
  autenticação PostgreSQL. Não houve alteração de contas/senhas ou do `.env`.
- Com PG vigente e Redis ainda antigo:222passed/4failed/14errors, associados à
  autenticação Redis e à preparação/teardown dependentes. Uma seleção de
  credencial Redis recusou antes de executar testes; foi ajustada apenas a
  leitura da configuração vigente em memória.
- Rodada final com ambas as configurações somente no ambiente do processo:
 235passed. Logs com detalhes ficam privados0600 em
 `.local/history-retention-validation`, nunca no Git/issue.
- As rodadas menores anteriores (6/41/46testes) e os primeiros lint de imports
  não substituem os resultados finais; não foram ocultados por exclusões.
- CIs das fontes intermediárias foram canceladas pela concorrência normal após
  novos commits; não são apresentadas como workflows aprovados.

## CI da fonte final

[Workflow46054659557](https://github.com/Buraddomoon/AEGIS/actions/runs/46054659557)
na fonte 46a03b1: primeira tentativa com falha no teste preexistente
`test_sigma_validation.py::test_private_scope_expiry_drift_and_recovery_fail_closed`.
A partição 1 terminou1094passed/2skips/1failed em361,65 s. O teste define `NOW` na
coleta e uma autorização de5 min; a primeira leitura válida foi recusada, compatível com a
janela já expirada. Diagnóstico: expiração dependente da duração da suíte, sem diferença
nesse teste ou no runtime Sigma entre a entrada e a fonte final. Nenhum limite,
validade, filtro, skip ou arquivo Sigma foi alterado nesta entrega. Pedido de
rerun durante o workflow ativo foi recusado pelo GitHub; após a conclusão foi
aceita uma única repetição da partição 1, na **mesma fonte**, sem mudar testes.

Resultado final: **SUCCESS na tentativa 2**. Partição 1:1095passed/2skips em263,71 s.
Partições 0/2/3 e React já aprovadas na tentativa1 foram preservadas pelo GitHub;
cinco jobs finais conferidos, sem filtros novos ou exclusões. União das quatro
partições: **4303 Python aprovados/9 skips existentes**, não soma de tentativas:

| Partição | Passed | Skips |
| --- | ---: | ---: |
|0|1016|2|
|1 (rerun)|1095|2|
|2|1081|1|
|3|1111|4|

React: **186 testes/24 arquivos**. Lint/tipos/formato, build e auditorias do workflow
aprovados. A falha inicial permanece consultável na
[tentativa1](https://github.com/Buraddomoon/AEGIS/actions/runs/46054659557/attempts/1).
O defeito de relógio do teste Sigma não foi corrigido nem ocultado nesta entrega.
O teste PostgreSQL nativo de retenção foi executado localmente de forma explícita;
o SUCCESS de CI não significa que ele rodou no GitHub nem que houve implantação.

## Fonte, implantação e autorização

- `2ce4945` — `feat(retention): define immutable snapshot policy and review plans (Refs #114)`.
- `b2e4cc9` — `feat(retention): archive complete private snapshot copies with verified restore (Refs #114, Refs #115)`.
- `025a60d` — `feat(retention): require one-use approval and fresh restore before removal (Refs #116)`.
- `46a03b1f2ffafeb48992c2e92c7f414d54131770` — `fix(retention): refuse unresolved staging and ownership drift (Refs #115, Refs #116)`; fonte executável final.

Somente main; push após cada commit. Arquivos relevantes:
`apps/api/aegis/operations/retention.py`, `retention_store.py`, `retention_apply.py`,
`scripts/history_retention.py`, testes `test_retention_*` e `native_retention.py`,
Makefile e [procedimento](../../operations/history-retention.md).

Implantado: **nenhuma nova implantação**. Demo anterior preservado, sem build de
imagem, mudança de tag, migração ou acesso/operação em Linux/Wazuh/SIEM/originais.
Não houve marcador, replay, nova run humana, alteração em qasrc/PKI/volumes/
journals/fences, upload ou descarte de backups/chaves. Apenas PostgreSQLs novos
em tmpfs/sem rede foram iniciados pelo ensaio explícito; não são laboratórios.
Exclusões de teste afetaram somente cópias de fixtures temporárias.

Sem prova de custódia externa, recuperação off-host, prontidão operacional ou
redução do crescimento de tabelas ativas. Nenhuma aprovação humana de exclusão
real foi consumida ou inferida. Não executar outro escopo após este registro.
