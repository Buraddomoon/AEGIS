# Recuperação operacional Demo — #29/#119/#120/#121

Retomada solicitada pelo responsável após os testes da fonte287ed69. Objetivo
agora é concluir os critérios restantes, com ensaio nativo próprio entre hosts,
não encerrar as issues somente por CI verde. Estado abaixo é cronológico;
aceite depende das fases realmente executadas e do cleanup.

## Implementação do ensaio

`cf7b5b79dd167dec1f662bb8034aa935f8bb728a` —
`feat(recovery): add approved encrypted two-host Demo rehearsal (Refs #119, Refs #120, Refs #121, Refs #29)`.

- `operational_recovery.py`: contrato fechado de plano/budget/ator/prazo,
  origem/destino distintos, arquivo limitado e medição explícita.
- `operational_recovery_assay.py` e workflow manual: preparar imagens/plano,
  exigir aprovação posterior específica, origem sintética nativa, fence e
  conjunto cifrado de dump/configuração/imagens; outro host com três restores
  (quarentena, rollback real, transição/ciclo Demo novo) e cleanup.
- Reutilizados backup/inventário, roles/HBA, reconciliação, API e worker reais
  existentes. Fixture não vazia inclui fila/reserva/sessão/schedule/grant e
  relatórios READY/FAILED/PENDING. Sem backup humano, Lab ou alvo externo.
- Runbook/guia e `make test-recovery` atualizados. A leitura anterior que exigia
  operar especificamente o backup humano/implantar serviço permanente excedia
  os critérios escritos das issues. Esse limite foi corrigido sem reescrever
  testes/evidência antigos ou alegar recuperação do Demo humano.

Local, `.venv/Scripts/python.exe`/Python3.14.4, `PYTHONPATH=apps/api` somente no
processo: `pytest tests/test_operational_recovery.py tests/test_recovery_guards.py tests/test_recovery_probe.py -q --tb=short`
→49passed/1aviso existente/0,54s. Trinta contratos novos e19guardas/probe; sem
Docker/DB. Ruff check/formato global aprovados; programas de provisioning/probe
compilados sem executar. Antes do commit, staged/segredos/whitespace e release
check aprovados:874arquivos/244Markdown/809links, zero erros. Push direto e
HEAD/remoto conferidos; sem branch/PR.

[CI da primeira fonte46182942068](https://github.com/Buraddomoon/AEGIS/actions/runs/46182942068)
disparada pelo push, com quatro partições e React inalterados. Não declarar
sucesso integral antes de conferir os cinco jobs. Uma correção posterior exige
validar sua própria fonte, independentemente desse resultado.

## Preparação recusada, sem efeitos de origem/destino

[Tentativa46182972376](https://github.com/Buraddomoon/AEGIS/actions/runs/46182972376),
fontecf7b5b7, job141096489458: preparação terminou **FAILURE/ValueError** antes
da publicação da proposta; destino141096812417 SKIPPED pela dependência falha.
Artefato público15278218412 contém somente `prepare-failure.json`,
`FAILED_NOT_VERIFIED`. Nenhuma aprovação emitida, identidade enviada ao provedor,
origem Demo/clone criado ou pacote de dados transportado. Pull/build preparatórios
de imagens na VM descartável não são boot/restore nem operação de laboratório.

Causa reproduzida: `prepared_at` e `expires_at` usavam chamadas de relógio
diferentes, produzindo validade ligeiramente maior que45min; o contrato recusou
corretamente. Correção usa um único instante-base. Teste de regressão com relógio
que avança a cada chamada valida45min exatos e que a preparação só chama
pull/pull/build, sem create/start de runtime.

Após correção, mesmo comando local acima →**50passed/1aviso/0,51s**, agora31
contratos novos e19guardas/probe; Ruff check/formato pertinentes aprovados.
Código de segurança de prazo não relaxado. A próxima execução é run/proposta
nova, não replay/renovação de uma autorização consumida.

## Gate ainda exigido antes dos efeitos

A #121 pede: “Ensaio próprio após escolha do destino e aprovação específica.”
O perfil proposto escolhe duas VMs novas Ubuntu24.04 em jobs sequenciais do
mesmo workflow; fonte Demo própria e endpoint interno do destino, sem endpoint
humano. Aprovação deve identificar a proposta real com imagens/commit/hash,
fence/disposição da origem própria, transporte cifrado, secret temporário,
três restores/uma run/quatro testes sintéticos e cleanup.

A chave de ensaio foi gerada no controlador, em diretório Windows com ACL
restrita ao operador; não é chave de backup humano. Somente recipient público
é passado à preparação. Secret exclusivo da run só será criado após aceite,
sem sobrescrever outro secret, e removido após a tentativa. Não publicar chaves,
credencial Git, plaintext, dumps, logs ou caminhos privados em Git/issue/artefato.
RPO/RTO só podem ser registrados a partir dos instantes do ensaio realmente
executado; plano ou CI não são essas medições. Até essas provas, pai/filhos
permanecem abertos. [Procedimento](../../operations/operational-demo-recovery.md).

## Nova proposta concreta preparada, ainda sem efeitos

Correção publicada em `1503fc2eb2ee718554eab1b89df60a87b73dbc4e`,
`fix(recovery): bind proposal expiry to a single clock instant (Refs #119, Refs #121, Refs #29)`.
Checks staged/release antes do commit aprovados:875arquivos/245Markdown/
811links locais, zero erros. Push direto, main local/remoto conferidos.
[CI anterior46182942068](https://github.com/Buraddomoon/AEGIS/actions/runs/46182942068)
cancelada automaticamente pelo push da correção: React/Python0/Python1
aprovados; Python2/Python3 cancelados, sem alegar CI integral verde.

[Run46183684773](https://github.com/Buraddomoon/AEGIS/actions/runs/46183684773)
preparou a proposta em28/11/2026 **19:56:46,300207 UTC**, com validade
exatamente45min, até20:41:46,300207 UTC. A espera de aprovação termina20:21:46
para reservar20min aos efeitos e encerramento. Fonte1503fc2, Linux/amd64,
schemaf3b28c5d901a. Pacote:
`d7d1134fbd9d79fe74e05dfd0771d45ff2cfef5ca30eba4de54e09130740a28c`.

Imagens efetivamente inspecionadas, com todos os IDs completos no manifesto
público e [comentário de proposta da #121](https://github.com/Buraddomoon/AEGIS/issues/121#issuecomment-7244952392):
aplicação`d48398d8d0f1`, PostgreSQL`fa7e2700e906` e Redis`78195281e51d`.
O novo teste de relógio corresponde ao pacote aceito pelo validador real.
Job141098711315 está no gate de aprovação posterior, sem container de DB/API,
backup, exportação/cifra de dados ou transporte de conjunto iniciados. Nenhum
secret de identidade foi cadastrado no provedor. Proposta não é autorização.

[CI46183661714 da fonte corrigida](https://github.com/Buraddomoon/AEGIS/actions/runs/46183661714)
em acompanhamento. Antes de liberar efeitos, conferir quatro partições e React
e obter o aceite do responsável sobre esse pacote concreto. Depois registrar
secret temporário novo e comentário de autorização exato, sem expor identidade
ou token. Pais/filhos continuam abertos enquanto essas fases não têm prova.
