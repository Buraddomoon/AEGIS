# Recuperação dos laboratórios — #9

Retomada em24/11/2026, restrita a #9/#64/#65/#66. O usuário pediu concluir toda
a entrega após a preparação parcial inicial. Dependência #4 encerrada; suas
autorizações antigas continuam consumidas. Consultar issues, este checkpoint e
os procedimentos; PROGRESS/chat antigo não são necessários.

## Implementação da retomada

- #64: biblioteca existente acrescida de coordenador de cópia fria RO, identidade
  de volumes/imagens, observações de quiescência, duas leituras byte a byte e
  custódia privada de configurações/PKI/fences selecionados, incluindo expirados e
  consumidos. JSON é dado inerte; nenhum histórico é corrigido para passar.
- #65: cluster novo offline, banco vazio e restore com inventário completo;
  locale/encoding/search_path preservados, sem reescrever sessões/aprovações/jobs,
  sem app/worker/runner/SIEM. Recibo verificado só depois de cleanup confirmado.
- Transporte limitado/saneado, intent antes dos efeitos, plano/hash de uso único;
  create ambíguo não é repetido, ausência sem ID não libera reserva, gate falho
  encerra novos efeitos e cleanup próprio continua permitido.

Arquivos: `operations/lab_archive.py`, `scripts/lab_recovery*.py`, testes
`test_lab_{archive,recovery,recovery_plan,recovery_transport}.py` e ensaio
explícito `tests/native_lab_recovery.py`; sem rota web ou migração nova.
[Contrato de dados](../operations/lab-backup.md),
[procedimento nativo](../operations/lab-recovery-native.md).

## Validação e limites

`make test-lab-recovery`: **297passed**,54,34s, zero skips; um aviso upstream
Starlette/httpx. Inclui59casos novos da retomada e os anteriores; mais8casos de
runtime reconferidos após acrescentar duas negativas de rede efetiva. São rodadas
sobrepostas, não somar como suíte única. `make lint` completo aprovado; checks staged/segredos/
whitespace/release antes de cada commit. CI final bce1f87/45454864685 **SUCCESS**:
quatro jobs Python conferidos,4070passed/9skips; React154testes/21arquivos,
lint/tipos/formato/build e revisão de dependências aprovados. #64/#65 têm aceite
técnico; a prova histórica e o aceite conjunto continuam pendentes na #66/#9.

O ensaio explícito já executou pg_dump/pg_restore, helpers tar, extração e
reabertura de cópia fria reais: inventários iguais,36tabelas/734linhas do schema
descartável e2, encoding/locale preservados e recursos próprios encerrados.
É synthetic=true, não prova dos originais b7. A primeira tentativa recusou a
estrutura por search_path diferente; a comparação não foi relaxada. Artefatos
privados/tentativa preservados; há regressão PG real para esse contexto. Ajustes
de fixtures de cleanup/hash também constam nas provas da retomada.

Somente metadados dos quatro volumes originais foram consultados; sem consumidores
na observação. Censo host-only:3689arquivos/20.457.443bytes/zero links no perfil.
Conteúdo dos volumes/chaves/configurações históricas não foi lido por este
coordenador; originais, PKI, rede qasrc e Demo preservados.

## Etapa restante para fechar #9

Atualização após aprovação: o usuário autorizou o escopo apresentado. A primeira
tentativa ad529621 foi interrompida por reboot, sem restore; cleanup separado
confirmado, tentativa preservada/consumida. [Incidente e novos tetos](../evidence/lab-backup-2026-11-24/INCIDENT-66.md).
Antes de continuar, coordenador e containers passam a ter CPU0,25/disco2MiB/s,
host384MiB/swap0/32tasks e cgroup obrigatório; piso disponível4GiB. Não repetir
o plano anterior ou tratar o cleanup como prova de restore.

#66 requer plano nativo de24h e aprovação específica dos quatro volumes e arquivos
de custódia definidos. O coordenador está implementado; não confundir essa
aprovação com trabalho de código ainda faltante. Após CI/fixture/plano concretos,
solicitar o aceite do escopo; não abrir originais antes disso.

O ensaio deve produzir recibos reais dos dois perfis, comparar origem/destino e
encerramento, preservar tentativas/autorizações consumidas e só então fechar #66
e o pai. Sem outros labs, marcador, migração, cutover, exclusão ou operação normal.
Falha/ambiguidade continua explícita e impede fechar #9.

Commits da retomada até a integração:46a6ba8 (arquivos frios/custódia),75b8e33
(transporte),cb9dd59 (restore). Último hash, CI, plano e sincronização constam nas
issues. [Provas iniciais preservadas](../evidence/lab-backup-2026-11-24/README.md).
Após aceite conjunto, registrar provas e **parar neste escopo**.
