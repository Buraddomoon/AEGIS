# Preparação de snapshots dos laboratórios — #9/#64

Estado em24/11/2026, retomada da #9: biblioteca e coordenador de cópia fria/restore
implementados. Há ensaio real de dump/restore e reabertura de cópia fria **com
dados descartáveis**, separado do ensaio histórico da #66. A execução sobre os
originais exige plano concreto e autorização específica. A dependência #4 está
concluída; suas autorizações antigas continuam consumidas.

## Contrato implementado

`aegis.operations.lab_backup` é uma biblioteca exclusivamente do host, sem rota
API, CLI de execução, descoberta de credenciais ou lifecycle Docker. O perfil
inicial cobre somente os labs históricos Linux/Wazuh com
`linux-file-marker/v1`; não inclui automaticamente perfis Atomic/processo/shell.

O chamador confiável fornece engine PostgreSQL17, diretório do diário parado,
contexto público, bytes dos fences previamente exportados e um escritor de dump
que importa o snapshot exportado. Esses parâmetros não vêm de YAML ou upload.
`create` não consulta `.env`, não inicializa Journal/Runner e não abre SQLite na
origem. O escritor é código confiável do host, não um comando livre recebido do
usuário. O adaptador nativo limitado e o coordenador estão em
`scripts/lab_recovery*.py`; ver [procedimento nativo](lab-recovery-native.md).

O contexto versionado inclui projeto fechado, commit, IDs do runner/lab/ativo,
descritor público completo e hash, fingerprints públicos de CA/cliente,
imageIDs de aplicação/runner/PostgreSQL/Redis, schema/revisão e versão do ambiente.
O descritor precisa coincidir com identidade, fingerprints e binding persistido.
Não entram chave privada, URL PostgreSQL, senha ou variável de ambiente.
Fingerprint e hash não autenticam o publicador nem substituem a custódia da PKI.

Sequência da preparação:

1. Destino novo exclusivo, sob pai privado0700, sem symlinks. Não adotar destino
   de tentativa anterior nem sobrescrever arquivos para liberar repetição.
2. PostgreSQL em REPEATABLE READ/READ ONLY, UTC e timeout15s. O mesmo snapshot
   exportado atende inventário e importação das provas persistidas; o escritor
   recebe esse ID enquanto a transação exportadora continua aberta.
3. Revisão existente exige lab revogado/sem reserva, histórico terminal e todos
   os dispatches conhecidos com prova CLEANED coerente. Ausência de prova,
   geração alterada, dispatch ambíguo ou estado desconhecido bloqueiam antes do
   dump. Nenhum404 é usado como prova de cleanup.
4. Captura do diário sob o mesmo lock da revisão, preservando DB/WAL/SHM/lock
   byte a byte. SQLite interpreta somente scratch privado, com os limites e
   verificações já existentes. WAL parcial/corrompido não é reparado ou truncado.
5. Dump privado exclusivo; checagem conservadora do cabeçalho PGDMP e limite
   de128MiB após escrita. Isso **não valida o arquivo como um restore**. O futuro
   escritor nativo também precisa de timeout e orçamento de saída/disco durante
   a exportação; o limite posterior não limita um subprocesso em execução.
6. Provas e diário reconferidos após o dump; inventário PostgreSQL fresco precisa
   coincidir. Só `reviewed_at` da observação do revisor é desconsiderado na
   comparação; o bundle original não é editado. Drift de dados ou histórico
   impede publicar manifesto.
7. Fences/intents previamente exportados são bytes opacos, sem interpretar
   instruções ou liberar reservas. Até100 documentos de4MiB cada,8MiB somados;
   candidatos expirados e autorizações consumidas devem permanecer presentes.
   A biblioteca não pode comprovar sozinha que o coletor exportou todos eles.
8. Arquivos0600, diretórios0700, fsync e manifesto publicado por último.
   Falha preserva cópia parcial privada; não produz recibo de restore.

O envelope `aegis-lab-data-snapshot/1` contém hashes/tamanhos dos arquivos,
identificador e contexto. `inspect(folder, expected_sha256)` exige hash canônico
retido independentemente, nomes fechados, arquivos regulares próprios/0600 sem
links, limites e coerência entre contexto, provas e diário. Não altera dados.
O manifesto não inclui linhas do banco; os arquivos do pacote continuam privados
porque dump/provas/diário/fences podem conter dados sensíveis.

As flags `physical_binding_verified`, `host_fences_complete_verified`,
`external_quiescence_verified`, `operational_snapshot_verified`,
`restore_verified`, `activation_permitted` e `normal_operation_permitted`
permanecem **false**. Editá-las invalida o perfil mesmo com um hash recalculado.
Um snapshot SQL não impede um consumidor externo de aparecer; a comparação
antes/depois também não substitui exclusão de consumidores durante a operação.

## Coordenador e aceite histórico

O coordenador acrescenta um envelope de evidência independente: metadados do
daemon/imagens/volumes, custódia dos arquivos privados selecionados, duas leituras
RO de cada volume, quiescência observada em cada etapa, cópia PostgreSQL parada,
dump real e restore em cluster novo. O manifesto `/1` acima permanece imutável,
com suas flags false; não é editado para representar evidência física posterior.

O restore da #65 não inicia app, worker, runner, scheduler ou SIEM. Mantém os
registros históricos como dados, inclusive sessões/aprovações/fences, sem
reconciliar como Demo ou reutilizar autorização. Encoding, provider/locale,
schema, todas as linhas/estruturas e hashes de diário/custódia são comparados.
O recibo verificado só é publicado depois do encerramento dos recursos próprios.

#66 só pode ensaiar esse fluxo depois das dependências, com origem/destino
identificados e autorização específica para os dados/volumes definidos. Não
executar marcador, cutover, migração ou operação normal. Retenção é preservação;
não existe limpeza automática nem autorização de exclusão.

## Verificação local

As suítes regulares usam schemas PostgreSQL/SQLite descartáveis e daemon simulado.
O escritor de dump de `test_lab_backup.py` continua sintético; há outro ensaio
explícito com pg_dump/pg_restore, helper tar, cópia fria e PostgreSQL reais, usando
somente fixture descartável. Nenhum deles representa o aceite histórico da #66.
Executar sequencialmente com PG/Redis15 já configurados:

```sh
make test-lab-recovery
make test-lab-recovery-native-fixture
```

Contagens, falhas e commits da sessão ficam no
[checkpoint](../development/lab-backup-checkpoint.md) e nos comentários da #9/#64.
Não executar targets de backup Demo ou diagnóstico Linux/Wazuh para preencher
evidência ausente deste escopo.
