# Preparação de snapshots dos laboratórios — #9/#64

Estado em24/11/2026: biblioteca de preparação e verificações locais; **não é um
backup operacional aceito nem um restore demonstrado**. #64 permanece aberta.
#65 depende do aceite da #64; #66 depende da #65 e de autorização específica.
A dependência de produto #4 está concluída, mas suas autorizações já foram
consumidas. Nenhum procedimento desta página autoriza abrir volumes originais.

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
usuário. O adaptador nativo desse escritor ainda não foi implementado/aceito.

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

## Bloqueios e trabalho restante

Para concluir #64, ainda é necessário definir/revisar o coordenador nativo que
identifica volumes/dados exatos, imagem/schema compatíveis e PKI pública atual;
coleta completa de fences/configurações privados; quiescência externa contínua;
e adaptador de dump com transporte limitado. Essa preparação deve produzir um
pacote concreto de escopo, efeitos, orçamento e encerramento. Depois, obter
autorização específica antes de acessar originais. O pedido genérico da #9 não a
concede; nenhuma autorização histórica pode ser reutilizada.

#65 ainda não está implementada/aceita. Seu restore deve usar destino novo isolado,
ownership e intenção durável próprios, PostgreSQL compatível sem portas/rede ou
mounts originais, sem worker/runner/API normal/SIEM. Deve comparar todo inventário
restaurado e diário/fences, preservar sessões/aprovações/histórico como dados
inertes, nunca reconciliar como Demo ou retomar jobs. Ambiguidade e falha de
cleanup precisam continuar explícitas, sem publicar sucesso ou apagar fences.

#66 só pode ensaiar esse fluxo depois das dependências, com origem/destino
identificados e autorização específica para os dados/volumes definidos. Não
executar marcador, cutover, migração ou operação normal. Retenção é preservação;
não existe limpeza automática nem autorização de exclusão.

## Verificação local

As suítes usam schemas PostgreSQL e SQLite descartáveis. O escritor de dump dos
testes grava um cabeçalho sintético e **não representa pg_dump/pg_restore real**.
As provas e as consultas PostgreSQL são reais; os labs originais não são usados.
Executar em sequência com PG/Redis15 já configurados:

```sh
.venv/bin/pytest tests/test_lab_backup.py tests/test_runner_journal_continuity.py tests/test_runner_persisted_review.py tests/test_runner_journal_probe.py tests/test_runner_persisted_probe.py tests/test_backup_inventory.py -q --tb=short
```

Contagens, falhas e commits da sessão ficam no
[checkpoint](../development/lab-backup-checkpoint.md) e nos comentários da #9/#64.
Não executar targets de backup Demo ou diagnóstico Linux/Wazuh para preencher
evidência ausente deste escopo.
