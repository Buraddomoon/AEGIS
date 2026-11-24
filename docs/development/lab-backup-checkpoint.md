# Recuperação dos laboratórios — #9 concluída

Entrega restrita a #9/#64/#65/#66, concluída em24/11/2026. Dependência nativa #4
fechada. [Prova histórica e aceite conjunto](../evidence/lab-backup-2026-11-24/VERIFIED-66.md).
Ler issues, este checkpoint e procedimentos; PROGRESS/chat antigo não são necessários.

## Resultado verificado

Plano db6aa7b2dee9454c9ae255bc6c782304, SHA
7998c53385171cc8e24f5011505253511af0b7dff189b515a2035146587203a8;
run12107d563cbe491b8900ba96ce4c6ea9, **COLD_BACKUP_RESTORE_VERIFIED/CLEANED**,
synthetic=false. Aprovação expressa do usuário registrada antes dos efeitos,
continuada com limites mais restritos após relato de travamento.

- #64: snapshot RR/READ ONLY e pg_dump no mesmo snapshot, banco/diário/contexto,
  descritor/PKI/imagens/schema e custódia protegida; ambiguidades bloqueiam.
- #65: clusters e bancos novos isolados, sem app/worker/runner/SIEM ou replay;
  inventários completos iguais, reservas e histórico preservados, cleanup por ID.
- #66: Linux b7/33tabelas/871linhas e Wazuh b7/33tabelas/855linhas iguais no
  restore; originais RO/nocopy iguais byte a byte antes/depois. UTF8/libc,
  en_US.utf8 e collation_version null preservados.16containers próprios
  sequenciais removidos, scratchs ausentes; metadados/quiescência reconferidos.

Recibo canônico5c224f34847eecf76f46aa4f19c50d9a931656f2d71d80ced0d5c6489077e65b,
igual ao pin de closed.json/operador. Artefatos e chaves privados somente no host,
0700/0600, em .local/lab-recovery/operations/RUN_ID e plans/PLAN_ID. Nada em Git/upload.

## Recursos, falhas e validação

CPU0,25/384MiB/swap0/disco2MiB/s por cgroup, host32tasks/nice15/IO idle e piso4GiB.
Serviço8min59,217s, pico384MiB incluindo cache; mínimo5,29GiB RAM disponível,
PSI de memória/interface0, NVMe máximo9,98%, sem interrupção do monitor final.
Custódia /2 em pack único: mesmos3689arquivos/20.457.443bytes, hash por arquivo
mais pack inteiro, manifesto por último; /1 retido continua verificável.

[Incidente e tentativas](../evidence/lab-backup-2026-11-24/INCIDENT-66.md): reboot
na primeira tentativa ad529621 após um tar Linux; cleanup posterior confirmado.
Plano0d448be9/b1a9e8f9 interrompido durante custódia por PSI, sem abrir volumes,
cleanup confirmado. Preflights UNCONFIRMED não consumiram pedidos. Nenhuma falha
foi reescrita como sucesso. Monitor final correlaciona PSI global com NVMe e
observa cgroup gráfico, sem reduzir tetos ou gates de dados/ownership/cleanup.

Fonte final1c36563500fa9473d9e1d73853b1d7e943dab2f3, CI45467586540 **SUCCESS**:
quatro partições Python982/1023/1060/1025 =4090passed/9skips,154React/21arquivos;
lint/tipos/formato/build/advisories aprovados.57testes pequenos locais passaram
sob tetos; rodada integral local interrompida deliberadamente, não aprovada.
Fixture sintética anterior fica separada na [retomada](../evidence/lab-backup-2026-11-24/RESUMPTION.md).
Auditoria final independente de recibos/inventários/custódia/permissões/cleanup
aprovada; path relativo recusado primeiro, corrigido no operador sem afrouxar guarda.

Arquivos: operations/lab_backup.py, lab_archive.py, continuity.py, persisted_review.py;
scripts/lab_recovery*.py e testes correspondentes. [Contrato](../operations/lab-backup.md)
e [procedimento](../operations/lab-recovery-native.md). Commits/cadeia completa,
hashes e último estado local/remoto nas issues e provas vinculadas.

## Limite encerrado

Dados AEGIS dos labs de marcador; não é restore integral do produto Wazuh/Indexer/
Manager/Redis. Sem novo marcador/campanha/veredicto, cutover, migração, renovação
PKI/binding, implantação ou ativação de jobs/aprovações. Qasrc, originais, Demo,
imagens, fences/candidatos expirados e tentativas preservados. Sem exclusão de
backups. Manifestos /1/flags false não editados; evidência nativa em envelope próprio.

Planos/autorizações consumidos; sem replay ou operação normal. #64/#65 técnicos
aceitos, #66 histórico e #9 conjunto atendidos. Registrar fechamento e **parar**.
