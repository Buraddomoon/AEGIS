# Checkpoint — retenção de histórico #27

Retomada de 27/11/2026 conclui os critérios técnicos de #116 e o aceite conjunto
com #114/#115 no perfil de **snapshots completos e cópias próprias cadastradas**.
Política explícita: pelo menos 30 dias/sete inventários distintos verificados,
legal hold, plano por hash/validade/área; arquivo age com todos os membros;
aplicação host-only com aprovação específica, lock, uso único e auditoria.
Não há TTL/DELETE de linhas ou mudança nos guards/grants do banco ativo.

O bloqueio do primeiro handoff exigia expurgo do banco ativo, que não consta no
critério da #116. Essa interpretação foi corrigida, preservando o registro
anterior e sem ampliar qualquer autorização. O alcance da política é explícito;
não declarar redução das tabelas ativas ou descarte de arquivos cifrados.

Complemento fdd8a59: 49 testes de retenção e lint completo aprovados; ensaio real
da CLI em PostgreSQL novo, schema f3b/36 tabelas, fixture sintética/34 linhas.
Nove snapshots distintos restaurados; uma cópia elegível removida, oito mantidas
(mínimo de sete + legal hold), 119783 bytes lógicos de arquivos removidos. Banco,
fontes e arquivos protegidos idênticos; restore após remoção, drift, dry-run,
replay e cleanup verificados. Não há mock de restore nesse ensaio.

[Provas do aceite e correção do handoff](../evidence/history-retention-2026-11-27/ACCEPTANCE-116.md),
[histórico inicial/falhas](../evidence/history-retention-2026-11-27/README.md) e
[operação](../operations/history-retention.md). CI do complemento fdd8a59:
[46058984159](https://github.com/Buraddomoon/AEGIS/actions/runs/46058984159)
SUCCESS na primeira tentativa, quatro partições conferidas: 4304 Python/9 skips
existentes e 186 React/24 arquivos. CI anterior 46054659557/46a03b1 e primeira
falha Sigma mantidas no histórico. Não confundir CI com o ensaio nativo local.

Demo anterior e originais Linux/Wazuh preservados, sem implantação/migração,
marcador, operação SIEM, remoção de backup/chave humana ou custódia externa.
Recursos descartáveis próprios encerrados e staging vazio. Nenhuma autorização
histórica reutilizada ou pacote de exclusão humana preparado. Critérios de
#114/#115/#116 e aceite conjunto de #27 atendidos, com encerramento e sincronização
registrados nas issues. Parar nesta entrega.
