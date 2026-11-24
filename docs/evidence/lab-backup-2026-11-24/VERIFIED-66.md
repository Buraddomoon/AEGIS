# Recuperação histórica verificada — #66 e aceite conjunto #9

**COLD_BACKUP_RESTORE_VERIFIED / CLEANED, synthetic=false.** Escopo #9/#64/#65/#66
concluído em24/11/2026. Dependência nativa #4 fechada; filhos técnicos #64/#65
aceitos antes do ensaio. Tentativas/falhas anteriores preservadas no
[incidente](INCIDENT-66.md), sem reutilizar pedidos consumidos.

## Origem, destino e autorização

O usuário aprovou expressamente o escopo apresentado e pediu concluir a entrega;
após relatar travamento, foram aplicados limites adicionais e custódia em pack.
Aprovação privada vinculada ao plano atual antes dos efeitos, sem inferir permissão
apenas dos flags da CLI. Todos os planos/autorizações usados ficam consumidos.

- Plano: `db6aa7b2dee9454c9ae255bc6c782304`.
- SHA256 canônico: `7998c53385171cc8e24f5011505253511af0b7dff189b515a2035146587203a8`.
- Fonte: `1c36563500fa9473d9e1d73853b1d7e943dab2f3`.
- Código do coordenador: `df7ba8eb3f9d136ff348bc1bb00419c883dc08f474d24a2b57203689f2d2696d`.
- Run: `12107d563cbe491b8900ba96ce4c6ea9`.
- Pedido: 2026-11-24T19:24:40.853372+00:00; recibo publicado: 2026-11-24T19:33:15.558331+00:00.
- Recibo canônico: `5c224f34847eecf76f46aa4f19c50d9a931656f2d71d80ced0d5c6489077e65b`, igual ao pin de closed.json e à saída independente do operador.

Somente `aegis-linux-lab_postgres-data`, `aegis-linux-lab_journal`,
`aegis-wazuh-lab_postgres-data` e `aegis-wazuh-lab_journal`, sem consumidores,
montados RO/nocopy em helpers próprios. PostgreSQL iniciou somente em cópias
privadas e clusters novos, sem rede/portas; database destino `aegis_restore`.
Imagem PostgreSQL17 local retida, sem build/pull/retag:
`sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24`.

- linux: `b9e402c109afbe5ff869610e20d6f050ea2ec49718e6c360984fd231f859de8e`; oito requests de criação próprios, scratch ausente após cleanup.
- wazuh: `12ede2c93d12a54732a2a66f93e21bfe5fc167920bba069d5163be7f614720c2`; oito requests de criação próprios, scratch ausente após cleanup.

## Comparação real

Inventários completos de estrutura e linhas da origem e do restore iguais.
A auditoria pós-cleanup confirmou igualdade JSON integral, schema/contexto e hashes.

| Perfil | Schema | Tabelas | Linhas | SHA256 SQL origem = destino |
| --- | --- | --- | --- | --- |
| linux | b7f3c2d91a06 | 33 | 871 | `2f9b7324c80560830426344a8f1e709687ff54a29e98da14d2efd13cb4f5bd71` |
| wazuh | b7f3c2d91a06 | 33 | 855 | `8d0544fd55bceb2796118cd8ddd5fdad5600a517bb09a95b12468d32390dd4b9` |

UTF8/libc, `en_US.utf8` em LC_COLLATE/LC_CTYPE e collation_version null preservados
nos dois perfis. Identidade/binding/descritor e CA/cliente conferidos contra o
histórico e os certificados públicos preservados na custódia; sem renovar PKI.
Source_commit identifica o coordenador, não a build histórica da aplicação.

Arquivos tar dos originais antes/depois idênticos byte a byte:

| Volume | Bytes | SHA256 antes = depois |
| --- | --- | --- |
| linux/PostgreSQL | 69713920 | `704e9dda1bbf32781fe726a0c90bd341fd70eb0dee4139d3a3881df29d120ab9` |
| linux/journal | 69120 | `d758fd227fd394dd4dcde79ad8e920c219d89c172214709148e21c766c50f62e` |
| wazuh/PostgreSQL | 70103552 | `6aab46f7b764c383f73e9ff34435d5761f4de37a52411a7055dee9097053dda9` |
| wazuh/journal | 60928 | `39d4a10da42e7681984f44c5edbe384f6c59376bc0df7cd8fec3fc412aec3f72` |

O PostgreSQL Linux também coincide com o arquivo anterior ao reboot da tentativa
ad529621. Estado shut down validado na cópia fria, sem PID e PG_VERSION17;
originais nunca foram iniciados ou montados RW por este procedimento.

Custódia de3689arquivos/20.457.443bytes selecionados dos dois checkouts AEGIS,
incluindo configurações, .env, PKI/chaves e fences/intents/candidatos expirados e
consumidos. Apenas dados inertes, sem seguir links ou importar configurações para
paths ativos. `/2` em records.tar0600 e inventory.json, diretórios0700:

- Pack: 23224320bytes, SHA `d3541eb3dd996ba60e0e31d1dd2d0f997c9772bc41feb88e057fcfc6625ae806`.
- Inventário de arquivos: `23652399218c7d30cd41f25455fb0fdf732b506950f5f12af45e61f76fe33791`.
- Envelope de custódia: `ba16ae9d1395c8f6ec5aff29ecae202c98ff8b72c7d476de85b5579b0e1aed8a`.

## Encerramento e impacto observado

Dezesseis containers próprios sequenciais, máximo um simultâneo. Todos removidos
por ID/ownership/receita conferidos; ausência confirmada, scratchs próprios
removidos. Auditoria final reconferiu quiescência/metadados/imagens, custódia,
permissões0700/0600 e zero containers de recuperação. Sem force/prune ou remoção
de volumes/backups. Rede qasrc e recursos terceiros não foram modificados.

Coordenador e cada container: CPU0,25, memória até384MiB por cgroup, swap0,
disco2MiB/s por direção;
host32tasks/nice15/IO idle, piso livre4GiB e prazo900s para novos efeitos.
Serviço: **8min59,217s**, CPU1min49,205s, pico384MiB incluindo cache, swap0.
Monitor externo de5s, 108amostras, sem interrupção:

- RAM disponível mínima: 5684191232bytes (5,29GiB).
- PSI de memória e de I/O do cgroup gráfico: máximos0,00.
- Ocupação física NVMe máxima: 9.98%.
- PSI global de I/O máxima: 32.49%; registrada separadamente, sem confundir espera com ocupação física.

A auditoria auxiliar inicialmente recusou path relativo antes de abrir a custódia;
repetida com path absoluto, guardas mantidas:10,755s, pico90,3MiB/swap0. Isso não
reexecutou o ensaio nem leu volumes originais. Relatório privado e hash de cadeia
preservados. Não há alegação de causa resolvida do reboot anterior; ver incidente.

## Validação e aceite

[CI45467586540 SUCCESS](https://github.com/Buraddomoon/AEGIS/actions/runs/45467586540),
fonte1c36563: quatro partições Python982/1023/1060/1025passed, **4090passed/9skips**;
React **154testes/21arquivos**, lint/tipos/formato/build e advisories aprovados.
Revisão de entrega45467586693 SUCCESS. Local:57testes pequenos sob tetos,
pico154,6MiB/swap0; nenhuma suíte integral local adicional para esse aceite.
Fixture sintética anterior e rodadas sobrepostas ficam separadas na
[retomada](RESUMPTION.md); não contam como prova dos originais.

- #64: banco/diário/metadados consistentes, custódia protegida, quiescência e originais inalterados; ambiguidades bloqueiam.
- #65: restore novo isolado, inventário integral igual, fences/histórico preservados; nenhum job ou aprovação reativado, ausência/404 não libera reserva.
- #66: dois perfis históricos verificados sob autorização própria, origem/destino e cleanup demonstrados.
- #9: aceite conjunto atendido; registrar fechamento dos filhos e pai nas issues e parar neste escopo.

Artefatos completos somente no host em `.local/lab-recovery/operations/12107d563cbe491b8900ba96ce4c6ea9`
e `.local/lab-recovery/plans/db6aa7b2dee9454c9ae255bc6c782304`. Nada de dump,
credenciais, chaves ou logs privados em Git/CI/issues. Hashes são integridade,
não assinatura. Manifestos /1 anteriores e seus flags false não foram editados;
a prova nativa/finalização é um envelope separado.

Sem app/worker/runner/scheduler/SIEM, novo marcador/campanha/veredicto, cutover,
migração, implantação, renovação PKI/binding ou retenção destrutiva. O escopo
protege dados AEGIS dos labs de marcador; não é restore integral de Indexer,
Manager ou Redis/Wazuh. Operação normal permanece false. Autorizações consumidas,
backups/imagens/fences e falhas retidos; sem replay ou outra entrega.
