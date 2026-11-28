# Recuperação operacional do Demo — preparação #29

Escopo: [#119](https://github.com/Buraddomoon/AEGIS/issues/119) →
[#120](https://github.com/Buraddomoon/AEGIS/issues/120) →
[#121](https://github.com/Buraddomoon/AEGIS/issues/121). Este documento define o
conjunto e os gates; não comprova transporte, boot, transição persistente ou
cutover. Estado e provas da sessão no
[checkpoint](../development/operational-recovery-checkpoint.md).

As dependências #11 e #28 estão concluídas. A #11 comprovou restore/boot em
quarentena e reconciliação de cópias compatíveis; a #28 aceitou custódia externa
manual e restore nativo local dos ZIPs entregues. Nenhuma demonstrou recuperação
em outro computador ou concedeu autorização para novo transporte/cutover.
Os pacotes e ensaios anteriores continuam encerrados.

## Conjunto recuperável e origem confiável

Um dump sozinho não é backup completo. O inventário privado de uma recuperação
deve vincular cada item abaixo à mesma origem e ao snapshot escolhido. Guardar
referências de integridade por canal confiável separado; hash não é assinatura.
Não publicar nomes de contas, caminhos privados, dumps, manifests operacionais,
configuração, chaves ou hashes de backups humanos em Git/issues.

| Item | Fonte existente | Exigência antes do boot |
| --- | --- | --- |
| Dados | `scripts/demo_backup.py`, envelope age e manifesto de inventário | Origem confiável, chave correspondente, autenticação da cifra e comparação de dados/estrutura após restore; sem fallback para o banco fonte |
| Aplicação e frontend | Imagem compatível retida, commit e locks correspondentes | ID imutável, arquitetura/OS, revisão Alembic esperada e frontend da mesma imagem; rebuild é outra imagem |
| PostgreSQL | ID de imagem registrado no manifesto | PostgreSQL17 e a imagem exata disponível no destino; a CLI recusa pull e substituição silenciosa |
| Redis | Imagem local identificada para o ciclo | Instância nova, senha nova, sem RDB/AOF antigo; filas duráveis são reconciliadas no PostgreSQL |
| Código de operação | Checkout confiável, scripts, `alembic.ini`, fixtures e locks | Compatibilidade com a imagem/schema escolhido; nenhum arquivo de configuração humana incluído no checkout transportável |
| Configuração | Lista privada de nomes e finalidade das variáveis, origem/orientação TLS e redes revisadas | Recriar somente valores aprovados para o destino; não copiar `.env` integral nem habilitar conectores por herança |
| Roles/ACL/HBA | `runtime_grants.py`, `recovery.py`, provisionamento do clone | Recriar papéis mínimos no destino vazio e verificar privilégios efetivos; o dump é restaurado sem owners/ACLs |
| Segredos | Custódia privada independente da chave age e referências de acesso | Preservar chaves antigas para seus backups; gerar credenciais SQL/Redis/conta/token novas no destino, sem argv/log/camada de imagem |
| Artefatos externos | Inventário explícito de presença/ausência | Dump não inclui PKI, journals/intents/fences de runner ou evidência externa; não recuperar operações reais a partir desse conjunto Demo |
| Evidência | Recibos, intenções, hashes e tempos privados; resumo sanitizado | Vincular conjunto, IDs de imagem, destino e cleanup; recibo só após a fase correspondente e encerramento confirmados |

O backup aceito pela #28 é b7/33 tabelas, snapshot de 27/11/2026 20:28 UTC,
3.399 linhas. Esses números são evidência histórica, não inspeção do banco ativo
nesta sessão. O checkout examinado em 28/11 tem head Alembic
`f3b28c5d901a` e 36 tabelas pelo metadata incluindo Alembic. Código atual não
substitui automaticamente a imagem b7. `required_revision()`, o review e a
reconciliação exigem correspondência exata; não migrar o backup nem remover a
guarda para fazê-lo passar. Escolher a combinação compatível e registrar a
decisão antes do ensaio. Ver [compatibilidade anterior](backup-recovery.md).

### Preservação e exportação de imagens, ainda não executadas

1. Em host autorizado, identificar por ID a imagem efetiva da aplicação e as
   imagens PostgreSQL/Redis necessárias. Registrar OS/arquitetura, revisão,
   commit/locks e limitações conhecidas no inventário privado.
2. Antes de qualquer build/retag, criar referência local dedicada, inédita por
   imagem, e conferir que resolve para o mesmo ID. Preservar todas as referências
   históricas. Somente anotar o ID não retém a imagem.
3. Sob plano de transporte aprovado, usar `docker image save` para as referências
   preservadas em arquivo privado novo; `docker export` de container não substitui
   esse arquivo de imagem. Calcular integridade do arquivo e protegê-lo conforme
   sua sensibilidade; manter metadados de custódia separados. Tags locais não
   protegem contra perda do host.
4. Conferir integridade antes de `docker image load` em destino vazio autorizado;
   conferir IDs/OS/arquitetura após o load, sem sobrescrever tags preexistentes.
   Se houver conflito ou ID ausente, parar. Não usar pull/rebuild como prova de
   identidade com a imagem preservada.

Nesta sessão nenhuma imagem foi inspecionada, retaggeada, exportada, importada
ou construída. A lista de imagens concretas e a verificação após transporte
permanecem pendentes; não há alegação de conjunto completo já disponível.

## Destino vazio e privilégios

O operador precisa delimitar host, recursos, diretórios privados e Docker local
Linux/POSIX, incluindo socket Unix e suporte a permissões/ownership e tmpfs.
O fluxo atual de `demo_backup.py` fixa `unix:///var/run/docker.sock`, ignora
contexts remotos e exige `getuid`, arquivos0600/diretórios0700. Windows nativo
não satisfaz esse contrato. Não emular essas guardas nem instalar stack para
contornar a ausência do ambiente sem escopo específico.

Provisionar somente recursos novos próprios. Banco `aegis_restore` do ensaio
fica sem rede externa, portas, mounts persistentes ou socket Docker montado;
API/Redis/worker compartilham o namespace desse banco. Não usar `make up` ou o
serviço `migrate` do Compose para recuperar o snapshot: eles executam migração,
seed, grants e inicialização normal. Nenhuma migração é implícita no restore.

| Identidade | Privilégios e duração |
| --- | --- |
| Administrador host-only do clone | Restore/provisionamento e reconciliação no banco novo; nunca credencial da API/worker; TCP administrativo rejeitado pelo HBA do ensaio |
| `aegis_recovery` | Login próprio, SELECT e transações read-only; sem memberships, ownership, CREATE/TEMP, escrita por tabela/coluna, execução de funções da aplicação ou large objects; restrições verificadas por `database_guard` |
| `aegis_app` novo | NOINHERIT/NOSUPERUSER/NOCREATEDB/NOCREATEROLE/NOREPLICATION/NOBYPASSRLS; grants revisados de `RUNTIME_PERMISSIONS`, revogações append-only e por coluna; sem acesso ao schema privado `aegis_recovery_guard` |
| Conta administrativa Demo nova | Criada somente após reconciliação, senha nova e escopo sintético novo; não reativar usuário/sessão antiga |

A política de quarentena aplica também revogação de funções large object de
PUBLIC **somente no clone descartável**. Não alterar grants globais/roles da
fonte ou de outros projetos. Validar privilégios efetivos em READ WRITE além de
conferir configuração read-only. Não importar roles globais do host anterior.

Na configuração nova, revisar `DATABASE_URL`, `REDIS_URL`, `PUBLIC_ORIGIN` e
`SECURE_COOKIES`. Em quarentena usar `OPERATING_MODE=recovery`, token independente
e binding atual de `RECOVERY_RECONCILIATION_ID/HASH` quando aplicável. O token
recovery não é sessão normal. Conectores Wazuh, registros/configuração Linux,
perfis defensivos e scheduling Linux continuam ausentes/desligados; nunca
transportar automaticamente certificados ou configurações desses laboratórios.
TLS/proxy/publicação além do loopback exigem revisão específica do destino.

## Gates da transição #120

Reutilizar `recovery.py`, `reconciliation.py`, `recovered_demo.py`,
`scripts/demo_backup.py` e `scripts/recovery_cycle_runtime.py`. O código atual
ensaia um ciclo **descartável**, remove o clone e não oferece promoção persistente
ou cutover. Uma futura transição operacional deve ter procedimento/implementação
e validação próprios; sucesso do ciclo não abre esse gate.

1. **Restore fiel:** verificar cifra, origem, imagem/schema e inventários antes
   de boot. SQL é executável: arquivo confiável é requisito. Divergência bloqueia.
2. **Quarentena:** API restrita e papel leitor novo, sem worker/scheduler/login
   normal; validar recusas dos entrypoints e de escrita. Rotas normais ficam503.
3. **Plano de reconciliação:** vincular hash do snapshot atual e ID novo. Estado
   real pendente, reserva ambígua, dispatch externo associado a pendência ou estado desconhecido
   bloqueiam a transação. Recibo antigo não satisfaz binding atual.
4. **Aplicação host-only no clone:** lock exclusivo/NOWAIT, hash revalidado,
   sessões removidas, usuários desativados, labs revogados, reservas liberadas
   apenas quando não ambíguas, schedules/grants revogados, pendências Demo
   canceladas pelas transições permitidas e relatórios PENDING marcados FAILED.
   Aprovações/scopes/resultados/históricos finais não são reescritos. Falha
   reverte a transação; não fazer reparo manual para obter recibo.
5. **Identidades novas:** somente com blockers/fences zerados e recibo atual,
   provisionar role/senhas/Redis/conta/lab/ativo sintéticos novos. Nenhum worker
   antes desse gate. Aprovação nova com scope novo; não readquirir efeito ambíguo.
6. **Ciclo limitado:** API e worker normais apenas no destino isolado; uma run dos
   quatro testes Demo, evidências e relatórios sintéticos, hashes e linhas
   históricas conferidos. Isso não prova detecção real ou retomada Lab.
7. **Encerramento:** revogar lab novo, consumir aprovação própria, fechar sessão,
   desativar conta e exigir zero pendências. Encerrar worker→API→Redis→DB;
   falha de ownership/cleanup retém dependências e bloqueia recibo. Preservar
   intents/diagnóstico, sem prune/replay ou remoção de recursos de terceiros.

Testes existentes cobrem guardas, DB/API/worker, falhas por fase e rollback.
Executar no ambiente compatível, com PG/Redis de testes em sequência, conforme
[guia de testes](../development/testing.md). Passes de contratos sem I/O e
inspeção estática não substituem boot com roles mínimos, restore real ou ensaio
entre hosts. Falhas ambientais são evidência de bloqueio, não sucesso parcial
do ensaio operacional.

## Pacote concreto exigido antes da #121

Preencher em registro privado e publicar somente resumo sanitizado para decisão:

- Conjunto/snapshot e referência confiável; imagens exatas, arquitetura, schema,
  roles/ACL, caminho de recuperação da chave e itens ausentes do inventário.
- Destino novo escolhido, ownership, capacidade, isolamento, armazenamento e
  janela; origem a preservar, recursos permitidos e proibição de alvos Lab.
- Transporte delimitado dos artefatos e custódia separada de chaves; nada enviado
  apenas porque as dependências estão fechadas.
- Ações exatas: ensaio isolado, ou também transição persistente e cutover;
  endpoint/origem/TLS, novas identidades e quem aprova cada fase.
- Interrupção/fence de escrita da origem, instante de referência e condição
  comprovável de ausência de dois workers ativos sobre a mesma operação.
- Rollback: gatilhos, preservação da origem/backup e responsáveis. Falha no novo
  destino não autoriza reativar automaticamente contas/jobs da origem; se houver
  escrita nova, reconciliar a divergência antes de qualquer retorno autorizado.
- Orçamento e condição de cleanup, recursos a reter, prova de ausência de filhos
  e limites aceitos; não apagar arquivos humanos ou imagens anteriores.

Sem conjunto compatível validado, destino e aprovação específica, parar antes
do transporte/start/cutover. A #121 continua bloqueada e #29 não fecha.
Após autorização, medir separadamente snapshot, início da indisponibilidade,
início/fim do restore, gates, ciclo e eventual serviço aceito. RPO observado
depende do snapshot e do fence da origem; RTO observado inclui o intervalo de
indisponibilidade definido. Tempos locais de restore da #28 não medem RPO/RTO
de recuperação entre hosts e não são SLA.
