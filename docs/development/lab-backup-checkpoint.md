# Recuperação dos laboratórios — #9

Sessão de24/11/2026, restrita a #9/#64/#65/#66. Partida local526f1a6,
atualizada por fast-forward para origin/main3c5b848 antes de editar. Dependência
#4 encerrada. Lidos AGENTS, guia de sessão, pai/filhas e referências pertinentes;
PROGRESS e chat anterior não foram usados como fonte de execução.

## Entrega parcial da #64

Biblioteca host-only `apps/api/aegis/operations/lab_backup.py`, perfil
`aegis-lab-data-snapshot/1`: contexto público/imagens/schema, snapshot PostgreSQL
compartilhado com provas, captura íntegra do diário/WAL e cópia opaca de fences,
destino novo privado e publicação durável. Inspect por hash independente recusa
drift, links, permissões inseguras e flags operacionais alteradas. Refatorações
pequenas dos revisores existentes preservam o contrato anterior de `review`.
Procedimento e limites em [lab-backup](../operations/lab-backup.md).

## Bloqueios preservados

- #64 aberta: falta coordenador nativo de volumes/ownership, coleta completa de
  fences/configurações, quiescência externa e escritor pg_dump limitado; depois,
  pacote de escopo concreto e autorização específica para acesso aos originais.
  Flags de vínculo físico/quiescência/restore/operação permanecem false.
- #65 aberta e ainda não implementada: depende do aceite da #64. Não substituir
  implementação por cópia de arquivos ou pelo restore/reconciliação do Demo.
- #66 aberta: depende da #65 e da aprovação específica; nenhum ensaio autorizado
  nesta sessão. Não usar pacotes históricos consumidos para contornar o bloqueio.
- #9 permanece aberta. Nenhum pai/filho fechado sem evidência correspondente.

Não houve start/build de Lab, leitura de volumes originais, marcador, migração,
restore nativo, mudança de PKI, binding, grants, credenciais, rede ou implantação.
Nenhum backup/chave/log/dump foi adicionado ao Git. A outra cópia do repositório
em `/home/IVPTER/codes/aegis` conserva suas alterações locais de outra tarefa.

## Verificação e sincronização

Primeira sondagem:1teste SQLite passou e1teste PG falhou no setup por autenticação
da configuração deste checkout. A configuração já existente do checkout de
desenvolvimento foi usada somente no ambiente dos processos de teste, sem alterar
arquivos/contas/grants. A repetição do caso PG passou. Primeira rodada da nova
suíte:32passed; rodada intermediária ampliada236passed. A rodada final executou
os seis arquivos do procedimento: **238passed**, incluindo42casos novos, em52,28s;
um aviso upstream Starlette/httpx, sem skips. As contagens são sobrepostas, não
devem ser somadas. Escritor de dump é fixture explícita, sem restore PostgreSQL
real. `make lint` completo aprovado: Ruff/formato/mypy/TypeScript/Prettier.
Nenhuma UI mudou, portanto build/E2E não foram repetidos localmente.

Implementação `5ead4907edb8237536fc5a2b36430384e919ffb5`,
`feat(recovery): prepare consistent private lab snapshots (Refs #64, #9)`, enviada
a origin/main. [CI45402749488](https://github.com/Buraddomoon/AEGIS/actions/runs/45402749488)
**SUCCESS**: quatro partições Python conferidas,4005passed/9skips existentes;
React154passed em21arquivos, build/lint/tipos/auditorias aprovados. Revisão de
fonte45402749351 também SUCCESS. O commit posterior acrescenta somente provas
Markdown; não muda o código validado. [Provas e resultados por job](../evidence/lab-backup-2026-11-24/README.md).

Nenhuma issue fechada. Checks staged/segredos/whitespace/release aprovados antes
do commit da implementação e exigidos novamente na consolidação documental;
push direto em main. Último hash/mensagem e sincronização final constam nos
comentários da #9/#64.

Ao registrar as provas finais, **parar neste escopo**; não iniciar #65/#66 nem
outra entrega a partir deste checkpoint sem resolver os bloqueios descritos.
