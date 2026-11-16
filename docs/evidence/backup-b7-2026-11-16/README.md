# Recuperação Demo a0/b7 — 16/11/2026, #70

Entrega [#11](https://github.com/Buraddomoon/AEGIS/issues/11), primeira unidade
[#70](https://github.com/Buraddomoon/AEGIS/issues/70). Fonte de partida
`2b31144`, checkout limpo/sincronizado em main. Nenhuma mudança executável ou
implantação nesta unidade. API/worker do Demo continuam na imagem `b8abe5e44af4`.

| Cópia | Revisão | Tabelas | Linhas | Resultado |
| --- | --- | --- | --- | --- |
| Pré-migração de09/11 | a0d9c7e21b45 | 32 | 3399 | [restore e boot restrito](a0-application.json) |
| Snapshot fresco de16/11 | b7f3c2d91a06 | 33 | 3399 | [restore e boot restrito](b7-application.json) |

Os recibos agregados foram conferidos contra os arquivos privados. Cada ensaio
usou PostgreSQL17 pelo ID do manifesto, clone próprio network=none/tmpfs sem
portas ou volumes persistentes, restore em transação única e comparação completa
do inventário/estrutura/hashes internos. A API teve somente SELECT/SCRAM, sem
Redis/worker/scheduler operacional: nove rotas protegidas/bloqueadas, quatro
escritas SQL negadas, cinco entrypoints recusados e TCP administrativo negado.
Inventário idêntico após leitura; API removida antes do banco, antes do recibo.

A cópia a0 original em `codes/aegis/.local/backups` permaneceu intacta; uma cópia
privada0600/0700 no checkout atual foi validada pela mesma ferramenta antes do
restore. Dump e manifesto não foram editados. Imagens a0 `9e3fe0c86a83` e b7
`b8abe5e44af4` retidas em tags próprias `aegis-recovery-issue11:a0-20261109` e
`aegis-recovery-issue11:b7-20261109`, com IDs imutáveis completos nos recibos.
Nenhum build substituiu tags ou serviços existentes. A seleção local da imagem
antes de `demo_backup.rehearse(..., application=True)` não relaxou guardas.

Comandos/resultado: `make backup-demo`; ensaios `rehearse` a0 e b7 em sequência;
`make test-recovery`: **229passed**, um aviso upstream Starlette/httpx. Primeira
tentativa com `.env` deste checkout:171passed/58errors por autenticação PostgreSQL;
primeira criação de backup também recusada, sem manifesto válido. Configuração
da instalação ativa foi lida localmente, sem trocar credenciais; repetição passou.
Diretórios dessas tentativas permanecem privados e não substituem cópias boas.

O backup b7 contém **zero scheduled_reports**,23runs COMPLETED e nenhuma fila
de execução pendente. Isso é fidelidade real desse snapshot, não prova não vazia
de READY/FAILED/PENDING. A #71 trata reconciliação e os casos sintéticos
complementares. Sessões/usuários/lab históricos presentes no snapshot continuam
inacessíveis na API em recovery; esta etapa não os reconcilia.

Não houve cutover, login normal, migração, execução/replay de campanha, alteração
de contas ou nova implantação. Linux/Wazuh, qasrc, PKI, volumes, journals e fences
preservados. Backups, intenções e diagnósticos ficam no host; sem envio de dumps,
manifestos, documentos ou credenciais. Hash não é assinatura; não há prova
off-host, recuperação de roles/Redis/journals ou garantia de RPO/RTO.
