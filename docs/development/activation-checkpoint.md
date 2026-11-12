# Checkpoint da issue4 — 12/11/2026

Escopo concluído: #4 e seus quatro filhos nativos, sem descendentes adicionais.
#3 fechada. Trabalho em `/home/IVPTER/AEGIS`, main com push direto. Os cinco
arquivos locais de `/home/IVPTER/codes/aegis` foram preservados integralmente.
Não avançar para outra entrega.

## Entrega

| Issue | Resultado |
|---|---|
| #48 | Backup frio real, restore/upgrade em clones e grants verificados; original real d446/27tabelas, corrigindo hipótese anterior a0 |
| #49 | Núcleo e executor concreto, cinco helpers fechados v3/d446, gates/intents/prazo/cleanup implementados; CI integral verde |
| #50 | API/UI testadas; binding real atualizado e revogado, preflight vigente confirmado no ensaio |
| #51 | Ensaio nativo positivo em12/11, conta temporária autorizada e desativada, recursos ausentes e evidência preservada |
| #4 | Aceite conjunto documentado; encerrar com todos os filhos concluídos |

Relatório atual: [ROTATION-2026-11-12](../../labs/linux/ROTATION-2026-11-12.md).
Preparação futura: [ACTIVATION-ASSAY](../../labs/linux/ACTIVATION-ASSAY.md).

## Evidência real

#48: original PostgreSQL copiado uma vez após validação, somente RO/nocopy/sem
rede;51.434.896bytes/1.439entradas, inventários fonte e backup idênticos.
Dump custom397.998bytes, SHA256
`4ef1bc67cdb7013198c76890685eab8f59785683226aa32b001900379ef5e969`.
Restore preservou linhas/colunas, contas/verificadores e ACLs efetivas. Upgrade
somente no clone d446→b7,27→33tabelas, seis novas vazias, `alembic check` e grants
mínimos. Preparações intermediárias falharam de forma fechada, sem nova cópia do
original; ledgers e volumes preservados. Ver
[compatibilidade](../operations/linux-schema-compatibility.md).

Evidência original de clone `f6ded75c...` preservada; derivada canônica para o
pacote `03fcbe5979e75a719300318ce2e6c735142a96ebfa8722320e0ea3585d12f935`.
A única normalização foi metadata.options null→{}, exatamente como o inventário
Docker do planejador. Nenhum backup/dado/prova foi modificado para essa derivação.

#51: operação `3003981c6b8240879f7a33151280b885`,12/11 13:12:13–13:14:45UTC.
Identidade mTLS nova, CA anterior recusada por erro de cadeia, binding revogado
confirmado, ambiente2→3 e preflight vigente. Uma prova histórica revisada, diário
idêntico antes/depois.55eventos duráveis,9recursos nativos ausentes, todos os
intents fechados. Conta temporária criada sob aprovação adicional específica,
desativada ao final, zero sessões; três contas antigas inativas e hashes intactos.
Recibo nativo `ccbc926a1db67ee5ca2ecabc52760921773d8e36770b1cae5d951954cc6eb01c`.
Recibo conjunto `b0635ae37efbfd33b72daa1b0029940f873b7cbc6cb7ca03fc3bac807bffc7b4`.

Originais sem consumidores após encerramento; qasrc, imagens, volumes/backups,
PKI, journals, candidatos e fences preservados. Sem migração original, seed,
bootstrap, grants/senhas antigas alterados, campanha, marker, worker ou Wazuh.
A chave privada do cliente antigo não foi usada; seus controles específicos
continuamfalse. Sem conclusão de detecção ou liberação de operação normal.

## Código, testes e implantação

Fonte executável final `eb834f5`, sincronizada com origin/main. Commits anteriores:
df5f5ef,9f31e48,c99e14d,8399ad3,19c9eec,54f61b0,295b8b8,5e91afc,0c08332.
Imagem nova a893bdae... em tag exclusiva538055454f3046ad911d1fc23bce29ce, fonte
instalada71arquivos/45dependências runtime/3build verificados. Leitor SQL dessa
imagem passou no clone real com credencial runtime e prova histórica completa.
Candidato81826566e88e4c9ebc8b9aa09c8a8d02 usado somente nas receitas do ensaio;
fonte PKI antiga e Demo b8/schema b7 não foram reimplantados/substituídos.

CI exata deeb834f5 [43104557557](https://github.com/Buraddomoon/AEGIS/actions/runs/43104557557)
**SUCCESS**, quatro Python e React conferidos: **3181Python/9skips,91React**;
revisão de fonte43104557594 também passou. CI5e91afc falhou em3casos de
introspecção da fixture e foi corrigida; não é evidência verde.

Testes locais PG/Redis15 sequenciais:44casos nativos d446, mais2casos distintos
de cleanup histórico; grupo4compatibilidade+2cleanup passou6/6 em7,40s, com
dump/restore efetivo sem skips. SQL exato da conta temporária foi testado também
em clone novo sob papel runtime: criada/desativada, contas antigas intactas e
zero sessões. Ruff lint/format, mypy e checks de staged/release aprovados.
Grupos anteriores e rodadas repetidas não são somados.

Este handoff atualiza documentação/comentário, sem mudar comportamento executável.
Artefatos privados não entram no Git. Um próximo ensaio exige escopo vigente;
não reabrir o pacote consumido nem limpar fences para repetir operação.
