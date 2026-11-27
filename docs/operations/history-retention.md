# Retenção de histórico — #27

A unidade desta política é um snapshot completo. Eventos, evidências, auditoria,
recibos, relatórios e contexto (escopos, aprovações, versões, contas e relações)
permanecem juntos no dump PostgreSQL. Nenhuma tabela recebe TTL ou DELETE; não
há alteração de triggers append-only, grants, migrações ou endpoints web.

A área host-only de retenção recebe **cópias explicitamente cadastradas** de
backups. Originais, arquivos cifrados, chaves, journals e fences não são alvos.
Aplicar significa remover apenas uma cópia em claro cadastrada nessa área,
após arquivo cifrado e restauração isolada confirmados. Isso reduz o espaço das
cópias em claro; não reduz tabelas do banco nem promete retenção off-host.

A política JSON precisa ser fornecida explicitamente:

```json
{
  "format": "aegis-history-retention-policy/1",
  "retain_days": 30,
  "minimum_snapshots": 7,
  "legal_holds": []
}
```

Trinta dias e sete snapshots **distintos e verificados** são pisos herdados do
planejador anterior, não autorização para excluir. É possível aumentá-los. Um
hold contém o ID exato do backup, sem justificativa confidencial no plano. Dados
incompletos, formato desconhecido e cópia sem restauração verificada ficam
preservados. Duas cópias/IDs do mesmo inventário não contam duas vezes para o
mínimo. Uma cópia recente e qualquer hold são preservados independentemente do
mínimo. Nenhuma política é executada automaticamente no startup/worker/CI.

O plano inclui membros e hashes de arquivos, contagens por categoria/tabela,
bytes reais de arquivos, motivos, política, área, validade de até uma hora e hash
do conjunto. Tamanho de linhas não é estimado: aparece como desconhecido.
Mudanças de política, hold, arquivos, recibos ou conjunto exigem outro plano.
Hashes não são assinatura; recibo local não comprova custódia independente.

Uso destrutivo no ambiente humano exige nova aprovação específica do pacote e
é proibido na sessão de implementação da #116. Testes usam recursos descartáveis.
A fonte em10/11 tinha somente planos consultivos de backups; este documento não
reescreve essa evidência histórica nem altera os comandos consultivos existentes.

## Cadastrar, arquivar e verificar

Todos os caminhos são absolutos, sem symlinks; diretórios0700 e arquivos0600,
pertencentes ao usuário atual. A área deve ser **nova**; `init` recusa adotar
qualquer diretório existente. Não há pasta padrão nem descoberta de originais.
Crie o JSON da política como arquivo privado e use:

```sh
.venv/bin/python scripts/history_retention.py --store /AREA/NOVA init --policy /PRIVADO/policy.json
.venv/bin/python scripts/history_retention.py --store /AREA/NOVA enroll --source /BACKUPS/ID
.venv/bin/python scripts/history_retention.py --store /AREA/NOVA archive ID --recipient AGE_PUBLIC_RECIPIENT
.venv/bin/python scripts/history_retention.py --store /AREA/NOVA verify ARCHIVE_ID --expected-sha256 CIPHER_SHA256 --keys /PRIVADO/KEYS --key-id KEY_ID
.venv/bin/python scripts/history_retention.py --store /AREA/NOVA plan
```

O cadastro copia manifesto, dump e todos os recibos reconhecidos, byte a byte;
publica ownership somente após conferir origem/destino. Um cadastro interrompido
fica preservado e inelegível. Arquivos extras/desconhecidos são recusados. Não
remova/recrie um cadastro incompleto para fazer o plano passar.

O pacote versionado contém índice, manifesto original, dump e recibos completos,
com referências/hashes; não exporta uma seleção mutilada de linhas. O dump mantém
proveniência, flags `synthetic`, versões, relações e snapshots. Age/X25519 faz a
cifra autenticada; não existe fallback para texto em claro. O índice e todos os
membros devem coincidir; links, caminhos, tipos especiais, duplicatas e excesso
de tamanho são recusados na extração manual. Pacotes e chaves ficam no host.

`verify` executa o coordenador de recuperação existente: PostgreSQL17 local
fixado no manifesto, clone novo sem rede/portas/volumes persistentes, inventário
de dados/estrutura idêntico e cleanup. Não inicia API/worker nem reconcilia ou
reativa dados. Recibo de sucesso só é publicado depois da remoção do clone e do
staging privado. Falhas retêm cópias e pacotes parciais. Dump confiável apenas:
restaurar SQL pode executar funções; arquivo recebido de terceiro não se torna
confiável apenas por ter um hash válido. Ver [limites de recuperação](backup-recovery.md).

## Revisão e aplicação de uso único

Salve o plano em arquivo0600 fora da área gerenciada; confira IDs, motivos,
bytes, hashes, holds e validade. `apply --dry-run` só revalida o plano atual:

```sh
.venv/bin/python scripts/history_retention.py --store /AREA/NOVA apply --plan /PRIVADO/plan.json --expected-sha256 PLAN_SHA256 --dry-run
```

Para uma operação futura **separadamente aprovada**, o operador humano fornece
um arquivo0600 com estes campos exatos (sem ferramenta que autoaprove):

```json
{
  "format": "aegis-history-retention-approval/1",
  "store_id": "ID_EXATO_DA_AREA",
  "plan_sha256": "HASH_EXATO_DO_PLANO",
  "decision": "approve_enrolled_plaintext_removal",
  "approved_by": "IDENTIFICADOR_DO_APROVADOR",
  "approved_at": "INSTANTE_COM_FUSO",
  "expires_at": "ATE_A_VALIDADE_DO_PLANO"
}
```

O arquivo é registro de aprovação operacional, não autenticação, assinatura ou
prova automática de que um humano aprovou. A aprovação deve existir antes de o
operador materializar esse registro. A flag sozinha não concede autorização.
Nesta sessão, não criar esse registro para ambiente humano nem aplicar nele.

```sh
.venv/bin/python scripts/history_retention.py --store /AREA/NOVA apply --plan /PRIVADO/plan.json --expected-sha256 PLAN_SHA256 --authorization /PRIVADO/approval.json --keys /PRIVADO/KEYS --key-id KEY_ID --confirm-remove-copies
```

A trava exclusiva cobre cadastro, arquivamento, verificação, plano e aplicação.
A intenção durável consome o hash uma única vez. Todas as cópias candidatas são
restauradas novamente, com clone/staging removidos, antes da primeira remoção;
depois todo o inventário é reconferido. Aprovação, prazo e holds são revistos
antes de cada unlink. Somente nomes explicitamente inventariados em diretórios
cadastrados podem ser removidos, usando descritores de diretório e sem recursão.
Arquivos cifrados e fontes originais permanecem. Não há comando de prune global.

`receipts/HASH-begin.json` e `HASH-result.json` são privados e exclusivos. Falha
ou interrupção após begin consome o plano; não repetir nem remover recibos para
liberar replay. Exclusão parcial deixa cópia incompleta preservada no próximo
plano; o arquivo cifrado completo continua disponível para recuperação isolada.
Se faltar resultado, inspecionar intenção, clones próprios e arquivos privados;
não supor cleanup. Não alterar fonte/manifesto/recibos para obter aceite.

O piso de sete snapshots usa verificações registradas; não comprova capacidade
atual de todas as chaves nem custódia independente. Os arquivos cifrados nunca
são removidos por esta versão. Assim, crescimento de armazenamento de arquivos
cifrados e tabelas ativas permanece fora da aplicação destrutiva: alterar essa
política exige decisão explícita e trabalho próprio, preservando append-only.
