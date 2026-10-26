# Backups Demo criptografados

Ferramenta operacional **somente no host**, usando age v1/X25519 pelo pyrage.
Não há upload, endpoint de restore ou alteração no banco em uso. Os comandos
completam o [backup consistente e restore offline](backup-recovery.md).
Contratos no [ADR0016](../architecture/decisions/0016-encrypted-demo-backups.md).

## Preparar e gerar uma identidade

```bash
make backup-tools          # wheel fixado por hash; já incluído em make setup
make backup-keygen
```

A saída apresenta `key_id`, destinatário **público** `age1...` e caminho da
identidade privada. A chave nunca aparece na saída, em argumentos ou recibos.
Arquivos `.local/backup-keys/<key_id>.agekey` têm0600, diretórios0700, e pertencem
ao operador. Não guardar a chave em Git, `.env`, tickets, imagens ou junto à
cópia enviada a terceiros. O scanner staged também recusa arquivos `.agekey`,
`.age` e o padrão de identidade age; Git/Docker ignoram esses artefatos.

A identidade inicial é um segredo aleatório próprio, sem senha de proteção.
Não é a senha do site nem interfere nas contas da aplicação. Sem essa identidade
não há recuperação do ciphertext; o destinatário público não a substitui.
Para guarda independente, o responsável deve escolher um dispositivo/local
seguro separado e controlar suas permissões. A ferramenta não exporta nem envia
chaves automaticamente. Não apagar a identidade antiga ao gerar outra: cópias
anteriores continuam precisando da chave original. A rotação nesta versão é
manual: gerar identidade nova, selar novamente e verificar, preservando originais.

## Selar um backup existente

```bash
make backup-demo
make seal-backup BACKUP_ID=ID_DO_BACKUP RECIPIENT=DESTINATARIO_PUBLICO
```

Pode-se usar destinatário público de outra máquina. Somente X25519 `age1...`:
sem plugins, SSH, senha ou comandos externos. `seal` valida o backup local,
limita manifesto4MiB/conteúdo1GiB e processa o dump em streaming. O formato
externo é age; o conteúdo interno AEGIS possui prefixo versionado, comprimento
do manifesto e dump restante. Não envolve tar, paths importados ou descompressão.

Cada cópia tem ID exclusivo em `.local/backup-vault/<sealed_id>/`:

- `bundle.age`: manifesto e dump cifrados, preservando os bytes originais.
- `envelope.json`: publicação concluída, ID, destinatário público, instante,
  bytes e SHA256 do ciphertext. Não contém manifesto, linhas ou chave.
- `verification-<uuid>.json`: somente depois de verificar decriptação,
  restauração, inventário e cleanup.

`sealed_not_yet_verified` descreve a criação. O envelope permanece imutável com
esse estado; verificações posteriores acrescentam recibos, sem reescrevê-lo.
Uma falha pode deixar diretório/`bundle.age.partial` privados, sem envelope de
sucesso. Não remover originais para resolver uma falha ou simular criptografia
dos backups antigos.

**Guarde o SHA256 retornado num registro confiável independente da cópia.**
O hash detecta troca apenas quando sua referência é confiável. age autentica a
integridade do conteúdo, mas não identifica seu remetente: qualquer pessoa com
a chave pública pode cifrar outro arquivo para você. Não restaurar uma cópia de
origem desconhecida, mesmo se decripta; `pg_restore` executa SQL.

## Verificar diretamente a cópia cifrada

```bash
make verify-sealed-backup SEALED_ID=ID_SELADO \
  CIPHERTEXT_SHA256=SHA256_GUARDADO KEY_ID=ID_DA_CHAVE
```

O comando não usa `DATABASE_URL`, banco fonte ou dump original como fallback.
Precisa do Docker Unix local e da mesma imagem PostgreSQL17 por ID já presente,
sem pull. A configuração da aplicação existente não é modificada.

1. Confere paths, permissões, ownership, tamanhos, ID/envelope e hash esperado.
   Symlinks em componentes, hardlinks e arquivos especiais são recusados.
2. Decripta em scratch privado limitado, verificando também o SHA256/tamanho dos
   **bytes efetivamente consumidos**. Isso recusa uma substituição válida durante
   a leitura, além de corrupção, truncamento, dados extras e chave errada.
3. Somente após autenticar o stream completo materializa os dois nomes fixos em
   `.local/backup-vault-work/verify-...`. Valida o mesmo manifesto/hash/inventário
   do backup normal. Nenhum conteúdo parcial é entregue ao PostgreSQL.
4. Usa o restore existente: clone próprio, `network=none`, tmpfs, sem portas,
   volumes persistentes, aplicação, worker, Redis ou SIEM. Compara inventário,
   estrutura, hashes e revisão. Não restaura no banco da aplicação.
5. Remove clone e staging privado. Só então publica recibo durável no diretório
   cifrado. Falha de restore, comparação ou cleanup não emite sucesso.

A cópia em claro original pode estar indisponível; a recuperação usa somente
ciphertext, chave e imagem PostgreSQL compatível. Backups/configurações antigos
continuam sujeitos às guardas de schema/imagem dos ADRs de recuperação. Este
comando testa dados, sem boot da API, reconciliação, novo ciclo ou cutover.

## Retenção e falhas

```bash
make backup-vault-plan       # somente leitura: cópias cifradas e chaves locais
make backup-retention-plan   # somente leitura: arquivos originais
```

O inventário cifrado confere integridade, registra recibos vinculados ao mesmo
ciphertext e compara destinatários com identidades locais válidas. `key_present_locally`
é uma observação local; `verification_recorded` é registro histórico editável,
sem assinatura ou garantia de que uma nova restauração passará.

A política mantém os sete snapshots **distintos, verificados e com chave local**
mais recentes, e todos com até30dias. Re-selagem não verificada não muda a data
usada para ordenar cópias boas. Sem recibo, sem chave ou com cópia incompleta:
`keep`. Outros antigos podem receber `review_only`; nenhuma exclusão é executada.
O plano é limitado a1024diretórios,256chaves e256recibos por cópia, recusando
inventário maior em vez de retornar uma visão silenciosamente parcial.

Não há exclusão automática, envio externo, alteração de imagens ou remoção de
journals/volumes Linux/Wazuh. A revisão manual deve considerar retenção própria,
necessidade de histórico e recuperação antes de qualquer autorização de exclusão.
Um recibo alterado não substitui um ensaio atual sobre uma cópia confiável.

Saída normal remove plaintext temporário; unlink não é apagamento seguro. SIGKILL,
queda do host ou falha de filesystem podem deixar staging/intents/clones. Inspecione
somente `.local/backup-vault-work` e os nomes/labels próprios de recuperação;
consulte o procedimento de cleanup em [backup-recovery](backup-recovery.md).
Não use prune, limpeza global, `down -v` ou exclusão indiscriminada de `.local`.

## O que esta entrega protege

Permite guardar/transportar uma cópia cifrada sem revelar manifesto/dump a quem
não possui a identidade. O envelope revela ID, tempo, destinatário, hash e tamanho.
O formato é interoperável com age para decriptar o conteúdo interno versionado;
o operador ainda precisa do checkout confiável para validar seu framing.

Isso não cifra o banco, filesystem, swap, dump original ou backups anteriores.
Chave e ciphertext no mesmo computador não protegem contra comprometimento do
host ou perda do disco. Nesta entrega não houve transporte externo ou teste de
custódia independente. Imagens, configuração, segredos/roles PostgreSQL, Redis,
PKI e diários de runner precisam de guarda própria; não fazem parte do pacote.
Sem promessa de RPO/RTO ou recuperação operacional entre hosts.

[Evidência local e limites](../evidence/encrypted-backups-2026-10-26/README.md).
