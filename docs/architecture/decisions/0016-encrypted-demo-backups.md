# ADR 0016 — Cópias Demo criptografadas e recuperação verificável

Data: 2026-10-26. Escopo: operação local no host, sem API, upload ou exclusão.

## Decisão

Usar o formato age v1 com destinatário X25519 e streaming pela biblioteca
pyrage1.4.0 (MIT, Rust age0.12.1). Dependência opcional `backup`, instalada no
ambiente de desenvolvimento para testes, ausente do lock/imagem da aplicação.
Não implementar primitivas criptográficas, plugins, SSH ou senhas de criptografia.
A identidade privada fica0600 em diretório0700 separado das cópias; encrypt usa
somente destinatário público. Geração é explícita e nunca imprime a chave.

Encapsular os bytes originais do manifesto e dump num conteúdo simples versionado:
prefixo fixo, tamanho limitado do manifesto, manifesto e restante como dump.
Sem tar, extração de paths, compressão adicional ou SQL de origem arbitrária.
Limitar manifesto4MiB e conteúdo total1GiB. Criptografia não autentica o remetente:
qualquer pessoa com destinatário público pode produzir outra cópia. Operador deve
confiar na origem e conferir SHA256 do ciphertext por registro independente.

Publicar envelope e ciphertext somente após fsync e conclusão. Artefatos em
`.local/backup-vault`, staging privado em `.local/backup-vault-work`; sem substituir
cópias existentes. Envelope contém versão, IDs, instante, destinatário público,
bytes/hash do ciphertext; não inclui manifesto, linhas ou chave privada. Criação
de cópia não equivale a decriptação ou restore verificados.

`verify-sealed` exige ID da cópia, hash esperado e ID da chave local. Autenticar
stream inteiro antes de permitir restore; recusar truncamento, alteração, chave
errada, permissões inseguras, symlinks e limites. Materializar somente os dois
arquivos fixos num diretório temporário privado, validar manifesto/dump e passar
pela mesma restauração offline do ADR0010. Sem banco fonte para essa operação,
sem fonte em claro como fallback, sem aplicação, worker ou SIEM. Recibo durável
somente após inventário e cleanup do clone; staging não persiste após saída normal.
Arquivos temporários podem existir após SIGKILL; unlink não é apagamento seguro.

Retenção permanece somente plano. Mostrar separadamente cópias seladas,
verificações, chaves locais disponíveis e pendências. Nunca considerar só um
recibo JSON como prova de posse da chave ou substituir uma verificação atual.
Nunca apagar backups originais, chaves, imagens, journals ou volumes automaticamente.

## Limites e continuidade

A mesma máquina pode guardar chave e ciphertext para desenvolvimento; isso não
protege de comprometimento do host ou perda do disco. Guarda independente da chave,
destino off-host e política de retenção operacional exigem escolha do responsável.
Nenhum envio externo é implementado ou implicitamente autorizado. Criptografar uma
cópia não cifra o dump original, filesystem, swap, banco ou backups anteriores.
Schema/imagem compatíveis seguem obrigatórios. Sem cutover, garantia RPO/RTO ou
novo ensaio Linux/Wazuh. Hash não é assinatura; metadados de envelope não são secretos.

## Fontes oficiais consultadas

- [age, formato v1.1.0](https://c2sp.org/age@v1.1.0)
- [age, implementação e licença](https://github.com/FiloSottile/age)
- [pyrage1.4.0, wheels/ABI/licença](https://pypi.org/project/pyrage/1.4.0/)
- [pyrage, código revisado do release](https://github.com/woodruffw/pyrage/tree/c2aff17ff4154df5ce066e7734aaf8e090cb9e39)

Fernet foi avaliado: a documentação oficial exige mensagem inteira em memória;
streaming age evita esse limite para dumps e mantém formato interoperável.
[Limitações Fernet](https://cryptography.io/en/latest/fernet/#limitations).
