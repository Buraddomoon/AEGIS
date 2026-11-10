# Certificados mTLS do runner — preparação offline

As ferramentas inspecionam material público e criam um candidato separado para
revisão. Não aplicam a troca, não escrevem no banco/diário, não montam volumes e
não iniciam containers ou jobs. O Demo em uso não utiliza essa PKI e não precisa
reiniciar. Os ensaios Linux/Wazuh anteriores continuam encerrados/autorização consumida.

## O que esta etapa entrega

- Inventário dos quatro certificados e do connection.json, com fingerprints,
  SPKIs públicos, validade UTC, IDs/URL e hash do descritor do backend.
- Candidato com duas CAs novas e quatro chaves novas/distintas, preservando IDs
  e nomes dos secrets. Renovação comum conserva endpoint; a transição explícita
  move apenas o runner Linux legado para `192.168.253.2`. Nenhuma chave privada
  antiga é lida/reutilizada.
- Validação OpenSSL de assinaturas/cadeias, constraints, EKU, SAN/IP/CN, curvaP-256,
  pares privados/públicos e validade. Não há consulta a CA/OCSP/CRL externos.
- Manifesto privado, canônico/hash, publicação após flush/fsync e verificação
  explícita de drift do material. Nenhum recibo concede operação normal.

A mesma ferramenta aceita PKI do Linux legado172.30.88.2, do runner atual
192.168.253.2 ou do runner no overlay Wazuh172.30.89.2. **Não rotaciona
certificados do Indexer, manager,
agente ou Filebeat**, senhas de integração ou PKI de outros serviços.

## Requisitos e comandos

Linux, ambiente Python de desenvolvimento instalado e `/usr/bin/openssl`3.x.
Não requer Docker, banco, Redis, Wazuh ou rede. O executável usa ambiente mínimo,
sem overrides OPENSSL_CONF/OPENSSL_MODULES/proxies do usuário, preservando a
configuração/política padrão do OpenSSL do sistema. Não instalar provedores ou
contornar a política do host para executar os comandos.

Primeiro inspecione somente a origem existente:

```bash
make runner-pki-inspect PKI_SOURCE=.local/linux-lab
# Runner do overlay Wazuh, sem acessar o SIEM:
make runner-pki-inspect PKI_SOURCE=.local/wazuh-lab/runner
```

`status=public_inventory_only` não significa que os certificados são atuais.
`valid_now` informa cada CA/folha separadamente. Cadeia/identidade/uso continuam
sendo verificados; somente nessa inspeção de certificados antigos a validade
cronológica é ignorada no OpenSSL. Data expirada ou futura permanece explícita.
O resultado não atesta posse de chave antiga, estado do runner ou volume correto.

Revise IDs/URL/certificados e guarde o `inventory_sha256`. Depois:

```bash
make runner-pki-prepare PKI_SOURCE=.local/linux-lab PKI_SHA256=HASH_DO_INVENTARIO
# Retorna candidate_path e manifest_sha256, nunca uma chave privada.
make runner-pki-transition PKI_SOURCE=.local/linux-lab PKI_SHA256=HASH_DO_INVENTARIO
# Somente transição explícita legacy Linux .2 → 192.168.253.2; ainda offline.
make runner-pki-verify PKI_SOURCE=.local/linux-lab \
  PKI_CANDIDATE=.local/pki-candidates/ID_RETORNADO PKI_SHA256=HASH_DO_MANIFESTO
```

Equivalentes sem Make: `.venv/bin/python scripts/runner_pki.py inspect|prepare|verify`,
com `--source`, `--expected-sha256` e `--candidate` conforme `--help`. Prepare aceita
`--output-root`, sempre área privada separada da origem; não aceita path com
interpolação/espaços/quebra de linha para arquivo Compose env. Não existe apply/up/smoke.

Hashes são SHA256 do JSON **canônico**, não de whitespace do arquivo: use o valor
emitido pelo comando, não `sha256sum rotation.json`. Guarde o hash esperado por
registro independente confiável. Hash não é assinatura nem prova quem gerou a PKI.
Não publicar material de chave, copiar a pasta inteira para o Git ou transportar
para outro host como se a custódia externa já estivesse resolvida.

## Arquivos, validade e falhas

Origem: somente cinco nomes públicos fixos são lidos. ids.env, chaves antigas,
SQLite/journal e recibos não são abertos nem copiados. A origem permanece intacta.
Symlinks, hardlinks, FIFO, tamanho excessivo, owner/permissões inseguros ou config
não revisada fazem a operação falhar sem correção automática.

Destino: diretório0700 próprio com ID novo; nunca sobrescrever candidato anterior.
Folhas e chaves de folhas usam0444 para bind secrets lidos pelo UID10001, protegidos
pelo pai0700 no host; chaves das CAs e manifesto0600. Não montar diretório inteiro
nem as chaves das CAs na aplicação. `.key` é ignorado por Git/Docker e recusado no
scanner, além da proteção de `.local` e dos padrões de conteúdo.

CAs7dias/folhas2dias; verify exige tempo atual válido e pelo menos24h restantes,
sem folha ultrapassar a CA. Um candidato antigo pode deixar de ser verificável;
gere outro sem apagar o anterior. Um recibo de hoje não garante validade futura.
Nenhum comando renova certificados no lugar ou prolonga trust automaticamente.

Falhas não produzem sucesso. Podem deixar material privado incompleto, inclusive
um manifesto após erro final de durabilidade: não inferir prontidão pela presença
isolada do arquivo. Inspecione/reverifique o candidato; não reaproveite resíduos
para iniciar laboratório. A ferramenta não limpa arquivos automaticamente.

`verify` compara a origem novamente e os certificados/pares reais do candidato,
ambiente Compose derivado e hashes. Reescrever o manifesto e apresentar outro
hash não substitui validação do material. Usuário/root do host pode ler/alterar
chaves/receipts; não há cofre externo, revogação de certificados ou garantia contra
comprometimento do host.

## O que uma futura ativação ainda precisa

A preparação não autoriza ligar o laboratório ou substituir secrets ativos.
Antes de uma ativação sob escopo próprio:

1. Conferir autorização do escopo, laboratório revogado e estado de reservas/jobs.
   Um efeito ambíguo mantém quarentena: resolver no runner original sem start/replay,
   sem apagar journal ou editar a reserva para obter acesso.
2. Preservar os mesmos IDs e o volume/diário original. O candidato não inspeciona
   nem prova a integridade desse volume; uma identidade igual não prova fences intactos.
3. Verificar novamente validade/hash e planejar a troca dos dois lados do mTLS.
   Confiança ou cliente antigos devem falhar; não desabilitar TLS para completar a troca.
4. Revisar o novo descritor/binding, versão do ambiente e preflight mTLS/isolamento.
   O novo server CA/client cert muda o hash e invalida binding/preflight/scopes antigos.
5. Obter nova autorização de laboratório/solicitação/aprovação quando cabível.
   Aprovação histórica e ensaio anterior não se tornam válidos por trocar certificado.

Recuperação automática de jobs sob certificado/binding antigo, ativação coordenada,
rotação da PKI Wazuh e validação num laboratório em execução continuam pendentes.
[Revisão persistida de bloqueios](linux-binding-review.md) já implementada na
API/UI; [plano coordenado](runner-pki-activation.md) explicita arquivos, volumes e
interrupções. Ambos preservam a exigência de novo escopo para iniciar o lab.
[Recuperação Linux](../../labs/linux/README.md#recuperação-e-rotação) ·
[ADR0018](../architecture/decisions/0018-offline-runner-pki.md).

## Testes

`make test-runner-pki` gera/verifica material real em temporários, incluindo drift,
limites/arquivos inseguros e falhas; faz handshake TLS de echo apenas em loopback,
sem runner, API, journal ou marcador. Esse teste não é evidência de ativação do lab.
A suíte completa inclui os casos. Não é necessário repetir Linux/Wazuh ou instalar
ferramentas ofensivas para validar a preparação.
