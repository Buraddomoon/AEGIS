# PKI de serviços Wazuh: inventário e candidato offline

Entrega #6, subissue #55. O ensaio de22/10/2026 permanece encerrado.
Este procedimento não inicia containers, abre volumes, renova a PKI do runner,
recria credenciais nem autoriza outro ensaio. Não executar novamente
`prepare_wazuh_lab.py` sobre o laboratório existente.

## Perfil suportado e inventário

Somente Wazuh4.14.9/linux/amd64 e os três digests já fixados em
[images.json](../../labs/wazuh/images.json). O perfil do comando fixa os hashes
do Compose, políticas e configurações TLS/roles. Mudança exige revisão explícita;
um inventário novo não aprova automaticamente outra versão/configuração.

| Consumidor | Identidade/trust efetivos |
|---|---|
| Indexer HTTP9200 e transporte interno | `indexer.pem`, DN `O=AEGIS Lab,OU=AEGIS,CN=wazuh.indexer`; SAN DNS `wazuh.indexer`, IP `172.30.90.2`; EKU servidor/cliente; CA pública própria |
| Filebeat no manager | `filebeat.pem`, DN `O=AEGIS Lab,OU=AEGIS,CN=aegis-filebeat`, EKU cliente; validação `full` do Indexer; login separado `aegis_ingest` |
| Coletor API/worker | CA pública e usuário `aegis_reader`, sem chave privada de serviços; CA/SNI, destino fixo e ACL continuam obrigatórios |
| Agente→manager1514/TCP | Protocolo seguro Wazuh/AES com `client.keys` pré-provisionado; não é um canal X.509 a renovar |
| API de gestão55000 | Loopback dentro do manager, fora do coletor; certificados internos do volume não são inventariados/rotacionados por esta ferramenta |

As redes antigas `172.30.89/90.0/29` conflitam com qasrc. **#149 permanece
bloqueadora de qualquer ativação.** O candidato deste perfil é apenas offline;
a transição de rede exigirá reavaliar SAN, destino e perfil antes de gerar outro
candidato. Não alterar qasrc nem aplicar este candidato para contornar a dependência.

```bash
.venv/bin/python scripts/wazuh_pki.py inspect --source /caminho/privado/wazuh-lab
```

Lê exclusivamente os três certificados públicos em `pki/`, nunca as chaves,
`lab.env`, senhas, `client.keys`, runner, banco, journals ou volumes. Valida
assinaturas/cadeia mesmo quando expirados e informa `valid_now` separadamente.
Não desativa TLS de cliente algum. O digest público não é assinatura nem autorização.

Inspeção real somente desses arquivos em12/11/2026 confirmou folhas expiradas
em23/10/2026 às18:57:22UTC e CA em28/10/2026 às18:57:22UTC. Inventário SHA256
`eb3e7008f8bc0fffcf56c7f126409c0b9d99dd6b4cc933f8a0be491550a9f85b`.
Isso não demonstra conectividade TLS atual ou conteúdo de volumes.

## Candidato separado

```bash
.venv/bin/python scripts/wazuh_pki.py prepare \
  --source /caminho/privado/wazuh-lab \
  --expected-sha256 <inventory_sha256-revisado> \
  --output-root /caminho/privado/wazuh-candidates
.venv/bin/python scripts/wazuh_pki.py verify \
  --source /caminho/privado/wazuh-lab \
  --candidate /caminho/privado/wazuh-candidates/<id> \
  --expected-sha256 <manifest_sha256-revisado>
make test-wazuh-pki
```

Diretórios0700 de propriedade do usuário; CA privada0600 e folhas/chaves de
serviços0444 para mounts individuais de leitura, como no perfil original. Nenhum
container recebe o diretório pai ou a CA privada. Candidato contém somente `pki/`
e marcador de conclusão `rotation.json`0600. RSA2048, CA7dias e folhas2dias,
chaves novas distintas, pares conferidos e pelo menos24h restantes ao verificar.
Verificação estrita de cadeia, assinatura da raiz, DN, SAN DNS/IP, EKU, constraints,
key usage e prazo da folha limitado pela CA; nenhuma trust store ambiental.

O manifesto é publicado com exclusividade/fsync depois dos artefatos. Falha deixa
o diretório parcial para revisão, sem marcador de conclusão válido. Retry produz
outro ID; não remover candidatos expirados/históricos nem sobrescrever a origem.
Symlinks, hardlinks, FIFO, permissões inseguras, material adicional e drift de
origem/candidato/configuração são recusados. Erros CLI não imprimem PEM, chaves,
credenciais ou caminhos privados. Guardar manifestos localmente, não no Git.

Testes usam PKI real em temporários, auditoria de leituras/rede em processo novo
e renderização Compose sem startup. Eles não comprovam um ensaio Wazuh nativo.
Troca/rollback: [procedimento coordenado](wazuh-pki-rotation.md); ensaio real é a #57.
