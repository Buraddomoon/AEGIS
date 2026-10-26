# Cópia cifrada e restore offline — 2026-10-26

Backup criado a partir do Demo local, cifrado com age/X25519 e decriptado pela
ferramenta host-only. PostgreSQL real em clone próprio network=none, sem portas,
volumes persistentes, API, worker, Redis, runner ou Wazuh. Nenhuma simulação nova.
[Operação e limites](../../operations/encrypted-backups.md).

32tabelas/3.169linhas e estrutura conferidas, restore4,682s medidos; clone removido
e zero staging remanescente. Tempo de uma verificação de dados, sem garantia RTO.
O harness privado recusou chamadas ao loader do dump original e à fonte durante
a recuperação cifrada. Decriptação/restore dependeram somente de cópia/chave/
imagem PostgreSQL; banco em uso permaneceu disponível, inventário completo e
registros humanos idênticos antes/depois. Senha humana não foi usada nem alterada.
Não houve migração, reinício de API/worker ou mudança de imagem implantada.

Chave nova0600 separada em diretório0700; valor privado nunca impresso, incluído
em argumentos, evidência pública ou Git. Destinatário age é público; cópia e chave
continuam no mesmo host. Não houve transferência externa, escolha de provedor,
compra de serviço ou teste de custódia independente. Originais/backups anteriores,
imagens e journals/volumes Linux/Wazuh foram preservados. Plano retornou keep,
sem excluir nada. Recibos privados e ciphertext não foram adicionados ao Git.

Testes reais age cobrem roundtrip em streaming, chave errada, hash esperado
incorreto, alterações de cabeçalho/meio/final, truncamento, bytes extras, limites,
permissões, symlink/hardlink/FIFO e publicação exclusiva. Regressão substitui um
ciphertext válido in-place após a pré-checagem e exige recusa antes de unpack.
Guardas Docker de CLI continuam cobertas por mocks; não são outra evidência de
runtime. Novo comando usa a mesma engine que este restore real exercitou.

Revisão especializada encontrou corrida hash/leitura e influência de re-selagem
não verificada na retenção; corrigidas, testadas e conferidas por inspeção.
[Revisão](../../security/review-encrypted-backups-2026-10-26.md).
Primeira suíte completa:712Python/53frontend; dois casos posteriores ampliaram
a suíte específica para21vault, todos passaram. Rodada final/CI no PROGRESS.
Lint/tipos/build e auditoria runtime+extra passaram; advisory transitivo DiskCache
revisado permanece visível. E2E navegador não repetido nesta entrega host-only:
sem mudança na UI/API/worker, capturas anteriores permanecem reais.

Resumo curado, sem chave ou conteúdo de linhas:

```json
{
  "format": "aegis-encrypted-backup-proof/1",
  "status": "passed",
  "backup_id": "20261026T164137Z-9c0d7d0bebc54d8cb25a5898d96acafc",
  "dump_sha256": "30e1e84387b0b1da4ce2becc756ed3b1d3ed6bd2345bcea195bf05a951500af5",
  "sealed_id": "20261026T164137Z-9c0d7d0bebc54d8cb25a5898d96acafc-68e8fae04ce140d79036d6d3e101cf80",
  "ciphertext_sha256": "fe8a7491de6d5d2aefb746f5663ec529f59f5d6f06b1d98b34b5bf04c3259f52",
  "ciphertext_bytes": 1318864,
  "recovery": {
    "application_started": false,
    "backup_id": "20261026T164137Z-9c0d7d0bebc54d8cb25a5898d96acafc",
    "clone_removed": true,
    "dump_sha256": "30e1e84387b0b1da4ce2becc756ed3b1d3ed6bd2345bcea195bf05a951500af5",
    "elapsed_seconds": 4.682,
    "format": "aegis-demo-backup/1",
    "inventory_format": "aegis-pg-inventory/2",
    "limitations": [
      "No failover or application restart tested",
      "No RPO/RTO guarantee",
      "No roles, secrets, Redis or runner journals backed up"
    ],
    "network": "none",
    "rows": 3169,
    "status": "verified",
    "structure_comparison": "pg17-literal-array-casts/1",
    "tables": 32,
    "verified_at": "2026-10-26T16:41:42.418676+00:00"
  },
  "source_inventory_unchanged": true,
  "source_tables": 32,
  "source_rows": 3169,
  "human_user_records_unchanged": true,
  "plain_source_fallback_disabled": true,
  "private_staging_remaining": 0,
  "verification_recorded": true,
  "retention_action": "keep",
  "deletion_performed": false,
  "off_host_transfer_performed": false,
  "external_lab_or_siem_accessed": false,
  "api_healthy": true,
  "limitations": [
    "Local key and ciphertext only; no off-host copy or independent key custody tested",
    "Original plaintext backups are preserved, not encrypted or erased",
    "No cutover, application boot, roles, secrets or RPO/RTO guarantee"
  ]
}
```

Hash não é assinatura; o expected SHA deve vir de registro confiável independente.
Public-key encryption não autentica remetente e pg_restore executa SQL: não
restaurar arquivos de origem desconhecida. Manifesto/dump cifrados não incluem
roles, configuração, imagens, segredos, Redis ou diários de runner. Guarda externa,
cutover e recuperação operacional entre hosts continuam pendentes.
