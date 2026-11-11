# Coordenador nativo de rotação Linux

Implementação da #49, com CLI host-only `scripts/runner_rotation.py` e helpers
fechados em `aegis.lab_runner.rotation_probe`. Validada com daemon simulado,
PostgreSQL/SQLite descartáveis e cliente TLS de fixture; **não executada sobre o
Lab original**. Testes não autorizam a intervenção nem comprovam runtime nativo.

O plano de metadados existente mantém seu formato/perfil e não ganha poderes
retroativos. Um pacote separado `aegis-native-rotation-package/3` fixa o hash do
plano original, perfil executável, build revisado, origem PostgreSQL, evidência
do clone, administrador e dados de registro. Precisa de aprovação específica do
seu hash. Hash é integridade relativa ao pin, não assinatura ou serviço de aprovação.

## Gates anteriores à execução

- Main limpa e fonte atual; imagens locais por ID. Runner deve ter build/receipt
  de fonte e dependências seladas revisados. PostgreSQL exige recibo de origem
  oficial e correspondência local. Não há pull/build implícito.
- Plano base vigente, PKI candidata atual/verificada e fonte antiga preservada.
  Pacotes/planos antigos não são rehashados para autorizar esta operação.
- Evidência revisada da #48: backup/restore/upgrade em clone do volume original,
  inventário antigo preservado e grants verificados. `prepare` recusa ausência ou
  hash/volume/perfil divergente. O objeto de evidência não produz um backup por
  preencher flags: deve ser derivado e revisado a partir do procedimento real.
- **Banco alvo d4465b7aca2a**, com perfil fechado `linux-native-pki-rotation/3`. Os cinco
  helpers usam somente as 27 relações históricas e conferem esse conjunto antes do binding;
  qualquer conjunto diferente recusa este perfil. A compatibilidade vale
  apenas para esses entrypoints administrativos, sem API normal ou worker.
  O clone comprova separadamente restore/upgrade b7; o original permanece d446.
  Não há migração, seed ou bootstrap implícitos. Os pacotes v1/b7 e v2/a0 ficam disponíveis
  somente para cleanup histórico, sem conversão ou nova autorização.
- Laboratório original revogado, nenhuma reserva/pai/filho/cleanup pendente,
  histórico íntegro completo e diário sem ambiguidade. Falha mantém quarentena.

Formato fechado da evidência do clone, sem credenciais ou conteúdo SQL:

```json
{
  "format": "aegis-linux-schema-clone-evidence/1",
  "source_volume_sha256": "HASH_CANONICO_DOS_METADADOS_DO_VOLUME_FIXADO",
  "source_schema": "d4465b7aca2a",
  "clone_schema": "b7f3c2d91a06",
  "backup_sha256": "HASH_REAL_DO_BACKUP_PRIVADO",
  "restored_inventory_sha256": "HASH_REAL_DO_INVENTARIO_ANTIGO_RESTAURADO",
  "upgraded_old_inventory_sha256": "MESMO_HASH_APOS_UPGRADE_ADITIVO",
  "clone_restore_verified": true,
  "old_rows_preserved": true,
  "grants_verified": true,
  "original_modified": false
}
```

Esse documento e seu hash esperado independente permanecem privados. Não criar
um recibo sintético para liberar `prepare`. A prova real da #48 foi obtida no ensaio de clone documentado em
[compatibilidade](linux-schema-compatibility.md). Flags de fixture não são evidência nativa.

## Sequência fixa

1. Registrar begin, confirmação do pacote/prazo e fence exclusivo/fsync antes de
   create. Hash e prazo originais não mudam ao reconstruir confirmação. Plano
   consumido/pedido parcial não permite retry, nem criando outra operação.
2. Conferir duas observações de inventário/ownership/consumidores, fonte/PKI,
   imagens e subnet/rotas. Criar somente bridge interna192.168.253.0/29 em modo
   isolated, sem portas host, IPv6 ou conexão com qasrc.
3. PostgreSQL próprio usa volume exato, UID70, rootfs RO, HBA fechado montado RO,
   TCP somente127.0.0.1 e limites fixos. O servidor usa a rede isolada em.4, mas
   SQL é acessível apenas pelos helpers que compartilham seu namespace de rede.
   Nenhuma API, Redis, worker ou serviço de migração é iniciado.
4. Helper `review-before`: SQL READ ONLY e duas revisões WAL-aware do diário RO,
   em UID10001, sem copiar/mudar origem. Resultado privado fixa todas as provas.
5. Primeiro runner normal em.2, UID10001, PKI nova por secrets individuais RO,
   diário original preservado e workspace tmpfs. Helper `identity-before` faz
   GET de identidade mTLS, conferindo IDs/allowlist, e controle TLS separado usando
   a CA anterior com o cliente candidato. Só erro de construção da cadeia/issuer
   prova a recusa desse trust: expiração, EOF e falha de transporte não bastam e
   bloqueiam o binding. A CA antiga pública é montada separadamente somente nesse
   helper; não integra a confiança positiva. Remover esse runner
   e comprovar ausência antes de reler o diário; nenhum job/marker é solicitado.
6. Helper `binding`: reconferir SQL/diário, comparar baseline inteiro e registrar
   novo vínculo sob lock, com autorização revogada e versão+1. Intenção/start do
   helper já foram fsyncados antes de qualquer commit. Confirmação ambígua não
   dispara retry nem rollback do vínculo já confirmado.
7. Segundo runner, em **outro papel de ownership**, uma única criação/start;
   helper `preflight` persiste verificação atual e mantém revogação. Os dois
   starts são etapas distintas fixadas no pacote, não retry de um mesmo efeito.
8. Remover segundo runner antes de `review-after`. Conferir novamente SQL/diário
   e permitir somente versão/descritor novos, preservando provas históricas.
9. `finally`: cleanup por IDs/labels próprios, helpers→runners→DB→bridge. Pai
   permanece se dependente incerto. Sem force, remoção de volume, expurgo ou
   adoção por prefixo. Conferência final exige projeto vazio, volumes/imagens
   iguais aos pins e ausência real de cada recurso criado.

Os helpers não recebem comandos, SQL, URL, paths ou destinos arbitrários; modo
vem da receita fixa. Senha SQL entra somente em stdin privado, fora de argv/env/
hash público. Respostas/erros não expõem senha, chaves ou erro SQL bruto. Bundles
de histórico são capturados apenas em diretório privado0700/arquivos0600.

Cada create/start exige gate recente computado por código, hash da receita,
ownership/mounts efetivos e configurados, namespace, UID, limites e projeto/volume
sem consumidores extras. O gate não é JSON positivo vindo de API. CLI Docker usa
socket local/config vazia/ambiente mínimo; consultas e efeitos compartilham prazo
monotônico/UTC. Efeitos até begin+230s, cleanup reservado até begin+300s.
Readiness é sondagem limitada do listener, sem repetir create/start.

## Comandos explícitos

`runner_rotation.py prepare --help`, `run --help` e `cleanup --help` não iniciam
recursos. `prepare` recebe arquivo privado com campos fechados `build_inputs`,
`postgres_origin`, `clone_evidence`, `clone_sha256`, `actor_id`, `registration`.
Usar `make runner-rotation-prepare` só após obter os pins reais. Não há modo de
ignorar backup, PKI, schema, provenance, intenção ou autorização do pacote.

Após aprovação específica do pacote, `run` requer hash esperado, hash aprovado e
`--confirm-native-rotation`. Entrada stdin privada: objeto contendo exclusivamente
`database_password`, com o segredo runtime existente. Não usar segredo em variável
Make, argumento, terminal/log ou arquivo rastreado. Não invocar o target run em
CI, testes, startup, retomada de conversa ou como consequência de um commit.

Cleanup posterior usa `--operation-id` e `--begin-sha256`, verifica cadeia durável,
pacote/plano históricos e imagens originais, sem ler senha ou exigir PKI vigente.
Não reconstrói autorização de efeitos e não retoma fases. Presença incerta retém
intent/dependências; não remover arquivos para liberar nova tentativa.

O recibo registra a fase da falha sem erro SQL/segredo bruto. Só afirma
`activation_verified=true` após todas as fases,
preflight, continuidade e fechamento comprovados na execução. Sempre mantém
normal_operation_permitted/marker_executed/worker_started/volumes_removed false.
Handshake não é detecção; este ensaio não libera campanha ou operação normal.
O cliente antigo não é testado com sua chave privada original; o recibo mantém
previous_client_rejection_verified e all_tls_controls_verified **false**, inclusive
no caso positivo. Não converter essa limitação ou o EOF histórico da #3 em prova.

[Preparação/autorizações pendentes](../../labs/linux/ACTIVATION-ASSAY.md) ·
[Compatibilidade/clone](linux-schema-compatibility.md).
