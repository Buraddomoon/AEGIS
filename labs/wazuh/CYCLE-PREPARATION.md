# Preparação da retomada com histórico — #58

Etapa em clone **autorizada e concluída** em16/11:
[continuidade e catálogo verificados/CLEANED](../../docs/evidence/wazuh-cycle-2026-11-16/CLONE.md).
O procedimento abaixo preserva o escopo consumido, sem autorizar repetição.

Ferramentas implementadas em16/11/2026 para os bloqueadores de software da#7.
Não constituem ensaio concluído ou autorização de acesso aos volumes.

## Comportamento entregue

- `wazuh_cycle_scope.py` compila nove serviços, sem `migrate`/`controller`,
  dependência da migração, build ou pull implícitos. Exige sete IDs de imagens
  e nove volumes originais externos. Somente os arquivos individuais de PKI
  mudam de mount; política, client.keys, senhas e IDs ficam na origem.
- `wazuh_cycle_prepare.py` prepara/revalida pacote privado de Compose/PKI.
  Confere certificados/pares/validade, fonte, imagens locais e renderização.
  A inspeção existente aceita o perfil integrado explícito e confere IDs
  efetivos das imagens, ID de revisão e novos mounts. O perfil histórico de
  dez serviços permanece separado e coberto por regressão.
- `wazuh_cycle_continuity.py` compila o probe do volume fixo Wazuh journal,
  RO/nocopy, sem rede, UID10001, rootFS RO,192MiB e tmpfs privado. Reutiliza o
  leitor/decoder existente e compara identidade/descriptor/inventários completos
  com provas PostgreSQL independentes. A receita Linux permanece fechada.
- `wazuh_cycle_catalog.py` prepara plano read-only sobre b7, técnicas legadas
  idênticas ao snapshot distribuído e trabalho ocioso. Aplicação explícita sob
  locks revalida o plano e preserva tabelas antigas, contas e auditoria anterior.
  Acrescenta somente uma release, um estado e auditoria de bootstrap; sem seed
  geral, abertura de conexão, startup ou commit automático.
- `wazuh_cycle_assay.py` coordena uma tentativa sobre histórico conhecido.
  Confere IDs/hashes dos detalhes antigos, intent preservado, perfil, versão do
  ambiente e escopo. Exige administrador ativo distinto do operador, aprovação
  de dois minutos e duração até120s. Intenções duráveis precedem autorização,
  campanha, solicitação e o único start. Mesmo pacote não pode ser reutilizado,
  inclusive após falha anterior ao start. Resposta ambígua preserva acesso à
  recuperação; estado terminal sem prova física de cleanup não permite fechá-lo.

Todos esses módulos ficam em `scripts/`. Catálogo, continuidade e tentativa são
primitivas internas, sem CLI de ativação. O coordenador nativo deve conferir
volume/imagem físicos, continuidade e aprovação específica. O callback `recheck`
recebe etapa/runID e verifica os gates reais, admitindo somente o próprio run
pendente antes do start. Um checklist JSON de fixture não é autorização.
A API mantém RBAC, CSRF, escopo/aprovação/reserva transacionais independentes.

## Pacote privado de PKI/Compose

Usar candidatos **novos e separados**, com as ferramentas existentes de
transição `runner_pki.py prepare --migrate-wazuh-network` e
`wazuh_pki.py prepare --migrate-wazuh-network`. Preservar origem/IDs e fornecer
os hashes públicos revisados. Não usar `prepare_wazuh_lab.py` para recriar a
origem ausente neste checkout nem gerar material expirante enquanto faltar RAM
para uma proposta operacional pronta.

O JSON privado de imagens tem exatamente as chaves `application`, `runner`,
`postgres`, `redis`, `indexer`, `manager`, `agent`, com IDs `sha256:` revisados
em [CYCLE-ASSAY](CYCLE-ASSAY.md). Exemplo com placeholders, sem executar literalmente:

```text
.venv/bin/python scripts/wazuh_cycle_prepare.py prepare \
  --source ORIGEM --runner-candidate CANDIDATO_RUNNER \
  --runner-sha256 SHA_RUNNER --service-candidate CANDIDATO_SERVICOS \
  --services-sha256 SHA_SERVICOS --images IMAGENS_JSON_PRIVADO \
  --output-root DIRETORIO_PRIVADO
.venv/bin/python scripts/wazuh_cycle_prepare.py recheck \
  --package CAMINHO_RETORNADO --expected-sha256 SHA_RETORNADO
```

`compose.json` contém credenciais existentes: somente diretório0700/arquivo0600,
fora do Git. A CLI imprime caminhos/hashes/gates, sem config ou diagnóstico
privado. Fontes/candidatos/pacote não podem se sobrepor. Plano parcial, fonte,
imagem, Compose ou certificado alterado/expirado recusam a rechecagem. Não
inicia serviços nem comprova continuidade física, recursos ou autorização.

## Próxima etapa nativa proposta: continuidade e catálogo em clone

**Executada e encerrada sob autorização específica**, conforme o relatório acima.
Etapa pequena e sequencial, independente
do piso de8GiB do integrado; escopo revisável para aprovação específica:

1. Conferir metadados/zero consumidores dos nove volumes e imagens locais por
   ID. PostgreSQL17 `sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24`;
   cópia `sha256:b5ae5340f417ef3fce7ce25f8ec07d2dd92545b3a34d6db1982ac37fb108c593`;
   aplicação `sha256:64112646c663933a81a3777adbac03ea439ee6ae923a74418996d8d370fba0fe`;
   runner `sha256:0440049a28cb8799d350d1a646f470e6eed26cc0893384ab6cc211050cfaba54`.
   Ausência/drift interrompe; sem pull/build implícito.
2. Criar intenção exclusiva nova; copiar a frio o PostgreSQL original b7/33
   por mountRO/nocopy para backup/cópia de trabalho novos. Conferir hashes e
   origem antes/depois; preservar backups/clones anteriores. Iniciar somente
   a cópia isolada, PG384MiB, sem porta publicada/rede externa/API/worker.
   Helper SQL até256MiB; senha só por stdin/arquivo privado, nunca argv/saída.
3. Coletar provas read-only de binding/dispatch/cleanup com os leitores
   existentes e conferir IDs/schema/grants/histórico. Probe do journal original
   somente RO/nocopy,192MiB, sem runner; comparar antes/depois. Ler o log de
   observação RO, helper até128MiB, sem iniciar observador/agente; conferir
   identidade/hashes históricos e limite existente de1MiB.
4. Preparar o plano do catálogo na cópia. Somente se projeção idêntica e estado
   ocioso, demonstrar adoção **apenas no clone**. Comparar todas as tabelas e
   verificadores; reter plano/hash/recibo para revisão antes de aplicar no original.
5. Encerrar só os recursos novos próprios e confirmar zero consumidores. Reter
   backups/clones/PKI/journal/recibos. Resposta ambígua exige reconciliação da
   operação, sem repetir cópia/startup para obter aceite.

Pico configurado proposto PG384MiB+helper256MiB, probes sequenciais. Limites não
são reserva de RAM. Sem SQL de escrita no original, migração, novas contas,
binding/ativação PKI, Wazuh, runner/observador, marcador ou UI. Aplicar catálogo
original exige revisar o plano efetivamente obtido, sob autorização própria.

Depois dessa preparação, restam RAM suficiente, PKI vigente e revisão do
runtime/ACL/regra/agente/observador sob pacote específico. #59 e #60 dependem
desses gates; ferramentas/fixtures não são evidência nativa.

### Adoção no banco original — proposta separada, ainda não autorizada

Plano host-only `4b058e1a6f194fb1a76d37117fbb7520`, SHA256
`e52f0d0e5d1fcf588c4c46b47d3c38a3957000e7b40b54b416c44f5833fb727a`,
em `.local/wazuh-original-catalog`. Usa a proposta obtida no clone
`b3f12e604b450b4fe4032677897095f71bb2d39f50bbce58d0ca069882a5e26a`.
Operador/helper preparados, compilados e revisados; nenhum efeito executado.

Exigir hash físico2c19f3ed completo do relatório tanto no original quanto no
novo backup frio retido, mesmo inventário lógico b04c7c04 e helpers/imagens
fixados. Iniciar somente PostgreSQL original384MiB, sem porta publicada/rede
externa, mais helper256MiB no namespace privado. Aplicar uma vez o plano exato
de catálogo: uma release, um estado e uma auditoria, preservando linhas antigas,
verificadores, schema e grants. Intenção durável antes dos efeitos; interromper
em drift, sem seed ou migração. Encerrar banco/helper, conservar backup/clones/
recibos e conferir zero consumidores. A mudança física do original é esperada.
Não autoriza novas contas, binding, PKI, Wazuh/runner/observador ou marcador.
Resposta ambígua exige reconciliação, sem aplicar novamente ou restaurar original.

## Verificações executadas

`make test-wazuh-cycle`: **46 passaram**, incluindo API/PostgreSQL reais de teste,
PKI temporária, renderização Compose e SQLite privado. Sem Wazuh nativo ou volumes
originais. Regressões sequenciais: `make test-wazuh`60; preparação114+96.
Conjuntos se sobrepõem; aviso conhecido Starlette/httpx. `make lint` completo
passou. Testes não executam o procedimento proposto acima. Commits/checks/CI e
sincronização nos comentários de#58/#7 e no
[checkpoint](../../docs/development/wazuh-cycle-checkpoint.md).
