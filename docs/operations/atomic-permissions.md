# Atomic de permissões — implementação #79 e bloqueio do ensaio #80

Esta receita documenta a capacidade implementada e os pré-requisitos do ensaio.
Não é pacote autorizado para executar. Nenhum Lab original foi iniciado,
migrado, reconfigurado ou usado para comprovar esta entrega.

## Perfil fixado

O [dossiê #78](../integrations/atomic-permissions-review.md) define o único GUID,
fonte oficial, licença, efeitos e incompatibilidades. A revisão de implementação
é `aegis-atomic-review/1`, SHA256
`9e283889776cbd42ebf9b7b25bc1ebfbad452157398ecbe0ab77415136c35673`.
Programa próprio `permissions_program.py`, SHA256
`b645e702a86155857eea13e44866b4fb76c289eda670af07ca639936b9356838`.
O identificador do protocolo é `atomic-file-permissions/v1@` seguido do hash
da revisão. Mudar GUID, commit/hash, modos, programa ou versão exige outra
identidade/revisão; não existe atualização/download no startup.

A definição própria `atomic-file-permissions-v1` usa o transporte existente
`execution_kind=linux_marker`. Esse campo identifica o transporte de arquivo
fixo do runner; o comportamento é `owned-file-permissions` e a associação
T1222.002 exige observar a mudança0400→0600, além da criação do arquivo.
Não existe engine de comandos ou novo tipo de fila. O seed explícito pode
acrescentar essa definição revisada a um banco compatível; nenhum seed/migration
é disparado por startup ou importação Atomic. Não se alterou o schema.

Os registros importados do catálogo permanecem `approved=false` e
`executable=false`, inclusive para o mesmo GUID/hash já revisado no código.
Revisão de metadados não modifica allowlist, configuração ou binding.

## Configuração e efeitos

O runner precisa ser configurado explicitamente com `AEGIS_RUNNER_TEST_ID`
igual ao identificador completo acima. O arquivo privado de conexão da
API/worker precisa de `test_id` idêntico. Ausência desses opt-ins preserva o
perfil `linux-file-marker/v1`; seu JSON de identidade/spec/recibo não ganhou
campos nem teve histórico reescrito. O cliente exige uma allowlist de exatamente
um teste correspondente ao perfil; não negocia/testa coleções inteiras.

O novo perfil precisa de **estado/workspace próprios e identidade nova**.
O fence de identidade recusa reutilizar o journal histórico de marcador.
O binding inclui revisão completa/hash de programa, certificados públicos e
IDs; exige revisão administrativa, preflight vigente, autorização explícita do
lab e aprovação por outro administrador ativo. Campanhas mistas, outro teste,
Demo, inputs livres, revisão/definição/configuração alteradas são recusados.

O worker persiste dispatch antes da RPC; o runner persiste RUNNING antes de
criar diretório/processo. Executa somente bytes próprios cujo hash foi conferido,
em Python `-I -S`, sem shell e sem reabrir um path depois da conferência do código.
UID0 é recusado antes do efeito. Recursos, PDEATHSIG, lease2s e efeito máximo5s
permanecem supervisionados. Não há alteração de ACL, ownership, sysctl ou rede.

Efeito máximo por job: diretório UUID0700, `proof.marker` de43bytes criado
exclusivamente em0400, `fchmod` para0600 e `receipt.json`. O recibo inclui modos
observados antes/depois, IDs, hash de escopo e conteúdo, tempos e test_id da revisão.
O supervisor confere hash/conteúdo43bytes e dono/modo final pelo descritor.
O programa não executa o arquivo nem cria processo `chmod`; a adaptação não
comprova detecção de shell/command line do teste upstream.

Cancelamento/deadline/lease encerram e recolhem o processo; falha/resposta perdida
não repete start. Recuperação somente consulta/cancela/limpa o job original.
Cleanup exige ausência dos dois arquivos e do diretório; desconhecidos, links,
erro de RPC,404 ou commit perdido retêm a reserva até confirmação explícita.
O recibo histórico é preservado mesmo quando cleanup falha.

## Bloqueadores concretos da #80

Não existe autorização específica para este GUID/efeito. As autorizações das
#5/#7/#8 estão consumidas e não podem ser reaproveitadas. Não existe neste escopo
uma imagem candidata construída/inspecionada nem um ambiente nativo revisado para
esse perfil. Os gates operacionais b7 e receitas históricas continuam intactos;
fixtures sobre schema descartável c8 não provam compatibilidade do Lab original.

Antes de pedir autorização para uma tentativa, preparar em escopo próprio:

1. Fixar commit de aplicação e imagem por ID imutável, com procedência/imports
   conferidos. Preservar tags/imagens anteriores; não reutilizar a tag histórica.
2. Escolher laboratório/ativo/runner próprios, IDs novos, journal vazio próprio,
   rede sem conflito com qasrc e PKI dedicada. Definir recursos, imagens, mounts,
   revisão de schema/grants/catálogo e duração. Nenhum volume/journal original
   pode ser aberto ou convertido para liberar este perfil.
3. Tornar concreto o pacote privado de uma tentativa: identidade completa,
   revisão acima, hash de configuração/receita, imagens, janela/deadline,
   solicitante/aprovador distintos e escopo/limites. Não preencher IDs, imageIDs,
   aprovação ou recibos fictícios para apresentar um pacote como pronto.
4. Definir fonte defensiva e regra compatível com `fchmod` e comportamento
   `owned-file-permissions`, ou explicitar coleta indisponível e resultado
   INCONCLUSIVE. Não reutilizar a regra histórica de criação de marcador como
   prova de detecção da alteração de permissões.
5. Só então solicitar autorização humana específica para startup, configuração
   e uma única execução. Erro ambíguo consome tentativa e exige reconciliação,
   sem replay. Conferir cleanup, revogar lab, inativar contas/sessões próprias,
   parar recursos próprios e preservar fences/provas.

Não há comando apply/start oferecido por este documento. O bloqueio está
registrado nas #14/#80; esses itens permanecem abertos até ensaio e aceite real.
