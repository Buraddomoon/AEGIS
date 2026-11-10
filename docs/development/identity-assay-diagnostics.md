# Diagnóstico da tentativa de identidade de10/11/2026

Escopo: issue #3/subissue #47. A tentativa encerrada e seus limites permanecem
na [evidência original](../evidence/identity-assay-2026-11-10/README.md). Nenhum
recibo, plano, autorização, certificado ou fence original foi alterado.

## Cliente e idade da admissão

O gate start do cliente foi observado às18:53:55.282146 UTC e persistido às
18:54:04.754207 UTC:9,472061s para produzir uma admissão cuja idade máxima é10s.
Após isso, lifecycle e driver ainda revalidam intent, configuração e request
antes da RPC. O lifecycle registrou falha em start e passou a cleanup às
18:54:06.049053 UTC, sem resultado do cliente.

O teste de regressão reproduz a expiração durante a preparação do driver:
`journal_probe_gate_stale` bloqueia a RPC, consome a admissão e encerra os recursos.
Antes da correção, esse código era descartado pelo lifecycle porque não estava
na lista fechada de diagnósticos do papel identity-client; o recibo também não
o propagava. Os tempos do ensaio são compatíveis com essa causa, mas o registro
antigo não preservou o código e não permite afirmá-la como causa nativa comprovada.

A correção evita repetir o parsing OpenSSL de certificados públicos idênticos.
Somente os metadados imutáveis são mantidos em cache limitado a32 certificados,
indexado pelos bytes reais, papel, identidade e endpoint; cada chamada recebe
uma cópia do resultado. Arquivos/permissões continuam sendo lidos, cadeias e
assinaturas verificadas, relógio/validade conferidos e chaves candidatas comparadas
em cada inventory/verify. Nenhum segredo ou resultado de confiança é armazenado
no cache. Bytes, papel, identidade ou endereço diferentes exigem novo parsing.

As provas conservam a ordem e as duas revisões integrais do plano ativo.
checked_at permanece no início; validade20s, idade máxima10s, lease e limites
de240/300s não aumentam. Falha, drift, expiração ou persistência incompleta
continuam impedindo efeitos. Não há retry ou obtenção de outro gate depois do
fence START_REQUESTED.

## Inventário e diagnósticos

O recibo original declara inventário não verificado; a revisão integral continua
recusando esse recibo. Uma reconstrução somente do leitor, sem confirmação/lease,
writer ou adaptador nativo, conseguiu ler os13 envelopes preservados. A causa
transitória da falha original do inventário não foi reproduzida nem inferida a
partir dessa leitura posterior.

Recibos novos usam `aegis-identity-assay-receipt/2` com failure_code e
artifact_inventory_failure_code. Os valores pertencem a listas fechadas; erros
de filesystem são classificados sem paths, stderr ou texto arbitrário de exceção.
A revisão aceita também recibos /1, sem inventar diagnósticos para o histórico.
Inventário incompleto continua sendo falha, inclusive se todos os arquivos
restantes puderem ser lidos depois.

A CLI de revisão agora distingue a causa `recorded_artifact_inventory_unverified`
do erro geral de integridade/política. Continua retornando exit1 e
native_runtime_rechecked=false; a mensagem melhor não transforma a tentativa
antiga em sucesso.

## Validação e limite operacional

Regressões verificam parsing por conteúdo com validação atual de trust/tempo/chave,
expiração antes da RPC sem start/retry, cleanup, revisão de um cliente falho com
inventário completo, diagnósticos sem segredos e compatibilidade de recibos /1.
Erros de inventário injetados continuam recusados pela revisão integral.

Essas correções são no coordenador/CLI do host e não alteram o pacote executável
da imagem runner. Testes e inspeção somente leitura não são nova prova de mTLS
nativo. Nenhum container/rede de laboratório foi iniciado durante o diagnóstico.
Outra tentativa requer outro plano/pacote, CI correspondente e autorização
específica; a autorização da operação anterior está consumida.
