# Aceite conjunto da #15 — 18/11/2026

Pedido explícito para conferir o conjunto e encerrar o que estiver completo.
Revisão partiu de `6007e98149a4087f6a110dfdc870c41459f9af94`, main limpa.
#81/#82/#83 e dependência #5 conferidas no GitHub: todas fechadas. Os critérios
do pai estão atendidos; não há pendência obrigatória nesta entrega.

## Capacidade entregue e aceite

| Critério | Evidência conferida | Resultado |
| --- | --- | --- |
| Pequena allowlist e fontes/limites, #81 | [Especificação](../../development/linux-behaviors-spec.md), revisão por hash, fonte ATT&CK versionada | Atendido |
| Programas fixos supervisionados e telemetria esperada, #82 | Processo e shell separados, binding/identidade/revisão, recibos, cancelamento/timeout, cleanup e falsos positivos; CI da fonte | Atendido |
| Uma tentativa por novo teste sob autorização, #83 | [Dois ensaios nativos](VERIFIED-83.md), aprovação dos hashes, atores segregados, persistência, JSON/HTML e encerramento | Atendido |
| História, aprovações e evidências preservadas | Propostas/inventários/autorizações/fences/recibos recalculados em leitura; nenhuma alteração desses artefatos | Atendido |
| Fonte/testes/implantação/sincronização distintos | CI em1dcff25, imagens novas só nos ensaios próprios encerrados, consolidações posteriores somente Markdown | Atendido |

Dois perfis novos: `linux-process-canary-v1` usa `/bin/true`, sem técnica;
`linux-shell-canary-v1` usa printf literal em `/bin/sh`, limitado à primitiva
T1059.004. Nenhum comando/alvo livre ou Atomic importado executável adicionado.
Demo e perfis Linux/Atomic anteriores preservados.

Runs nativas `86163bb8-28fe-46eb-8bd5-1cdb59f4b2fe` e
`38e9d86e-8664-433e-83bc-8a37a378b612`, ambas
**COMPLETED/INCONCLUSIVE/CLEANED, synthetic=false**, um teste por pacote e43bytes
próprios. Processo: exit0/stdout0; shell: exit0/stdout43. Sem coletor/regra
defensiva, INCONCLUSIVE é limite explícito aceito, não falha de execução ou prova
de ausência de telemetria/eficácia de detecção. Recibos não são alertas.

## Verificações efetivas deste aceite

Sem iniciar laboratório, montar volume ou repetir efeito:

- GitHub: estados de #81/#82/#83 e #5; critérios do pai e comentários de conclusão.
- Provas privadas: digest das duas propostas e de cada arquivo do inventário,
  revisão/ID/fonte do programa, autorização por hash e fence/tentativa consumida.
- API capturada: uma execução por run, aprovação por usuário distinto/scope exato,
  JobView do cleanup, digests de scope/recibo/cleanup/relatório e conteúdo/hash/
  bytes do artefato/stdout; synthetic=false e zero eventos/evidências defensivas.
- Helpers finais: dois labs revogados, quatro contas UI inativas/zero sessões e
  safe_to_stop, com binding-review/cleanup confirmados antes de down.
- Docker atual, somente metadados: zero containers próprios, inclusive parados,
  zero redes próprias; exatamente seis volumes e zero consumidores de cada um.
- Imagens novas ainda retidas nas tags exclusivas: runner8b173422 e aplicação
  b25b2bc0, IDs completos iguais aos da proposta/inspeção nativa. Nenhum rebuild.
- Diff Git desde a fonte de CI: somente Markdown; inputs executáveis idênticos.

[CI integral44317530894](https://github.com/Buraddomoon/AEGIS/actions/runs/44317530894)
reconferida SUCCESS na fonte `1dcff254b7af0e699676cdfcbfd1508e9f747cec`: quatro
jobs Python e React aprovados, **3733Python/9skips opcionais e98React**. Os skips
e conjuntos locais sobrepostos estão em [PREPARATION](PREPARATION.md). Não houve
reexecução de suítes, filtros/exclusões, mudança de gates ou novo ensaio para
obter este aceite. A CI e os dois ensaios nativos permanecem provas distintas.

## Encerramento e limites

Aceite conjunto da #15 concluído; #81/#82/#83 já fechadas. Registrar este aceite
na issue e fechar o pai. Sem operação normal, implantação em Demo/originais,
replay ou nova autorização. Autorizações dos dois pacotes estão consumidas;
seis volumes/PKI/diários/fences/imagens/provas permanecem preservados. Não remover
volumes ou reativar recursos como parte de “fechar tudo”.

Esta consolidação é documental. Staged/segredos e checks de repositório antes do
commit; último hash/mensagem e sincronização no comentário final da #15. Não
alterar dados históricos para corrigir apresentação. Não avançar a outra entrega.
