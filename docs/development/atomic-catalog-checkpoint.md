# Checkpoint da entrega #13 —17/11/2026

#75/#76/#77 concluídas e a validação integral corrigida após retomada explícita:
catálogo Atomic offline versionado, API autenticada e biblioteca com requisitos/
procedência/revisão. Entradas sempre `approved=false`, `executable=false` e
`available_for_new_scope=false`, separadas da allowlist. Origem declarada pelo
operador; nenhum download/instalação/execução Atomic.

[Revalidação final](../evidence/atomic-catalog-2026-11-17/REVALIDATION.md): CI
integral44151198083 **SUCCESS** na fonte0517d24, quatro partições Python e React
conferidos:3525Python/9skips opcionais,98React/16arquivos e21regressões Node de
segurança. Lint/tipos/build/auditorias aprovados. npm0; Python mantém1finding
DiskCache explicitamente revisado, sem uso no caminho de parsing.

As7falhas Wazuh foram corrigidas com inventário b7 fixo e fixture b7 real, sem
ampliar compatibilidade operacional. Picomatch recebeu correção de parser em
[fork local privado/licenciado](../../apps/web/vendor/picomatch/README.md), com
origem/hashes fixados, resolução verificada, deadline e preservação de semântica;
nenhum advisory excluído ou threshold relaxado. Não é release upstream.

Firefox real da retomada:17metadados/1revisão/zeroexecuções Atomic, allowlist
preservada; Demo5runs/20testes/2snapshots/4PDFs/16capturas/zeroerrosJS. Cliente
final byte a byte idêntico ao build desse E2E; backend preservado após1d96860.
Schemas/processos de teste removidos. Não é implantação.

Fonte exige migration explícita c8/36tabelas; Demo/Labs originais b7 preservados.
Gates Linux/Wazuh continuam recusando c8 sem revisão operacional específica.
Não migrar original nem iniciar Lab a partir deste checkpoint.

O fechamento inicial da #13 ocorreu com pendências por pedido do usuário; o
[relatório histórico](../evidence/atomic-catalog-2026-11-17/README.md) preserva
falhas/limites daquele momento. A retomada corrigiu essas pendências e comprovou
a CI integral acima. Fechar o pai com esse aceite e parar, sem outra entrega,
execução Atomic, laboratório ou implantação.
