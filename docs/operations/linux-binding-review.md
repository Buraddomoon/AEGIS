# Revisão do vínculo Linux antes de uma troca de confiança

O administrador consulta **Laboratórios → Revisar pendências do vínculo**.
A consulta usa a API real e o histórico PostgreSQL, sem contatar runner ou SIEM.
Não é preflight, prova de integridade do diário, autorização ou ativação da PKI.

Contrato: `GET /api/v1/labs/{id}/binding-review`, sessão de administrador,
30 consultas/minuto/usuário. Snapshot próprio `REPEATABLE READ READ ONLY`,
timeoutSQL15s. Nenhuma auditoria de escrita, reparo ou liberação de reserva.
Resposta versionada `aegis-linux-binding-review/1` documentada no OpenAPI.

## Bloqueios e tratamento

| Código | Significado / próxima ação |
|---|---|
| not_linux | A revisão não se aplica ao Demo/outro tipo |
| laboratory_authorized | Revogar a autorização antes da revisão |
| laboratory_reserved | Preservar a reserva e confirmar cleanup do job original |
| nonterminal_runs | Cancelar solicitações pendentes ou acompanhar o encerramento autorizado |
| nonterminal_tests | Filho pendente/estado desconhecido exige investigação; não editar tabelas para liberar |
| unconfirmed_cleanup | Recuperação verificada do job original; não preparar/iniciar outro |
| dispatch_history_limit | Mais de1.000 dispatches: ferramenta de revisão ampliada ainda necessária; não apagar histórico |

Revogação não cancela automaticamente uma solicitação ainda não iniciada. A
remoção/revisão de vínculo agora recusa essa pendência mesmo sem reserva ativa.
Cancele explicitamente em **Execuções** e repita a consulta. Escopos e aprovações
históricos continuam intactos; cancelamento usa a máquina de estados existente.

Cleanup válido exige documento terminal `CLEANED`, hashes íntegros de escopo,
dispatch e confirmação, spec idêntico, geração e IDs/marker originais. Um estado
`CLEANUP_FAILED` histórico pode estar recuperado quando existe essa confirmação e
a reserva foi liberada pela recuperação existente. Não alterar o estado histórico
para fazê-lo parecer bem-sucedido. Ausência de dispatch significa ausência de
intent durável conhecido, sem atestar o estado físico do runner.

`unconfirmed_cleanup_count` refere-se **aos dispatches examinados**. A amostra
`unconfirmed_execution_ids` tem até25 IDs; `unconfirmed_sample_truncated` indica
mais pendências. `dispatch_history_complete=false` sempre bloqueia, inclusive
quando nenhum dos primeiros1.000 registros apresenta erro. Acima desse limite
não existe fallback positivo, expurgo ou liberação automática.

## Consistência e limites

O GET é uma fotografia. Registro/revisão Linux e bind/unbind Wazuh repetem o mesmo
predicado dentro do lock do laboratório. Novas solicitações Linux também usam
esse lock antes de capturar o escopo, atualizando o objeto após aguardar; uma
leitura anterior à revogação não pode produzir uma nova solicitação válida depois.
Start/cancel mantêm a ordem run → laboratório. A revisão não bloqueia runs depois
de adquirir o laboratório, evitando inversão dessa ordem.

O fluxo presume os escritores suportados da aplicação. Administrador SQL/root do
host permanece fronteira de confiança. Estados desconhecidos e inconsistências
observadas bloqueiam; o predicado não repara corrupção nem substitui inspeção do
volume, prova criptográfica externa ou análise do runner original.

A UI rejeita outro laboratório/versão, flags contraditórias e sucesso cacheado
após erro/atualização. Requisitos persistidos satisfeitos continuam com
runner_contacted/journal_verified/activation_permitted/normal_operation_permitted
**false**. A API não recebe certificados, paths, endpoints, comandos ou bypasses.

O painel Linux também mostra os fingerprints SHA256 do descritor do vínculo
revisado e da implantação atual, além da data da última auditoria de registro.
Correspondência desses fingerprints significa apenas mesma configuração pública;
preflight vigente e autorização continuam separados. Divergência ou confiança
ausente pede nova revisão. Nenhuma chave, conteúdo de certificado ou path é
publicado. Campos de auditoria novos registram versão e `authorized=false`;
auditorias antigas continuam intactas.

Registro atualiza a versão sob lock, recarregando o objeto mesmo se a sessão já
o conhecia, e mantém autorização revogada. O coordenador interno pode fornecer
um `ContinuityReview` do próprio processo: a transação reconstrói/compara as
provas completas antes da escrita. Esse objeto não é um parâmetro da API nem
comprova sozinho o mount físico. Preflight revalida versão/binding depois do
handshake sob o mesmo lock; alteração concorrente gera verificação sem sucesso.
Preflights e aprovações antigos são preservados, sem reativação ou reescrita.

## Testes

`pytest tests/test_binding_review.py tests/test_linux_campaigns.py
tests/test_wazuh_campaigns.py -q` utiliza schemas PostgreSQL descartáveis e
fixtures locais. Os novos casos de revisão persistem somente metadados/provas de
teste, com criação de cliente runner proibida. TLS e efeitos de laboratório real
não são necessários. Frontend: `binding-review.test.tsx`.

[ADR0019](../architecture/decisions/0019-runner-binding-review.md) ·
[Preparação PKI](runner-pki.md) ·
[Sequência de ativação a revisar](runner-pki-activation.md).
