# ADR 0019 — Revisão do histórico antes de alterar o vínculo Linux

Data: 2026-10-27. Status: em implementação.

A rotação offline do ADR0018 não prova que o laboratório pode receber um novo
binding. `active_run_id` sozinho não cobre filhos pendentes ou um dispatch cujo
cleanup não foi confirmado, inclusive após inconsistência operacional. Preservar
essa incerteza é necessário antes de trocar a confiança mTLS.

O backend oferecerá uma revisão administrativa somente leitura dos bloqueios
persistidos. O mesmo predicado será obrigatório no registro/revisão Linux e na
alteração/remoção do binding Wazuh. Exigir laboratório Linux revogado, sem reserva,
sem pais/filhos não terminais e todo dispatch acompanhado de confirmação terminal
de cleanup consistente com seu spec/hash/geração e identidade original. Estado
desconhecido bloqueia. Ausência de dispatch significa somente ausência de intent
durável; não atesta o volume ou o diário real.

Revisão de histórico limitada a 1.000 dispatches; acima disso recusar, sem truncar
uma conclusão positiva. Exibir agregados e até25 identificadores pendentes, sem
conteúdo de eventos, segredos ou comandos. Consulta não chama runner/SIEM, não
renova autorização, não escreve auditoria, não libera reserva e não repara dados.

As mutações continuam sob lock do laboratório, sem adquirir locks de runs depois
dele. O caminho de início já usa run → laboratório. Um GET é apenas diagnóstico;
a mutação recalcula as condições e não aceita o resultado anterior como grant.
Não restaurar certificados/binding antigos para contornar jobs ambíguos.

Testar com PostgreSQL real em schema descartável: histórico válido, drift,
cleanup ausente/inválido, pais/filhos pendentes, isolamento por laboratório,
RBAC, ausência de efeitos e nova validação no momento da mutação. Nenhum ensaio
Linux/Wazuh ou nova dependência é necessário para esse incremento.

Fontes consultadas em2026-10-27:

- [SQLAlchemy SELECT/FOR UPDATE](https://docs.sqlalchemy.org/en/21/core/selectable.html#sqlalchemy.sql.expression.Select.with_for_update)
- [PostgreSQL17 — locks de linha](https://www.postgresql.org/docs/17/explicit-locking.html#LOCKING-ROWS)

Ativação coordenada, inspeção de journal/volumes e preflight real continuam
operações separadas que exigem escopo específico autorizado.
