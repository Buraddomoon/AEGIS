# Verificação de entrega do código 0.2.0

Base demonstrável consolidada na [#12](https://github.com/Buraddomoon/AEGIS/issues/12),
17/11/2026. [Checkpoint curto](../development/release-checkpoint.md) e
[matriz corrente de aceite](../product/acceptance-criteria.md) substituem a leitura
do PROGRESS completo para retomar. Os marcos0.3–0.5 e1.0 organizam planejamento;
não são versões publicadas. Sem bump, tag Git, GitHub Release ou push de imagem.

GitHub informou visibilidade **PUBLIC** em16/11 e17/11, divergente da política
privada em AGENTS.md. Nenhuma mudança de visibilidade foi realizada, e essa
política de privacidade não é declarada atendida. Somente resumos revisados de
provas foram versionados; configuração/segredos/logs/dumps/artefatos de runtime
continuam fora do Git. A licença não define a visibilidade do repositório.

## Verificações reproduzíveis

Na configuração de desenvolvimento documentada:

```bash
make lint
make test
make build
make audit
make e2e
make release-check
```

PG/Redis15 das suítes devem ser usados em sequência. `make e2e` cria API/worker/
schema próprios, usa Firefox e só simulações Demo; `AEGIS_E2E_SCREENSHOTS` permite
guardar capturas fora da galeria histórica. Esse harness testa o desenvolvimento,
enquanto o ensaio Compose abaixo verifica boot/configuração e runtime da imagem.
Não repetir Linux/Wazuh para uma screenshot ou acionar targets de lab.

Para instalação nova, usar [README](../../README.md#executar-localmente) e
[operação local](deployment.md). Para coexistir com a fonte, seguir o
[projeto/imagem/porta próprios da #73](../evidence/release-2026-11-16/INSTALL.md).
`make up` padrão usa a tag/porta do Demo; antes de reutilizar qualquer tag,
preservar a imagem ativa em tag dedicada e conferir o ID. Nunca aplicar limpeza
de volume ao projeto existente para simular instalação nova.

`make release-check` não acessa banco, Docker, browser ou rede. Lê **o índice Git**,
verifica padrões de credenciais/paths, igualdade das versões Python/React/lock e
dependências declaradas na raiz do lock npm. Confere destinos relativos dos links
inline Markdown, incluindo imagens, e cabeçalho/dimensões PNG em docs/images.
O JSON identifica HEAD e divergências índice/HEAD/arquivos rastreados. Arquivos
não rastreados/ignorados, como `.env`/`.local`, não são lidos. Adicionar somente
arquivos revisados ao índice antes de validar; valores suspeitos não são exibidos.

Padrões não garantem ausência de segredos em todo histórico/logs; links externos,
âncoras e toda a gramática Markdown não são validados; cabeçalhos PNG não provam
procedência. Passed não substitui testes, auditoria, instalação ou revisão humana.
Não há publicação automática nem autorização de laboratório nesses checks.

## Evidências atuais e históricas identificadas

| Escopo | Referência verificável / limite |
|---|---|
| Código/locks | pyproject.toml, apps/web/package.json e package-lock.json:0.2.0; nenhum bump nesta entrega |
| Revisão de segurança | [#72](../evidence/release-2026-11-16/SECURITY.md):181testes, auditoria Python1finding revisado/npm0; sem pentest exaustivo ou promessa enterprise-ready |
| Instalação nova e UI | [#73](../evidence/release-2026-11-16/INSTALL.md):build/Compose/bootstrap/ready, Firefox contra imagem nova e `make e2e` separado; cada rodada5runs/20Demo/2snapshots/4PDFs/zeroerrosJS, cleanup conferido |
| Relatórios | #73:JSON/PDF pelos botões,5HTMLs200 pela API, pypdf nos4PDFs com aviso sintético em todas as páginas; [operação PDF](pdf-reports.md) e [snapshots](scheduled-reports.md) |
| CI da fonte executável | [43954449487](https://github.com/Buraddomoon/AEGIS/actions/runs/43954449487),a8db6da:3435Python/9skips/91React, quatro grupos/React completos; [inputs equivalentes](../development/release-checkpoint.md) |
| Imagem ativa e imagem testada | [Checkpoint](../development/release-checkpoint.md):Demo anterior b8 preservado; imagem1c7da571 testada só em Compose novo depois encerrado, retida localmente |
| Linux atual, limitado e encerrado | [#4:rotação/binding12/11](../development/activation-checkpoint.md) e [#5:campanha43bytes](../../labs/linux/CAMPAIGN-VERIFIED-2026-11-12.md), COMPLETED/INCONCLUSIVE/CLEANED sem SIEM |
| Wazuh atual, limitado e encerrado | [#7:campanha16/11](../evidence/wazuh-cycle-2026-11-16/CAMPAIGN.md) e [leitura da mesma run](../evidence/wazuh-cycle-2026-11-16/UI-EXPORTS.md), um marcador/regra100200, zero técnicas ATT&CK |
| Wazuh histórico | [22/10](../evidence/wazuh-2026-10-22/README.md), escopo original preservado; não é a campanha16/11 nem autorização de replay |
| Recuperação b7 | [#11](../development/backup-b7-checkpoint.md):a0/b7 e fixture não vazia separados; sem cutover ou recuperação off-host |
| Cópia cifrada histórica | [Restore26/10](../evidence/encrypted-backups-2026-10-26/README.md),32tabelas/3169linhas; não é backup atual b7; custódia externa adiada |
| Galeria histórica | [Origem das capturas versionadas](../images/README.md); capturas novas da #73 mantidas privadas, sem substituir prova antiga |

A CI principal executa dependências/testes/bancos/build/auditoria quando há código.
Source-review documental é distinto, sem bancos/instalação, timeout2min, permissões
read/cancelamento de duplicados. Commits desta entrega só alteram Markdown;
inputs executáveis iguais à CI fixada, sem alegar rerun integral em cada hash.
Checks finais/URLs/hashes e sincronização estão nas issues#72/#73/#74/#12.

## Limites e backlog, sem reabrir o que já foi entregue

- Custódia externa/chave fora do host:#28, adiada; sem upload/serviço pago.
- Recuperação operacional de labs:#9; retenção#27; Demo off-host#29. Backup não
  substitui configuração/segredos/imagens/journals, cutover ou prova de RPO/RTO.
- Rotação/identidade/binding Linux e a campanha Wazuh delimitada foram
  demonstrados e encerrados. Não são operação contínua, permissão permanente
  ou aprovação para outro teste. Novas campanhas reais exigem escopo específico.
- Perfis de versões Wazuh:#8; catálogo Atomic versionado#13/execução revisada#14;
  novos testes benignos#15. Atomic atual só importa metadados não executáveis.
- Sigma backend/pipeline#16 e consulta real#17; implantação#18 é futuro opcional.
  Parsing/análise/prévia não comprovam consulta, implantação ou eficácia.
- Administração/gestão:#24/#25/#26/#30; TLS operacional#41; MFA/SSO#38,
  multi-workspace#31/Windows#32/outros provedores#35 permanecem fora deste aceite.
- PDF, comparação, agendamento Demo e snapshots automáticos já estão entregues;
  não os listar como features futuras faltantes. Sem assinatura digital, PDF/A ou backfill.

## Encerrar e retomar

Revisar staged/segredos, check pertinente, `git diff --cached --check`,
`check_staged.py` e `check_release.py` antes de cada commit. Conventional Commits
pequenos em main, referência à subissue e push origin/main; sem branches/PRs,
force push ou mudança de visibilidade. Registrar comportamento/prova/limites,
commit/hash/mensagem/push e distinguir implementado/testado/implantado. Pai só
fecha após filhos/aceite conjunto; depois **parar**. Outra entrega depende da
escolha explícita de issue no [índice](https://github.com/Buraddomoon/AEGIS/issues/1).
