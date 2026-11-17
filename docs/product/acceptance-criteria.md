# Aceite por escopo — código 0.2.0

Consolidação da [#12](https://github.com/Buraddomoon/AEGIS/issues/12),17/11/2026,
com ensaios Demo de16/11 e conferência final da fonte em17/11. Critérios aceitos
abaixo correspondem à prova indicada; não significam todo o roadmap entregue,
privacidade do repositório ou prontidão enterprise. Nenhuma versão foi elevada.
[Checkpoint para outra sessão](../development/release-checkpoint.md).

## Matriz corrente

| Capacidade / critério | Prova verificável | Limite do aceite |
|---|---|---|
| Configuração/instalação Demo nova | [#73: build, Compose, migração/seed/grants, CLI bootstrap e ready](../evidence/release-2026-11-16/INSTALL.md); b7/33tabelas,0usuários/0runs iniciais | Projeto/imagem/porta/volume novos no mesmo host; caches presentes; sem reset do Demo existente ou teste off-host |
| Auth/RBAC/CSRF, SSRF/TLS, YAML/Sigma, SQL/runtime ACL, segredos/evidências | [#72: revisão e181testes locais](../evidence/release-2026-11-16/SECURITY.md) | Revisão dos controles e recusas cobertos, não pentest exaustivo; HTTP só loopback, sem MFA/SSO/tenant |
| Campanha/aprovação/worker, repetição e evidência persistente | [Firefox contra Compose novo e `make e2e`](../evidence/release-2026-11-16/INSTALL.md): cada rodada5runs/20testes/zeroerrosJS | Mesma regra de domínio, dados da API, synthetic=true; nenhuma execução ofensiva/PowerShell real |
| Classificação, integridade, métricas e comparação | #72 testa identidade/ativo/marcador/tempo/regra/execução; #73 confere1detectado/3válidos, inconclusivo excluído, recorte2runs/6válidos e delta0 | Ausência de alerta não prova ausência de telemetria; delta não prova causalidade; hash não é assinatura |
| Cancelamento/timeout/idempotência/cleanup/concorrência | [CI integral da fonte executável](https://github.com/Buraddomoon/AEGIS/actions/runs/43954449487), testes existentes de flow/cleanup/transactions/scheduling | Testes/fixtures não são nova execução de laboratório ou benchmark |
| PDF/HTML/JSON: execução, recorte, comparação e snapshots | [#73](../evidence/release-2026-11-16/INSTALL.md):4PDFs lidos por pypdf/aviso em todas as páginas;5HTMLs200; JSON/PDF por botões reais | HTML complementar pela API; não teste exaustivo de todos os botões; sem PDF/A/assinatura ou truncamento silencioso |
| Agendamentos e relatórios automáticos | #73:duas ocorrências/cadência real60s, grant delimitado,2READY inicial/comparação congelados após mudanças Sigma | Somente novas ocorrências Demo, sem backfill; documento pronto não comprova detecção |
| Interface/responsividade | #73:14capturas por rodada, inspeção visual desktop/móvel,390px sem overflow global e tabelas com scroll interno | Percurso coberto por Firefox, sem alegação de acessibilidade completa ou todos os browsers |
| ATT&CK versionado, matriz/proveniência/publicação controlada | #73 consulta API/snapshot inicial Enterprise20.0/706ativas; [publicação e histórico](../evidence/attack-catalog-2026-10-23/README.md) | Catalogado não significa executado; atualização não ocorre no startup; revisão pela UI é backlog#19 |
| Sigma: parsing, versões/vínculos/análise/preparação/prévia | #72 testa parser sem cache/limites; #73 confere revisão/retirada/histórico e bloqueios reais | Backend/pipeline/mapping físico, conversão, consulta e implantação não aceitos; #16/#17/#18 |
| Redes/PKI/identidade/binding Linux renovados | [#4: checkpoint e ensaio nativo12/11](../development/activation-checkpoint.md), dependência#3 atendida | Operação delimitada já encerrada; não é confiança permanente nem permissão de replay |
| Campanha Linux após renovação | [#5: campanha real12/11](../../labs/linux/CAMPAIGN-VERIFIED-2026-11-12.md),43bytes/COMPLETED/INCONCLUSIVE/CLEANED | Sem SIEM/alerta; zero técnicas ATT&CK; recibo não é evidência defensiva; autorização consumida |
| Wazuh com configuração atual | [#7: campanha16/11](../evidence/wazuh-cycle-2026-11-16/CAMPAIGN.md) e [UI/exports da mesma run](../evidence/wazuh-cycle-2026-11-16/UI-EXPORTS.md), COMPLETED/DETECTED/CLEANED | Um marcador43bytes/agente001/regra100200/4.14.9, zero técnicas ATT&CK; sem Windows/archives/outras regras ou eficácia geral SIEM/EDR; pacote consumido |
| Recuperação b7 e relatórios congelados | [#11: backups a0/b7 e fixture não vazia separados](../development/backup-b7-checkpoint.md) | Clones offline/quarentena; Demo fonte sem relatórios automáticos, fixture explícita com eles; sem cutover/off-host/RPO/RTO |
| Cópia cifrada e custódia | [Restore offline age/X25519](../evidence/encrypted-backups-2026-10-26/README.md) | Custódia externa#28 adiada; chave/cópia locais e originais em claro; sem upload/expurgo |
| Qualidade e histórico Git | CI integral43954449487:3435Python/9skips e91React; [inputs equivalentes e fonte/imagem](../development/release-checkpoint.md); checks locais/documentais | CI integral de fonte fixada, distinta de source-review documental e imagem ativa. Main/push direto; nenhum histórico/approval/receipt reescrito |

## Achados e condições que permanecem explícitos

- GitHub informou **PUBLIC** em16/11 e17/11, divergente da política privada em
  AGENTS.md. Nenhuma mudança de visibilidade executada; esse requisito de
  privacidade não é declarado atendido. A decisão permanece humana, fora da
  autorização de consolidação. Scanner de padrões do índice não atesta todo
  histórico Git ou ausência de exposição.
- DiskCache5.6.3:1finding médio upstream mantido visível na auditoria16/11;
  caminho limitado do parser sem import/cache conforme gate/testes. Habilitar
  validators/plugins/cache exige outra revisão; não se alega zero vulnerabilidades.
- Nenhuma implantação do código atual no Demo persistente: imagem b8 anterior
  preservada. A imagem nova foi validada somente em Compose temporário encerrado.
- Nenhum ensaio Linux/Wazuh foi repetido pela #12. Labs revogados/encerrados e
  autorizações consumidas; novas operações exigem escopo/revisão específicos.
- TLS/proxy externo, operação contínua, escala, multi-workspace, MFA/SSO,
  recuperação off-host e novos provedores não se tornam aceitos por este Demo.

## Retomada sem chat ou PROGRESS completo

Escolher uma issue no [índice](https://github.com/Buraddomoon/AEGIS/issues/1),
ler AGENTS.md e [guia curto](../development/session-workflow.md), a issue,
seus bloqueadores e arquivos de entrada. Não reconstruir PDFs, comparação,
agendamentos, snapshots, parsing Sigma ou matriz já entregues. Próxima capacidade
é decisão do usuário; a #12 não inicia automaticamente outra entrega.

O [texto anterior](acceptance-history-before-issue12.md) preserva integralmente
os registros históricos de aceite e suas antigas pendências. Evidências originais,
scopes, approvals, receipts e relatórios não foram reescritos para esta matriz.
