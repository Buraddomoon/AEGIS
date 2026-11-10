# Backlog executável por sessão

Fonte de execução: [índice de issues e subissues no GitHub](https://github.com/Buraddomoon/AEGIS/issues/1).
Este documento mapeia os requisitos ao inventário de10/11/2026; status e provas
posteriores ficam nas issues. Não é necessário carregar o chat antigo.

Use o [prompt e guia de sessão](../development/session-workflow.md). Escolha uma
entrega ou subissue e pare ao concluir. O índice geral não é uma sessão para
implementar tudo. Milestones são planejamento, sem bump de versão/data/release.

## Começar pelo laboratório

1. [Faixa Linux sem colisão](https://github.com/Buraddomoon/AEGIS/issues/2).
2. [Identidade mTLS nativa](https://github.com/Buraddomoon/AEGIS/issues/3), após
   [validação da fonte](https://github.com/Buraddomoon/AEGIS/issues/10).
3. [Ativação da confiança e binding](https://github.com/Buraddomoon/AEGIS/issues/4).
4. [Campanha Linux sob a configuração atual](https://github.com/Buraddomoon/AEGIS/issues/5).
5. [Duas redes Wazuh sem colisão](https://github.com/Buraddomoon/AEGIS/issues/149),
   [PKI dos serviços Wazuh](https://github.com/Buraddomoon/AEGIS/issues/6) e
   [fluxo integrado atual](https://github.com/Buraddomoon/AEGIS/issues/7).

Dependências nativas no GitHub determinam a ordem efetiva. Ensaio histórico já
existente não é autorização de repetição; cada tarefa delimita os novos efeitos.

## Rastreabilidade do pedido original

| Tema do requisito | Já entregue no escopo atual | Evolução/pendência em issues |
| --- | --- | --- |
| Fundação, API, frontend, persistência, migrações | Monólito e Demo executáveis | [CI integral](https://github.com/Buraddomoon/AEGIS/issues/10), [aceite/instalação/revisão](https://github.com/Buraddomoon/AEGIS/issues/12) |
| Simulação e estados, aprovação, cleanup | Demo e marcador Linux histórico | [rede](https://github.com/Buraddomoon/AEGIS/issues/2), [identidade](https://github.com/Buraddomoon/AEGIS/issues/3), [binding](https://github.com/Buraddomoon/AEGIS/issues/4), [retomada Linux](https://github.com/Buraddomoon/AEGIS/issues/5), [mais comportamentos Linux](https://github.com/Buraddomoon/AEGIS/issues/15) |
| Laboratórios e ativos autorizados | Demo e Linux revisado de implantação | [múltiplos labs/ativos](https://github.com/Buraddomoon/AEGIS/issues/25), [Windows opcional](https://github.com/Buraddomoon/AEGIS/issues/32) |
| Wazuh e evidências reais | Um pipeline4.14.9/marcador/regra100200 encerrado | [redes próprias sem colisão](https://github.com/Buraddomoon/AEGIS/issues/149), [certificados Wazuh](https://github.com/Buraddomoon/AEGIS/issues/6), [nova configuração integrada](https://github.com/Buraddomoon/AEGIS/issues/7), [schemas/archives](https://github.com/Buraddomoon/AEGIS/issues/8) |
| Atomic Red Team | Parser seguro de metadados não executáveis | [catálogo persistente](https://github.com/Buraddomoon/AEGIS/issues/13), [primeiro Atomic allowlisted](https://github.com/Buraddomoon/AEGIS/issues/14) |
| ATT&CK oficial e cobertura | Enterprise versionado, CLI de atualização, matriz/tabela/filtros/histórico | [revisão web](https://github.com/Buraddomoon/AEGIS/issues/19), [subtécnicas/telemetria](https://github.com/Buraddomoon/AEGIS/issues/20), [outra matriz opcional](https://github.com/Buraddomoon/AEGIS/issues/40) |
| Validação de detecção e correlação | Outcomes, evidências, janelas/identidades e disponibilidade distintas | [novos schemas](https://github.com/Buraddomoon/AEGIS/issues/8), [validação de consultas](https://github.com/Buraddomoon/AEGIS/issues/17), [recomendações determinísticas](https://github.com/Buraddomoon/AEGIS/issues/22) |
| Sigma, versões e regras | Parsing/versões/comparação/vínculos/análise/prévia rename | [backend/pipeline compatível](https://github.com/Buraddomoon/AEGIS/issues/16), [consulta real](https://github.com/Buraddomoon/AEGIS/issues/17), [implantação futura](https://github.com/Buraddomoon/AEGIS/issues/18) |
| Coverage e comparação | Recortes, denominadores e comparação por contexto/manifesto | [ambientes distintos](https://github.com/Buraddomoon/AEGIS/issues/21) |
| Campanhas e histórico | Criação, solicitação, revisão/aprovação, execução/cancelamento e repetição | Reutilizados pelas entregas reais; não reabrir o fluxo Demo como tarefa nova |
| Automação e agendamentos | Demo recorrente aprovado e relatórios automáticos | [agenda real](https://github.com/Buraddomoon/AEGIS/issues/23), [gatilhos CI/CD/GitHub opcionais](https://github.com/Buraddomoon/AEGIS/issues/33) |
| Relatórios técnicos/executivos e PDF | HTML/JSON/PDF, resumo, comparação e snapshots automáticos | [recuperação no schema atual](https://github.com/Buraddomoon/AEGIS/issues/11), [recomendações específicas](https://github.com/Buraddomoon/AEGIS/issues/22) |
| Interface/API reais e integrações | Páginas funcionais, erros/estados, consulta de evidências | [gestão de conectores](https://github.com/Buraddomoon/AEGIS/issues/26), [problemas operacionais](https://github.com/Buraddomoon/AEGIS/issues/30), [idioma/acessibilidade](https://github.com/Buraddomoon/AEGIS/issues/39) |
| Identidade, RBAC e segurança | Sessões/Argon2id/CSRF/RBAC backend/imports seguros | [manutenção de contas/sessões](https://github.com/Buraddomoon/AEGIS/issues/24), [auditoria de entrega](https://github.com/Buraddomoon/AEGIS/issues/12), [MFA/SSO opcional](https://github.com/Buraddomoon/AEGIS/issues/38) |
| Operação e dados | Backup/restore Demo em clone, quarentena, reconciliação, cifragem local | [backup Lab](https://github.com/Buraddomoon/AEGIS/issues/9), [schema atual](https://github.com/Buraddomoon/AEGIS/issues/11), [retenção](https://github.com/Buraddomoon/AEGIS/issues/27), [custódia adiada](https://github.com/Buraddomoon/AEGIS/issues/28), [recuperação operacional](https://github.com/Buraddomoon/AEGIS/issues/29) |
| Deployment e observabilidade | Compose local e health/heartbeat/logs/auditoria | [painel operacional](https://github.com/Buraddomoon/AEGIS/issues/30), [perfil TLS/deploy](https://github.com/Buraddomoon/AEGIS/issues/41) |
| Extensibilidade futura | Protocols e adapters separados do domínio | [workspace](https://github.com/Buraddomoon/AEGIS/issues/31), [Windows](https://github.com/Buraddomoon/AEGIS/issues/32), [CI/CD/GitHub](https://github.com/Buraddomoon/AEGIS/issues/33), [Caldera](https://github.com/Buraddomoon/AEGIS/issues/34), [outro SIEM/EDR](https://github.com/Buraddomoon/AEGIS/issues/35), [distribuição](https://github.com/Buraddomoon/AEGIS/issues/36), [IA opcional](https://github.com/Buraddomoon/AEGIS/issues/37) |

As possibilidades V1.0 não são bloqueadores do Demo ou promessa de implementar
todas agora. Issues futuras começam por decisão/perfil limitado e ampliam suporte
somente com evidência. Instalar dependência não é integração validada.
