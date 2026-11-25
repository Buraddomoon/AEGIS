# Contas, papéis e sessões — #24

Estado em25/11/2026: #105/#106/#107 e aceite conjunto da #24 atendidos.
Fonte integrada publicada em `origin/main`, CI integral aprovada e sincronização
resolvida. Entrega encerrada; parar neste escopo, sem iniciar outra feature.

- Fonte `38f2fee8ddef409ed60b5503ca9b52694d5759b3` combina os pais locais
  `f174e33` e remoto `5e4737a`, preservando os dois históricos. Único conflito
  textual no guia de testes, resolvido mantendo ambas as seções;22arquivos
  alterados apenas pelo remoto idênticos. Sem rebase/force push/branch/PR.
- Contas existentes: ativação/desativação, papel e último admin protegido por
  lock PostgreSQL; senha própria exige senha atual, redefinição administrativa
  para outra conta, Argon2id e revogação de todas as sessões afetadas.
  Reativação não restaura tokens antigos. Nenhuma exclusão de usuário/histórico.
- Viewer/operator gerenciam apenas sua senha/sessões. Backend aplica RBAC/CSRF/
  limites/auditoria; UI confirma efeitos, limpa segredos e descarta cache/identidade
  em401. Start/fila/worker/cleanup revalidam as contas e mantêm a limpeza obrigatória.
- Recorrência preservada: quatro casos adicionais mudam contas pela API contra
  grants existentes, sem emissão/efeito e sem reescrever aprovação ou escopo.
- Validação integrada local:255Python,166React/21glob, lint/build e Firefox
  aprovados. Três contas/capturas1440/390px, zero erros JS, cleanup conferido no PG.
  O grupo focado42está incluído nesses255; não somar rodadas sobrepostas.
- CI integral [45677946104](https://github.com/Buraddomoon/AEGIS/actions/runs/45677946104):
  **SUCCESS**,4188Python/9skips opcionais existentes e166React/21glob.
  Quatro partições Python e React conferidos; sem exclusões novas. Revisão de
  fonte45677946198 SUCCESS no mesmo commit.
- [Provas integradas](../evidence/user-maintenance-2026-11-25/INTEGRATED-24.md),
  [fase local anterior/falhas](../evidence/user-maintenance-2026-11-25/README.md)
  e [contratos de autorização](../security/authorization.md).

O bloqueio inicial de sincronização foi resolvido sob pedido explícito do usuário.
Demo/API/worker b8 anteriores preservados, sem implantação ou operação Linux/Wazuh,
contas humanas, volumes originais, marcador, PKI, rede ou migração de originais.
Workflows nativos não foram acionados. Os ensaios de uso único anteriores seguem
encerrados; esta entrega não autoriza reativação ou operação contínua.
