# Revisão local da preparação PKI — 2026-10-27

Escopo: geração aditiva com IDs explícitos, CLI offline, arquivos/manifestações e
comandos Make/scanner. Sem ativação, banco, diário, SIEM ou novo ensaio de runner.
Inspeção pelo responsável e revisão especializada adicional somente leitura;
não é pentest independente nem garantia de ausência de falhas.

| Risco | Controle verificado |
|---|---|
| Renovação recria identidade e permite replay | Preserva exatamente três UUIDs e endpoint; nunca lê/escreve diário nem modifica vínculo/autorizações |
| Candidato substitui origem | Diretório separado exclusivo, hash fixado antes de gerar, origem pública conferida novamente antes da publicação |
| Leitura de chaves antigas ou arquivo indevido | Cinco nomes públicos fixos, limites, owner/permissões, sem links/FIFO; audit hook em processo novo |
| Par ou confiança misturados | Cadeias, EKU/SAN/CN, curva/constraints, quatro SPKIs novos/distintos e par chave/certificado verificados |
| Aceitar expirado ou renovar confiança implicitamente | Exceção de tempo apenas no inventário explícito de origem; candidato validado agora com >=24h de validade nas folhas |
| Injeção de comando/configuração | OpenSSL fixo, sem shell, timeouts, ambiente mínimo sem overrides do usuário; política padrão do sistema preservada |
| Divulgação acidental | Erros estáticos, pai0700, CAs0600; folhas0444 só para secrets individuais; .key ignorado Git/build e scanner |
| Falso sucesso após erro de disco | Arquivos/manifesto exclusivos, fsync de diretórios e ancestrais inclusive retry; falhas sem recibo de sucesso |
| Manifesto forjado ou desatualizado | SHA canônico esperado e reverificação do material/pares/tempo, origem e descritor; hash não é assinatura |

Revisor encontrou lacuna na durabilidade de ancestrais recém-criados e depois na
repetição com diretório já existente após fsync falho. ecb4713/a57f5da corrigiram;
regressões cobrem publicação e retry em ancestrais privados. Revisão final estática
de d6d49ad confirmou resolução e nenhum bloqueador concreto nesse delta. O revisor
não executou OpenSSL/testes/serviços/rede nem leu segredos; responsável executou
os checks e a prova offline registrados na evidência.

Usuário/root do host é confiado. Não há proteção contra substituição concorrente
por esse mesmo principal, revogação/OCSP/CRL, vault externo ou durabilidade além
das garantias de fsync/filesystem. Material privado parcial pode permanecer após
falha, inclusive manifesto após erro final; presença de arquivo não comprova
prontidão. Nenhum cleanup automático de resíduos/originais.

Troca de server CA/client cert altera hash do descritor e invalida vínculo/preflight;
não recupera job antigo, comprova volume ou concede nova aprovação. Ativação,
revisão administrativa, preflight e resolução de jobs ambíguos requerem escopo
próprio. PKI Wazuh é separada e não foi rotacionada. Recibo offline não é evidência
de handshake num runner ou detecção defensiva.

[ADR0018](../architecture/decisions/0018-offline-runner-pki.md) ·
[Evidências e testes](../evidence/runner-pki-2026-10-27/README.md).
