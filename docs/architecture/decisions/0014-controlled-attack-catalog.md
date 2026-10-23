# ADR0014 — Atualização controlada do catálogo ATT&CK

Data: 2026-10-23. A fonte oficial ainda indica Enterprise20.0; não inventar uma
versão nova para demonstrar atualização. O marco resolve a substituição revisada
do catálogo de um banco populado e a rastreabilidade da origem.

Separar preparar, revisar e aplicar. Ferramenta local baixa apenas bundle
Enterprise numerado e licença do repositório oficial, fixados por commit completo.
TLS obrigatório, sem redirects/proxies herdados, limites de tamanho/tempo e cache
privado exclusivo. Nenhum download em API, worker ou startup; nenhuma URL livre.
Hash detecta alteração, não é assinatura. Licença diferente da revisada bloqueia
aplicação até revisão no repositório. Normalizador cobre somente o perfil de
catálogo Enterprise necessário; não declara validação completa de STIX.

Guardar releases imutáveis com origem/commit/hashes e documento normalizado
versionado, além de um estado atual único. AttackTechnique é a projeção consultada
pela aplicação. Esse JSON é snapshot externo imutável, não substituição das
entidades relacionais. Seed inicial reconhece o snapshot legado distribuído,
sem inventar commit ausente, e não sobrescreve um catálogo já inicializado.

Normalizar técnicas ativas e retiradas com flags oficiais. Nunca apagar IDs
referenciados: ausente de uma release significa fora da versão atual, não
revogada ou descontinuada por inferência. Preservar metadados anteriores desses
IDs. Identidade STIX/ATT&CK conflitante é bloqueador. Plano mostra inclusões,
mudanças, retiradas e impactos sobre testes; aplicação exige hash exato revisado,
administrador ativo e transação. Recusar downgrade e modificação de release já
registrada. Mesmo artefato aplicado novamente não causa novos efeitos.

Aplicação local com credencial de implantação; runtime consulta, sem privilégios
de modificar releases/estado/projeção. Locks NOWAIT e comparação do estado antes
da escrita recusam concorrência/drift. Não aplicar enquanto houver runs pendentes,
reservas ou agendamentos retomáveis. Não alterar testes, regras, aprovações,
scopes ou evidências históricas. Auditoria append-only e guardas no PostgreSQL.

Novos scopes registram identidade do catálogo e metadados das técnicas utilizadas.
Técnicas retiradas/ausentes não entram em novas solicitações. Histórico sem essa
referência permanece desconhecido; não preencher retroativamente. Cobertura da
release atual exige avaliação dessa mesma release; histórico continua acessível
e indicadores mantêm denominadores explícitos. UI mostra estado/versionamento,
proveniência e histórico reais, sem botão de atualização sem implementação.

Migração explícita para a modelagem nova. Backups antigos permanecem preservados,
mas exigem imagem/código compatíveis; não enfraquecer as guardas de recovery para
aceitá-los. Nenhum novo ensaio Linux/Wazuh é autorizado por este marco.

Fontes: [versões oficiais](https://attack.mitre.org/resources/versions/),
[attack-stix-data](https://github.com/mitre-attack/attack-stix-data),
[modelo oficial](https://mitre-attack.github.io/attack-data-model/) e
[licença](https://github.com/mitre-attack/attack-stix-data/blob/master/LICENSE.txt).
