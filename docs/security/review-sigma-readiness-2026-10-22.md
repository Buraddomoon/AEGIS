# Revisão da preparação Sigma —2026-10-22

Escopo: ADR0009, snapshot de metadados, sigma_readiness.py, endpoints e UI.
Revisão especializada somente leitura; validações executadas pelo agente
principal. Nenhum backend instalado, consulta gerada ou serviço Wazuh iniciado.

Confirmados na revisão:

- can_convert=false e bloqueios de pipeline/mapping físico persistem mesmo com
  requisitos declarados hipoteticamente satisfeitos. Perfil é candidato local.
- Caminhos derivam do alerta registrado, com distinção entre _source e mapping
  físico. Não mapear dados de processos/Windows para full_log.
- Sessão/viewer, hash/associação da versão, limite por usuário e contexto exato
  regra/versão/hash/perfil/hash na UI. Sem destino, índice, plugin ou pipeline
  recebido pela API; pacote é inspecionado via metadata sem importá-lo.
- Snapshot de wheel publicado com hash de artefato/METADATA verificados na
  captura; runtime usa cópia revisada offline. Não afirmar consulta atual ao PyPI
  ou compatibilidade semântica. Requisitos publicados conflitantes ficam visíveis.

Achado de precisão corrigido: valor `fieldref` é nome de outro campo, que não
aparecia em declared_fields da análise anterior. Preparação agora retorna essas
referências, bloqueio explícito field_reference_mapping_unspecified e
field_mapping_complete=false, mesmo para referência com caminho conhecido,
até existir tratamento de pipeline. UI mostra referências pendentes. Testes
cobrem UnknownField e AegisSchema e a indicação visível de mapeamento incompleto.

Revisão estática final não identificou bloqueador concreto restante nesse delta.
Teste em processo novo também executa assess com audit hook contra rede,
gravações e DiskCache. Testes API preservam cobertura/auditoria/histórico;
metadados inválidos/ausentes falham como503. Relatório anterior idêntico no E2E.

Limites: snapshot versionado não é assinatura externa nem observação contínua da
cadeia de suprimentos. Administrador do repositório/implantação controla arquivos.
Mapping completo de nomes não prova tipos/valores/modificadores/condições, fonte
atual ou eficácia. Backend revisado incompatível com core2.0.1 e pipeline
executável continuam pendentes. [Guia e fontes](../integrations/sigma.md#preparação-de-conversão-e-campos-candidatos), [progresso](../PROGRESS.md).
