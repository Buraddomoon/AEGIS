# Probes de continuidade — runtime, resultado e encerramento

Data: 2026-10-27. Escopo: desenvolvimento/testes locais e consultas de metadados.
Não houve novo ensaio Linux/Wazuh, abertura dos volumes originais, marcador,
campanha, troca de PKI/binding, criação/parada/remoção de recursos Docker, build,
deploy, migração, seed, upload ou alteração de credenciais humanas.

## Componentes verificados

- Receita somente journal-before/journal-after: imagem por ID, Python isolado,
  módulo/argumentos fixos, UID10001, rede none, root read-only, volume original
  read-only/nocopy, scratch tmpfs limitado, caps removidas e limites de recursos.
- Revisão projetada antes/depois: imagem/referência/entrypoint/argv/identidade,
  estado, mounts/opções/limites/namespaces e ownership. Imagem com VOLUME declarado
  bloqueia. Ambiente só nomes/booleans, allowlist sem duplicatas ou loader override;
  valores fixos, LANG/TMPDIR explicitamente definidos. Sem Config.Env bruto.
- Start intent durável e não repetível após retomada. Hashes de receita/gates/
  bundle são referências, não autorização nem prova dos gates por si só.
- Decoder vincula resposta/provas/descritor/identidade, flags falsas, contagens e
  hash; comparação exige inventário lógico completo e contagens inalterados.
- Cleanup interno: intent durável e ownership/imagem antes de stop SIGTERM/5s e
  rm por ID completo, sem force/volumes/global delete. Erro ambíguo exige consulta
  posterior confirmando estado/ausência. Dependências incertas retidas; ausência
  repetida no final antes de close. Driver concreto nunca invocado em recurso real.

Não há CLI apply nem create/start/transporte do bundle implementados no host.
Esses componentes são bibliotecas internas para o coordenador ainda pendente,
sem rotas públicas, Docker socket na aplicação ou início automático por Make/CI.
[Contrato e fronteiras](../../architecture/decisions/0023-journal-probe-runtime.md).

## Consulta real somente leitura

Recibo privado0600 em diretório0700, conteúdo/hash/permissões reconferidos e
diretório sincronizado. ID **91aa6eaa5bc34447b49a7fe970e14a8e**, observado em
**2026-10-27T18:08:57.725953Z**, SHA canônico
**8aaee0e5025f25ac1ad3e8c916140737a3e77594025a3d6f28dc2a92ff38b53e**.

O template completo foi parseado na API Demo já existente, somente metadados.
Projeção de ambiente não retorna valores e mounts efetivos não retornam Source
físico. Imagem runner local75059996… passou apenas no gate UID/ausência de VOLUME/
ambiente; isso não prova código atual, proveniência ou existência do probe na imagem.
Não iniciar uma imagem antiga para descobrir seu conteúdo no volume original.

Demo ready/database/redis true; imagem da API permanece92ffbc4e…. Nenhuma senha
ou configuração humana mudou. O recibo mantém actual_probe_runtime_validated e
normal_operation_permitted false. Ele não contém aprovação ou evidência SIEM.

## Problemas encontrados e corrigidos

Revisão estática especializada encontrou override de LD_PRELOAD/LD_AUDIT possível
apesar de Python -I. Projeção de nomes/booleans e allowlist/valores fixos eliminam
essa passagem; regressões incluem loader, PATH, TMPDIR, duplicatas e PYTHONPATH.
Imagem Python local omite LANG: só imagem aceita ausência, receita define LANG
fixo e revisão do container o exige. Consulta real encontrou HostConfig.Mounts
opcional ausente; uso de index corrigiu a projeção e ganhou regressão opcional.

Outra revisão encontrou totais impossíveis para SUCCEEDED. Piso agora considera
SUCCEEDED/FAILED conhecidos e INTERRUPTED explícito; implícitos ficam limitados
aos INTERRUPTED conhecidos mais jobs adicionais. Seis regressões usam writer/probe
real em SQLite temporário, sem marcador. Os deltas foram reconferidos por leitura;
revisão estática não substitui testes nem demonstra runtime do laboratório.

## Limites e sequência

O plano antigo expirou e a PKI candidata exige conferência atual; nenhuma evidência
antiga foi reaproveitada como permissão. Próximo trabalho: coordenador fixo com
create/start e transporte limitado do bundle, plano/escopo/proveniência, vínculo
físico do banco Linux, journal antes do construtor Runner, novo mTLS/recusa de trust
antigo, binding ainda revogado e fechamento verificado. Só depois apresentar o
escopo completo para nova autorização específica, sem marcador no primeiro ensaio.

Consulta de ausência não é uma trava atômica do daemon; root/daemon/usuário local
continuam fronteiras de confiança. Não criar volume ausente, remover histórico ou
liberar reservas para fazer um gate passar. Jobs ambíguos continuam em quarentena.
Custódia externa adiada pelo usuário e PKI dos serviços Wazuh continuam separadas.

## Testes executados

- Suíte global local: **1.352 passaram/376,43s**, em ad75285, antes da correção
  final do piso/teto e seus seis novos casos. Cinco projeções opcionais leram
  apenas objetos Demo existentes, sem criar recursos.
- `make test-runner-activation` final, após6d4174a: **367 passaram/28,32s**.
  Inclui98 runtime,65 intents,28 cleanup,44 resultado e132 metadados/plano/ownership.
  Os seis casos novos e todo decoder corrigido foram executados nessa rodada;
  **1.358 casos distintos locais em rodadas separadas**, sem somar reruns.
- Lint completo aprovado: Ruff/format165 arquivos, mypy4, TypeScript e Prettier.
  Aviso upstream de TestClient/httpx permanece. Sem mudança de UI/API/runtime
  implantado; frontend/build/E2E não repetidos localmente neste incremento.
- Scanner completo do índice e source-review aprovados antes de publicar os
  documentos; contagens/resultado final do CI registrados no checkpoint seguinte.

Logs privados: .local/pki-milestone/probe-runtime-full-tests.log e
probe-runtime-activation-tests.log. CI de código6d4174a está em andamento no
momento deste registro; não é tratado como aprovado até finalizar.
