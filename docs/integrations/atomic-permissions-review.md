# Revisão de um único Atomic — #78

Revisão offline em17/11/2026 para a entrega #14. Não é autorização de
laboratório, aprovação de campanha nem evidência de execução/detecção.

## Identidade e reprodução

Fonte oficial: [redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team/blob/a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6/atomics/T1222.002/T1222.002.yaml),
commit `a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6`, consultado pela API GitHub.
Arquivo `atomics/T1222.002/T1222.002.yaml`:9653bytes UTF-8,
SHA256 `f453e844306df372cf600ddd59d15626a83d3dd83cd5a4b3e5fe5175b4204f3b`.
[Fixture integral](../../fixtures/atomic/T1222.002.json): o campo `content`
preserva os bytes; o hash não é o do envelope JSON. A
[licença MIT](../../fixtures/atomic/LICENSE.txt) é idêntica nos dois commits
das fixtures:1078bytes,
SHA256 `65af6027045d23175366eab50e460ab3ee7790e591cb84cc32c78ac63a4c90e1`.
Hash identifica bytes, sem autenticar assinatura do autor.

Selecionado somente GUID `34ca1464-de9d-40c6-8c77-690adf36a135`, primeiro teste
de T1222.002, alteração numérica de permissões. Linux/macOS declarados upstream;
a adaptação ÆGIS é exclusivamente Linux. O teste recebe dois inputs upstream,
modo numérico e caminho, e usa um executor shell. Não declara dependências,
elevação ou cleanup. Isso não prova ausência de risco e não permite executar
o shell ou outros GUIDs presentes no documento.

Reprodução sem execução: decodificar o JSON, calcular SHA256 de
`content.encode('utf-8')`, carregar com o parser seguro e selecionar o GUID
acima. `pytest tests/test_atomic_review.py -q` verifica procedência fixada,
comportamento selecionado e projeção de metadados sem capacidade de execução.

## Configuração fechada para implementação

- Criar exclusivamente `proof.marker` dentro do diretório UUID privado de um
  job, com43bytes do marcador canônico gerado pela aplicação.
- Arquivo regular, dono igual ao UID efetivo, um link, sem symlink. Criar com
  exclusividade e modo0400; observar0400, alterar para0600 pelo descritor aberto
  e observar0600. Nenhum caminho ou modo vem do YAML/API/usuário.
- Usar programa Python próprio fixo e `fchmod`, sem shell, `chmod` externo,
  recursão, plugins, downloads ou instalação de pré-requisitos. Vincular revisão
  ao GUID, commit/hash YAML, licença, versão/configuração e hash desse programa.
- Cleanup explícito remove somente `proof.marker` e `receipt.json` desse UUID;
  desconhecidos, symlinks ou hardlinks retêm a reserva para revisão. Cancelamento,
  timeout, reinício e resposta perdida não autorizam replay nem dispensam cleanup.

A técnica real é **modificação de permissões de arquivo**. Criar o marcador,
isoladamente, não representa T1222.002. A adaptação troca o processo `chmod`
por `fchmod`; não testa detecções de command line/process creation do `chmod`
nem reproduz um shell upstream. O arquivo nunca é executado; não há permissão
para outros usuários, setuid/setgid, ownership change, evasão de controles,
persistência, coleta de credenciais, dados externos ou exfiltração. O diretório
pai permanece0700. A mudança400→600 só acrescenta escrita ao próprio dono.

## Pré-requisitos e incompatibilidades

Exigir executor/cliente com a mesma revisão fixada, workspace e estado privados,
UID sem privilégios em lab próprio isolado, código/imagem compatíveis, binding
específico revisado, preflight mTLS atual, laboratório autorizado e aprovação
segregada do escopo imutável. O programa deve verificar restrições antes do
efeito; falha não tenta instalar/corrigir o ambiente.

Os Labs originais continuam b7/33tabelas, parados e com autorizações consumidas.
O catálogo Atomic offline c8/36 não amplia os gates b7. Os perfis históricos
permitem somente `linux-file-marker/v1`; este GUID permanece incompatível com
esses perfis e não é disponibilizado por importação/revisão de metadados.
Nada nesta revisão altera imagens, volumes, rede qasrc, PKI, diário ou fences.

## Provas necessárias nas etapas seguintes

#79 deve demonstrar o adaptador fechado e negativas em temporários: drift de
GUID/commit/hash/programa/configuração, YAML sem permissões, RBAC/CSRF/aprovação,
dispatch durável antes da RPC, recibo de execução separado de telemetria,
timeout/cancelamento/restart/cleanup e bloqueio de replay.

#80 exige pacote de uma tentativa com IDs/imagens/revisão/prazos/efeitos/rollback
concretos e autorização humana específica antes de qualquer startup/efeito.
Sem consulta defensiva correlacionada, não declarar DETECTED ou eficácia de
T1222.002. Fixture/loopback não são ensaio nativo nem implantação. O pai #14
permanece aberto enquanto esse aceite conjunto estiver pendente.
