# Preparação nativa da #80 — ambiente novo e tentativa única

Este procedimento continua a implementação da #79. Preparar fonte, wheels,
imagens, PKI e proposta offline não autoriza startup ou efeito em laboratório.
Somente a #80 está sendo retomada; os ensaios históricos continuam encerrados.

## Ambiente proposto

`scripts/atomic_assay.py` compila uma receita fechada por pacote. Usa projeto
`aegis-atomic80-<id>`, identidades novas e três volumes próprios: `database`,
`journal` e `evidence`. Todos são preservados ao encerrar; nunca `down -v`.
Nenhum volume, banco, conta, binding ou diário original é montado/adotado.

Duas redes novas internas, IPv6 desativado e gateway mode isolated:
`192.168.253.0/29` para mTLS/controle e `192.168.253.8/29` para o backend.
Preflight consulta todas as redes/rotas duas vezes e recusa colisão/drift sem
alterar terceiros/qasrc. Nenhuma porta é publicada no host. O controlador
descartável acessa a API em `192.168.253.4:8080`; runner somente mTLS em `.2:8443`.
API e worker só participam dessas redes próprias; DB/Redis só do backend.

Imagens são IDs locais imutáveis. Runner/API/worker usam UID10001, rootfs RO,
ALL caps removidas e no-new-privileges. Runtime não recebe segredo do owner
PostgreSQL nem chaves privadas das CAs. Banco novo `atomic_assay`, owner novo
`atomic_owner`, credenciais próprias protegidas em diretório0700, sem argv/logs.
O PostgreSQL usa seu entrypoint oficial para inicializar o volume vazio; não é
rootfs RO. Redis não persiste dados e seu `/data` é tmpfs, evitando volume anônimo.

Limites: runner192MiB, API512MiB, worker256MiB, DB384MiB, Redis128MiB,
controlador128MiB e helper de administração256MiB (fases distintas). Pico
previsto1728MiB; exigir MemAvailable≥3072MiB antes de começar. Não alterar
memória, swap, sysctl, redes ou processos de outro projeto para passar o gate.
Chamadas possuem timeouts; janela de operação≤15min, run≤60s, efeito≤5s/lease2s.

## Schema e contas

O helper `atomic_assay_service.py bootstrap` exige URI/host/db/owner exatos,
schema public vazio e ausência de role runtime. Apenas nesse banco novo aplica
Alembic explicitamente até c8/36tabelas, seed versionado e grants mínimos,
criando duas contas temporárias próprias (administrador e operador).
Resposta ambígua não é repetida: o banco/intent ficam preservados.

`check` abre READ ONLY/REPEATABLE READ, confirma schema/tabelas/catálogo/allowlist,
nenhuma execução/dispatch/agendamento/relatório pendente e grants imutáveis.
É um gate separado para o ambiente novo; não amplia o gate histórico b7.
API/worker só são iniciados pelo coordenador depois do bootstrap/check explícitos.

O cliente usa a própria API: registro de lab novo inicialmente revogado,
preflight mTLS, autorização do lab, solicitação pelo operador e aprovação por
administrador ativo distinto, com scope hash exato. Não existe aprovação
sintética, bypass de RBAC ou execução direta do programa pelo controlador.

## Efeito e prova

A única definição é `atomic-file-permissions-v1`, GUID
`34ca1464-de9d-40c6-8c77-690adf36a135`, revisão
`9e283889776cbd42ebf9b7b25bc1ebfbad452157398ecbe0ab77415136c35673`.
Muda0400→0600 por fchmod em43bytes próprios; não executa shell/chmod/YAML
upstream ou outros GUIDs. Fonte/regra defensiva não configuradas: resultado
esperado INCONCLUSIVE, não DETECTED nem prova de ausência de coleta externa.

O fence host `attempt.json` é exclusivo/fsynced **antes do primeiro create**.
No controlador, `evidence:/evidence/run.json` preserva UUID/escopo/hash antes
de approve/start. O PostgreSQL e journal mantêm seus próprios intents/recibos.
Não repetir POST start, bootstrap, run ou pacote após perda de resposta.

Antes do efeito, o coordenador confere metadados nativos dos cinco serviços:
imagens, UID, limites, rootfs/caps, redes, ausência de portas e mounts somente
dos volumes/segredos próprios. O cliente verifica recibo/modes/hash, cleanup
CLEANED, JSON/HTML da mesma run e exatamente uma execução Linux.

Finalmente, tenta revogar lab e desativar as duas contas/remover suas sessões
independentemente de erro da API. O helper usa binding-review para confirmar
cleanup persistido. Sem confirmação, mantém recursos/workspace em quarentena;
sem remover arquivos desconhecidos ou liberar reserva. Com prova confirmada,
encerra somente o projeto próprio, mantendo três volumes/imagens/PKI/intents.

## Aprovação vinculada à proposta

O comando `build` usa somente blobs de main limpa, contexto novo e base local
fixada; wheels/locks conferidos, RUNs sem rede, pull=false e sem push. A base
própria é retida em tag nova com ID imutável conferido antes/depois; Docker29
não aceita um FROM sha256:ID como referência de base local. Check fresco confere
pacote instalado/versões/imports e assets de bootstrap. Tag exclusiva retém a
imagem anterior. Recibos locais não são assinatura ou atestado do publicador.

`prepare` gera PKI/identidades/segredos próprios, fixa imagens, hashes de todos
os arquivos e receita, e renderiza Compose sem criar recursos. A proposta é
válida por12h; expiração/drift bloqueiam, sem renovação silenciosa.

`run` exige package ID/SHA256 concretos e registro separado de autorização
humana para esse hash, `approved_by=user,one_attempt=true`; esse registro não
é gerado pelo prepare/build/verify. A instrução genérica para trabalhar a issue
não preenche essa autorização de startup/efeito. Ao apresentar o pacote,
informar IDs/imagens/prazo/efeitos/limpeza e pedir confirmação específica.

Testes de software usam somente temporários, mocks e schemas PG descartáveis;
não criam Docker/Lab. Conferir comandos/contagens, CI, imagens e proposta reais
nos comentários da #80 antes de operar. Não fechar #80 com preparação apenas.

## Ensaio encerrado em18/11/2026

O pacote202afac5 foi autorizado e consumido em uma tentativa,
COMPLETED/INCONCLUSIVE/CLEANED, synthetic=false. Lab revogado, contas próprias
inativas/zero sessões, recursos próprios encerrados, três volumes preservados
sem consumidores. [Provas e limites](../evidence/atomic-execution-2026-11-18/VERIFIED-80.md).
O procedimento é referência de controles; não autoriza repetir esse pacote,
reativar recursos ou iniciar outro ensaio. Preservar PKI/imagens/fences/histórico.
