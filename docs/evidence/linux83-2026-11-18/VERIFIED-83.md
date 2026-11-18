# #83 — dois ensaios nativos autorizados, verificados e encerrados

18/11/2026. Após a [proposta concreta](../../../labs/linux/LINUX83-REQUEST-2026-11-18.md),
o usuário respondeu **“autorizo”**. A decisão foi vinculada separadamente aos
dois hashes, com `approved_by=user,one_attempt=true`, em arquivos exclusivos
0600/fsync. As duas autorizações/tentativas foram consumidas e estão encerradas;
não há replay, startup futuro ou operação contínua autorizados.

Escopo exclusivo #83, dependência #82 concluída. O pai #15 aguarda aceite conjunto;
esta sessão não inicia outra entrega ou reescreve provas anteriores.

## Execuções efetivas

| Campo | Processo benigno | Shell Unix fixo |
| --- | --- | --- |
| Pacote | `0a85302e48bc4ecb9f854ba3881f89c0` | `22431af466174de6ab37ae9261d1c672` |
| Tentativa | `7832bf68-ce2a-4d52-87e0-132a7d42f369` | `5a687cac-8245-47fe-bf3d-983db6356fb7` |
| Fence consumido UTC | 14:10:34.453839 | 14:13:05.691130 |
| Run | `86163bb8-28fe-46eb-8bd5-1cdb59f4b2fe` | `38e9d86e-8664-433e-83bc-8a37a378b612` |
| Execução | `6c6e1f53-d09f-44f8-a1e9-e534f1a45350` | `903aeaf7-6ee9-45aa-bf7e-0b32912fd62a` |
| Início do programa UTC | 14:10:55.734903 | 14:13:26.892606 |
| Fim do programa UTC | 14:10:55.739726 | 14:13:26.897180 |
| Resultado | COMPLETED / INCONCLUSIVE / CLEANED | COMPLETED / INCONCLUSIVE / CLEANED |
| synthetic | false | false |
| Filho/PID no namespace próprio | 10 / exit0 | 10 / exit0 |
| Artefato próprio | 43bytes | 43bytes |
| Stdout | 0bytes | 43bytes iguais ao marcador+newline |
| Eventos/evidências defensivas | 0 / 0 | 0 / 0 |

Foram duas chamadas de `atomic_assay.run(package_id, expected_sha256)`, uma por
pacote, sem retry. O segundo só foi chamado após conferir o final-review do
primeiro: cleanup confirmado, contas/lab revogados e zero containers/redes/
consumidores. Nenhuma etapa ou campanha teve falha nesta operação. A segunda
tentativa também terminou com todos esses controles confirmados.

O primeiro programa executou somente `/bin/true <marker>`, sem associação
ATT&CK. O segundo executou somente `/bin/sh -c <printf fixo> <marker>`, associação
limitada à primitiva T1059.004, sem shell/comando livre. Cada wrapper recolheu o
filho antes de gravar recibo; o supervisor confirmou artefato/hash e recolheu o
wrapper antes de publicar o terminal. Nenhum Atomic/YAML foi executado.

## Aprovação segregada e integridade

| Campo | Processo | Shell |
| --- | --- | --- |
| Solicitante | `34975388-e783-4142-9ed3-810aa8a37d8f` | `089d1ac6-28e8-44d4-99b3-e05ed8da6623` |
| Administrador aprovador | `78b14eaa-e2b8-4456-9716-f38f26251834` | `b17f544e-1687-4cc8-a0b8-d287912b4587` |
| Scope SHA256 | `47606b7210feade28ff507d6f8b55a8eee7f6eef98311593340c73784a014d54` | `30251dd978fe3a6eefd2151f9c5591925721fcabe180f6d94f2834f23a31091c` |
| Artefato SHA256 | `3f6586269a83bae589233660945c4c6f23b2e873285cb9056d9a5819d9b3092a` | `51a53b66ccb785db7432466dd8d162b5392ef39552a7ac0a28aadc9975facaf1` |
| Recibo SHA256 | `bac7aa2e905848c2e56ac8ee5029f6d9aed752a0709bfcd84f609f4ea37aedb7` | `bc03113a416f8eacee1ab7c32d719c336d64dc187328a8f4f4e24ee64e30ac06` |
| Cleanup SHA256 | `487c1aa632007dd3f01e174bb768ebae85a5f7a74fbf28ab9e022b6b5235dc5b` | `846381c63ff3009bc4d7c5a4beef47d8cdadf39311dd9a0ed513f206e5e1ceaa` |
| JSON: integridade de run | `3002ad15768332941009866ac6d0a2fc4bc28681b32329bdc6377a808f0e449a` | `345c6f29439c2721a75b5fbeccc503d188e6e4b735125446153a960427d7ec9c` |
| HTML SHA256 | `613e2930e3b2e0d6ba43f4e8f6c17aa3908383bf29eca65b6200105487407fee` | `f924193bee233cc696604f4390438bfbc88806050b85cde306d87f126de5d548` |

Solicitante/aprovador distintos e scope da aprovação idêntico ao da run,
conferidos nos objetos persistidos retornados pela API. JSON de cada relatório
recalculado como digest(run); recibo, cleanup e artefato também recalculados.
JobView do cleanup validado com identidade/spec/geração/recibo exatos, estado
SUCCEEDED/CLEANED, mesmo lab/ativo/runner do pacote. Stdout vazio no processo
e hash/43bytes exatos no shell. Esses hashes são integridade, não assinaturas.

Histórico/relatórios lidos da mesma run após completar, sem reexecução. UUID/scope
haviam sido persistidos no volume de evidência antes de approve/start. Recibos,
dispatch, aprovações, resultados e cleanup permanecem no PG e no journal próprios;
provas brutas/JSON/HTML/segredos ficam locais, fora de Git. Aqui só metadados.

## Runtime nativo e encerramento

Nos dois projetos, bootstrap explícito de banco vazio e gate READ ONLY confirmaram
c8e4a6d21f90/36tabelas, catálogo, allowlist e grants mínimos. Preflight mTLS/
identidade/allowlist passou pelo fluxo da API antes de autorizar cada lab e de
despachar; identidade TLS não substituiu a aprovação por outro usuário.

Inspeção real dos cinco serviços antes do efeito confirmou os mesmos IDs de
imagens da proposta, nenhuma porta host ou rede externa e mounts somente próprios.
API/worker/runner10001:10001, rootfs RO/caps ALL removidas/no-new-privileges,
memória512/256/192MiB, CPU1 e64PIDs. Redis999:999/RO/tmpfs128MiB; PG com entrypoint
oficial/rootfs gravável384MiB. Redes internas isolated do pacote, sem qasrc.
MemAvailable3326MiB observado antes da primeira; piso3072MiB rechecado e aceito
pelo coordenador em ambas. Não houve alteração de host/sysctl/swap ou outros projetos.

Cada helper final confirmou `own_accounts_sessions_and_authorization_disabled`,
duas contas inativas/zero sessões e `safe_to_stop=true` após consulta do binding-
review. Labs revogados, reservas liberadas após cleanup confirmado. Docker down
restrito ao projeto, sem `-v`; verificações posteriores:

- zero containers próprios, inclusive parados;
- zero redes próprias;
- exatamente três volumes novos por projeto e nenhum consumidor, inclusive
  containers de outro projeto;
- quatro contas UI próprias inativas/zero sessões no total; diários, fences,
  pacotes/PKI/imagens/credenciais próprias preservados, autorizações consumidas.

Volumes retidos: sufixos `_database`, `_journal`, `_evidence` dos projetos
`aegis-linux83-0a85302e48bc` e `aegis-linux83-22431af46617`. Seis ao todo,
zero consumidores. Não reabrir/reativar a partir deste relatório.

## Fonte, verificações e limites

Código/imagens da fonte `1dcff254b7af0e699676cdfcbfd1508e9f747cec`, coordenados
com HEAD `729b9d8fc139c13e3317ef18293bf03ee8590432` (somente Markdown posterior).
Runner8b173422/aplicação b25b2bc0; IDs completos na proposta. A fonte executável
não mudou durante os ensaios; nenhuma implantação em Demo/originais.

[CI3733Python/9skips e98React](https://github.com/Buraddomoon/AEGIS/actions/runs/44317530894)
SUCCESS da preparação, com quatro partições e React conferidos; não é a prova
nativa acima. Software64casos de preparação/autorizações e73API/worker locais,
limites/falhas históricas em [PREPARATION](PREPARATION.md). Nesta fase foram
executados dois ensaios nativos e leitores/inspeções dos seus dados, sem repetir
suítes ou adicionar testes que só espelhem Markdown. Checks de repositório e
revisão staged/segredos serão registrados no comentário de encerramento.

Sem coletor/regra defensiva, os dois resultados são INCONCLUSIVE: recibo/exit/
stdout/arquivo não são alerta e não demonstram eficácia de detecção ou ausência
de coleta externa. A correspondência limitada a T1059.004 não cobre toda a
técnica/adversário. Demo, originais Linux/Wazuh b7, backups, PKI, IDs, journals,
fences, contas e imagens históricas preservados. Não houve envio de dados a SIEM
ou terceiro, instalação pesada ou novo comportamento fora da allowlist.

#83 tem critérios nativos atendidos e operação encerrada. #15 permanece aberta
até o aceite conjunto. Autorização consumida; parar neste escopo.
