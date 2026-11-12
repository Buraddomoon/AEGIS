# Renovação TLS Wazuh — aceite #57/#6 em 12/11/2026

**VERIFIED_AFTER_RECONCILIATION / CLEANED**, observado até
`2026-11-12T21:02:45.156948+00:00`. Ensaio real limitado a conectividade,
identidade e leitura, sem marcador. Serviços encerrados; nenhuma ativação
permanente. As duas autorizações de uso único estão consumidas.

## Histórico e autorização

A [primeira tentativa5175cd2f](README.md) permanece INCONCLUSIVE/CLEANED.
Seu relatório e resultado não foram alterados. O usuário autorizou separadamente
um novo ensaio único do pacote16e48a04, condicionado a CI/preflight aprovados:
Indexer, manager/Filebeat, agente001 e leitor, rede isolada192.168.253.16/29,
até15min, volumes existentes, sem marcador, banco, download ou build, com cleanup.

Antes do segundo startup, a CI integral da fonte `0acf359` passou nos quatro jobs
Python e React: [run43303306711](https://github.com/Buraddomoon/AEGIS/actions/runs/43303306711).
Gates atuais de recursos, redes, imagens, metadados, candidato e plano passaram.
Imagens oficiais Wazuh4.14.9/amd64 fixadas em `labs/wazuh/images.json` e leitor
local por ID; sem pull/build. Candidato/plano novos, sem reutilizar o primeiro.

| Artefato host-only | SHA256 (JSON canônico; operador: bytes) |
|---|---|
| Manifesto do candidato9dbcf74494ae45caa53eff0e8df00abe | `a05e0b87d6716ac1d17c60dd48c442c7d53605173ea937c952ce15a6c9872892` |
| Plano16e48a04fb284dad92d6fbe5ba201cd1 | `68718347d623c8ee74ef7f73809b90b7ddacf8111388cd9a3a8247fecc0772d0` |
| Pacote de autorização final | `2bacd56149a32192c4e9ede86804818edb97b05b7f79ab3fa340e633bb3957cb` |
| Operador congelado antes do efeito | `5bc22b148747dc7aa2b3dfb6cb13c7ecb9864dc79e11100b3ef15482a8bba577` |

JSON canônico: UTF-8 de `json.dumps(value, sort_keys=True, separators=(",", ":"))`,
sem newline. O arquivo de autorização formatado tem SHA256 dos bytes
`f891f595a7df16d89e8ae1bff875701e165c0e569d0277258be6e8a7ee7d59b9`.
Os hashes identificam os artefatos, sem equivaler a assinatura ou autorização.
Arquivos privados, Compose com credenciais, chaves e logs não foram publicados.

## Observações reais do segundo ensaio

Horários UTC; início `20:55:56.975838`, dentro da janela autorizada.

| Etapa | Observação |
|---|---|
| Indexer —20:56:25.899377 | Nova folha observada, CA/cadeia/SNI/IP verificados. SHA256 DER `b6b4ee3babf46451f59f6d3436326f7e19f65c9172076d59075c96a1b22e3455`, igual ao candidato |
| Filebeat —20:56:29.343045 | `test output` exit0, destino/CA esperados, verificação `full`, cadeia habilitada, TLSv1.3 |
| Agente/gestão —20:56:53.337159 | Manager:001/aegis-marker `Active`; estado local:`connected`. API de gestão realmente escutando somente em loopback interno, sem listener LAN |
| Leitor —20:56:53.565100823–20:56:57.636909812 | Exit0, sem OOM, TLSv1.3 e mesmo DER; principal/role reais, leitura de alertas e negativas de ACL verificadas |

O agente usa seu canal seguro e identidade pré-provisionada; `Active/connected`
não é apresentado como handshake X.509 do agente. Credenciais existentes
preservadas. O leitor executou somente cinco GETs fixos: raiz, authinfo,
permissionsinfo, busca `size=0` em `wazuh-alerts-4.x-*` e negativa403 da busca no
índice de segurança. Consultas não retornaram documentos de alertas ao relatório.
O resultado foi `tls_identity_and_read_acl_verified`: principal e leitura
verificados, acesso à API Security e ao índice de segurança negados.

## Reconciliação sem replay

O coletor de runtime inicialmente interpretou o label de build
`com.docker.compose.service=migrate` herdado pela imagem como papel de execução.
Retornou conservadoramente INCONCLUSIVE/CLEANUP_UNCONFIRMED e preservou o leitor
já encerrado e a rede própria, após remover os três serviços Wazuh. O arquivo
original `outcome.json` permanece intacto, SHA256 dos bytes
`ce0e4696a18232a4985dfe6a9b0ceaa39ef340146027ea37746a712047dbe3e8`.

A reconciliação verificou o container original pelo ID imutável
`fc26d2e61d2e1953f47a3990cabd40dcbe6e3b18e2a4a61929ef97debfc7d65d`, nome,
projeto, label do ensaio, imagem
`sha256:afec185e570d54652f0917de8adf4034fc97869d0ebb1a4bbb1fff39c0cd8a08`,
entrypoint `python` e comando `/review/probe.py`. Conferiu usuário10001:10001,
readonly, memória128MiB/PIDs32/CPU0,5, cap-drop ALL/no-new-privileges,
ausência de portas/devices/privilégios, somente telemetria e dois binds RO
(probe e CA pública), além dos hashes do código. O label herdado foi confirmado
na imagem. Nenhuma migração ou acesso a banco foi executado.

A saída redigida foi recuperada do container original, sem novo start/probe.
Intents adicionais foram persistidos antes de remover esse container encerrado
por ID e a rede própria comprovadamente vazia. Inspeções repetidas confirmaram
zero containers do projeto e zero consumidores dos volumes, nove volumes
originais preservados e configuração da origem intacta. O startup pode escrever
estado/logs normais nos volumes; não se afirma identidade byte a byte dos dados.

`reconciled-outcome.json` foi acrescentado, com resultado
VERIFIED_AFTER_RECONCILIATION/CLEANED. SHA256 dos bytes:
`a1a7b5576eae836705e3471528c6ce23c1ce723b9ea62348647a7a9b8bc3f933`.
Metadados antes/depois:
`e0931a45fd858ff0b4013846dbe13210fe2fe343a110b3536860b6efb936ea29`.
Inventário público da origem preservado:
`eb3e7008f8bc0fffcf56c7f126409c0b9d99dd6b4cc933f8a0be491550a9f85b`.

Planos/candidatos, outcomes originais, saída recuperada, runtime, intents,
reconciliação e consumo da autorização permanecem protegidos em `.local`.
`scripts/wazuh_tls_readiness.py` separa a identidade do comando do label herdado;
o helper foi também conferido offline contra o runtime salvo. Mounts, limites,
hashes e resultados continuam exigindo verificações próprias.

## Validação e limites do aceite

`make test-wazuh-tls-review`:114passaram, com aviso conhecido Starlette/httpx.
Inclui TLS real de loopback e fixtures de escopo/probe/prontidão/identidade;
não inicia Wazuh. Ruff, format, mypy e checks staged/release aprovados na revisão
final. A CI da revisão final será registrada nos comentários das issues, separada
da CI da fonte usada no ensaio acima.

O aceite comprova renovação e conectividade reais no escopo aprovado da #57.
`write_acl_verified=false` e `write_request_performed=false`: nenhuma escrita de
teste foi enviada; negativa de escrita não foi comprovada. Permissions Info só
avalia acesso à API Security. Sem marcador, alerta novo atribuído ao ensaio,
DETECTED, cobertura ATT&CK ou alegação de eficácia SIEM/EDR. Sem runner,
observador, API/worker da plataforma, banco/migração, binding/campanha ou nova
conta. A configuração antiga e PKI histórica permanecem preservadas, sem tentar
operar com certificados expirados. `normal_operation_permitted=false`.

Não reiniciar estes pacotes, apagar intents ou reutilizar aprovações. Qualquer
operação futura exige escopo/gates/autorização próprios. Esta entrega termina
com o laboratório parado e o conjunto #55/#56/#57 aceito para fechamento da #6.
