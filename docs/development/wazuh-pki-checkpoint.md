# Checkpoint da entrega #6 e dependência #149 — 12/11/2026

- #55 concluída: `6d42701`, inventário/candidato offline dos serviços Wazuh,
  sem chaves antigas/credenciais/runner/volumes. Perfil4.14.9/amd64/digests fixados.
- #56 concluída: `0b65f70`, plano/overlay de cinco arquivos, recheck e diário de
  troca/rollback. Sem CLI de lifecycle/startup.
- O usuário autorizou incluir #149 **somente offline**. #150: `ff0b29e`, ADR0034 e
  duas faixas fixas; #151: `6c2b637`, SAN/destinos/inspeção/coerência e transição
  explícita/versionada. #152: aceite offline/targets e recusas de baseline; hash
  final e sincronização registrados no comentário da subissue. Não houve startup.
- Perfil atual: execução192.168.253.8/29 e telemetria192.168.253.16/29. O preflight
  de leitura passou:20redes/61rotas, nenhuma sobreposição observada; SHA256
  `57bbdfc13bc8705d36c7ac7b922d2a3b280e4cdb25221973be13772fed726f62`.
  Nenhuma rede foi criada/reservada; qasrc e históricos intactos.
- #57 e #6 **abertas**. [Escopo TLS e bloqueios](../../labs/wazuh/TLS-ASSAY.md).
  A dependência de código/rede #149 foi atendida offline; recursos e autorização
  específica de startup/leitura/TLS continuam pendentes. Leitura ao concluir a #152:
  recursos5.307.334.656bytes MemAvailable (<8GiB),16CPUs,415.276.077.056bytes
  livres no Docker, vm.max_map_count1048576. Não liberar memória parando terceiros.
- Validação #151:244testes locais aprovados. #152: `make test-wazuh-preparation`
  114+84=198aprovações; `make test-wazuh`60aprovações após selecionar em memória
  credenciais da infraestrutura local já existente. Schemas descartáveis/Redis15
  sequenciais, sem mudar contas/grants/arquivos de configuração. Contagens têm
  sobreposição. `make lint` completo e staged/release-check passaram.
- CI integral `6c2b637`: [success](https://github.com/Buraddomoon/AEGIS/actions/runs/43245368974),
  quatro jobs Python e React conferidos. Fonte anterior `0b65f70` também teve
  [success](https://github.com/Buraddomoon/AEGIS/actions/runs/43242399008).
  A rodada final da #152 é separada; conferir comentário para o hash/run, sem
  apresentar validação anterior como CI do código final.

Retomar #57 somente com recursos e autorização específica do pacote atual. Não
iniciar o laboratório a partir deste checkpoint. Gerar material real novo apenas
quando os gates permitirem; usar `wazuh_pki.py prepare --migrate-wazuh-network` na
origem antiga, sem rehash/reescrita. Planos `/1` permanecem históricos; `/2` exige
candidato atual e não autoriza efeitos. A PKI do runner é separada; o ensaio TLS
não o inicia. Não abrir/migrar volumes, reutilizar autorizações/pacotes consumidos
ou fechar #6 com #57 pendente. Nenhuma nova evidência defensiva/implantação real.


## Retomada da #57 — 2026-11-12T18:27:26.434896+00:00

Inventário local protegido em `.local/wazuh-tls-reviews/9f79a7f1789c48b1a7a08b6b1adcbd9e/review.json`, SHA256
`9d4775fafdbe896511da41c4f5f3a2c30e78f779f1ce5a0ae7489c53a5b22986`. Duas leituras coerentes confirmaram as três imagens oficiais4.14.9
fixadas e o leitor histórico local por ID, nove volumes próprios e zero containers
ou consumidores dos volumes. Só metadados/arquivos de configuração protegidos;
nenhum conteúdo de volume, chave antiga, SQL, startup ou certificado novo.
Origem pública conserva o SHA256 histórico. Arquivo host-only, não publicado.

A revisão fixa um único ensaio de até15min: Indexer, manager/Filebeat, agente001 e
leitor na telemetria192.168.253.16/29, sem portas publicadas, marcador, runner,
observador ou banco. Não é plano de ativação nem autorização; os hashes de
candidato/plano continuam pendentes do gate de recursos.

Leitura mais recente:MemAvailable4190216192bytes
(~3.90GiB), mínimo8GiB;
16CPUs, Docker livre414918975488bytes,
vm.max_map_count1048576. Redes20/rotas61 sem sobreposição;
mesmo hash de observação anterior. O usuário foi informado da necessidade de
recursos; aprovação de startup ainda não solicitada/concedida. #57/#6 abertas.
Essa retomada é inspeção real de metadados; nenhum teste de TLS nativo executado.


## Recursos liberados e preparação concreta da #57

Sob instrução explícita do usuário, Firefox/Slack e seus descendentes foram
encerrados com SIGTERM; zero sobreviventes, sem SIGKILL. Preflight passou:
MemAvailable9.553.633.280bytes (~8,90GiB). Nenhum projeto Docker foi parado.

Candidato `0dfb54bbe5c54423ad37ef2309ae369d` criado separadamente com transição
explícita; manifesto `c38691e29f46429e230bcdb73a528b74164ced98275ce54932ba98ea192e1a6d`.
Plano `5175cd2f7c0f4ef68a1ef52f8d124df5`, SHA256
`374d60c68d0e10ae42bb7702f4193d2555d154857e667f119a4f51b22a26562a`.
Ambos verificados, não ativados. Origem permanece intacta. Preparação privada em
`.local/wazuh-pki-plans/5175cd2f7c0f4ef68a1ef52f8d124df5-assay/preparation.json`.
Revalidar TTL/recursos/metadados; hashes não são autorização.

Leitor fixo `scripts/wazuh_tls_probe.py` e projeção TLS-only em
`scripts/wazuh_tls_scope.py` preparados/testados sem containers reais. Leitor usa
GETs fixos, CA/SNI/IP/fingerprint, principal exato, ACL de leitura, saída redigida e
credenciais stdin. Não testa escrita. A projeção usa só três serviços, rede
telemetria e seis volumes externos existentes; nenhum runner/observador/DB/API.
O ensaio real #57/#6 ainda depende de autorização específica do pacote final.
