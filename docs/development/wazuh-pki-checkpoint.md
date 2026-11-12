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
  específica de startup/leitura/TLS continuam pendentes. Último preflight de
  recursos:5.307.334.656bytes MemAvailable (<8GiB),16CPUs,415.276.077.056bytes
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
