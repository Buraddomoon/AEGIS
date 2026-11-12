# Checkpoint da entrega #6 — 12/11/2026

- #55 concluída: `6d42701`, inventário/candidato offline dos serviços Wazuh, sem
  chaves antigas/credenciais/runner/volumes. Perfil4.14.9/amd64/digests fixados.
- #56 concluída: `0b65f70`, plano/overlay exclusivo de cinco arquivos, recheck de
  inputs e diário/procedimento de troca/rollback, sem CLI de lifecycle/startup.
- #57 e #6 **abertas**. [Escopo preparado e bloqueios](../../labs/wazuh/TLS-ASSAY.md).
  #149 está aberta e conflito de rede foi reproduzido somente por leitura.
  Preflight de recursos recusado:6.495.100.928bytes disponíveis, mínimo8GiB.
  Falta autorização específica de startup/leitura/TLS após resolver os gates.
- 132testes locais relacionados passaram, incluindo Compose renderizado e TLS em
  loopback; Ruff/format/mypy completos e staged/release-check passaram. Nenhum
  Wazuh/Linux/volume/banco/marcador iniciado, nem nova evidência defensiva criada.
- CI integral em `6d42701`: [success](https://github.com/Buraddomoon/AEGIS/actions/runs/43240888206).
  CI de `0b65f70`: [run](https://github.com/Buraddomoon/AEGIS/actions/runs/43242399008),
  ainda pendente quando este checkpoint foi escrito; não declarar verde sem
  conferir os quatro jobs Python e React.

Retomar somente #6/#57 quando houver condições. Se o usuário ampliar o escopo para
#149, seguir suas próprias subissues antes do ensaio e revisar o perfil rígido
antigo de `wazuh_pki.py`; não apenas trocar o digest para contornar a revisão.
Gerar candidato/plano reais novos depois da transição, com TTL atual. Não reutilizar
pacotes/autorizações históricas, alterar qasrc, abrir volumes sem aprovação,
iniciar stack para satisfazer testes ou fechar o pai com a #57 pendente.
