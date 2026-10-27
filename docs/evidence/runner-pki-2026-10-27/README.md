# Candidato offline da PKI do runner — 2026-10-27

Código validado: d6d49ad, continuação da preparação iniciada em2026-10-26.
Nenhum certificado ativo foi substituído. O Demo não depende desta PKI.

## Prova executada

Origem: `.local/linux-lab`, runner independente172.30.88.2. Somente cinco arquivos
públicos lidos; nenhum conteúdo de chave antiga, ids.env ou diário. Comparação
antes/depois confirmou bytes públicos e metadados dos arquivos originais iguais.
Auditoria do processo restringiu abertura da origem aos nomes públicos, negou
rede/importações de banco/worker/runner e permitiu somente comandos OpenSSL fixos.
Não é sandbox contra root, revisão do volume ou prova da posse das chaves antigas.

Inventário público SHA256:
`b4462e0ac8cbceb744a6a8c2751e22a22c49cc7dd233732a75945d457e989311`.
CAs válidas no inventário; folhas servidor/cliente originais **expiradas**.
Esse estado não foi corrigido no lugar nem ocultado pelo inventário.

Prepare e verify produziram candidato
`90204499ca2144aca175fe809538b7e7`, em pasta privada separada, com mesmos IDs e
endpoint, duas CAs/quatro pares novos/distintos e hash de descritor diferente.
Manifesto SHA256 canônico:
`24179f34ad0a2c708496e9b0b3798a18d547c4648975c95893330458f0ed8d5f`.
Descritor candidato:
`d1b616e115fecdf115652472656b4a82e6cd1c65f45b778f0239a2b4afbd566f`.
Hashes contêm somente dados públicos; chaves/arquivos privados não entram no Git.

Resultado inicial e nova verificação em2026-10-27:
`offline_candidate_verified_not_activated`. activation_performed,
database_modified, journal_opened, lab_started e normal_operation_permitted
permanecem **false**. A reverificação leu pares do candidato, nunca chaves antigas.
Validade curta exige nova verificação antes de uso; recibo não renova aprovação.

## Checks e limites

- 52 novos casos PKI cobrem geração, cadeia, SAN/EKU, IDs, drift, pares/validade,
  arquivos inseguros, falhas de geração/publicação e durabilidade/retry.
- Três casos exercitam echo TLS real somente em127.0.0.1, verificando SAN do IP
  configurado: novo par aceito, confiança antiga e cliente antigo recusados.
  Não há runner, API, diário ou marcador nesse teste.
- Um caso adicional impede commit de arquivo .key mesmo sem assinatura PEM;
  artefatos também excluídos do contexto Docker.
- Suíte local final `make test`: **839 Python passaram** em271,12s e
  **66 React passaram** em3,58s, incluindo quatro opcionais Docker. Aviso upstream
  de depreciação Starlette/TestClient-httpx permanece visível.
- CI executável d6d49ad: **835 Python passaram, quatro opcionais Docker pulados,
  66 React passaram**; lint/tipos/build/auditoria aprovados.
  [Run40409355739](https://github.com/Buraddomoon/AEGIS/actions/runs/40409355739).
- Lint local, auditoria e pip check passaram. npm: zero vulnerabilidades reportadas;
  DiskCache5.6.3/PYSEC-2026-2447 permanece achado conhecido/revisado e visível.
  Não houve dependência, migração ou alteração da imagem runtime.

A revisão estática especializada identificou fsync incompleto de ancestrais,
inclusive em retry após erro. Corrigidos ecb4713/a57f5da com regressões;
revisão final não encontrou bloqueador concreto nesse delta. Não é pentest.

Health local18780 confirmou ready/database/redis. Nenhum container Linux/Wazuh
em execução; nove volumes Wazuh históricos preservados. Nenhum SIEM consultado,
serviço de laboratório iniciado ou efeito real executado. PKI de Indexer/manager/
agente/Filebeat, ativação coordenada, novo binding/preflight e recuperação de jobs
sob vínculo alterado continuam pendentes. Custódia externa continua adiada.

[Operação](../../operations/runner-pki.md) ·
[Decisão](../../architecture/decisions/0018-offline-runner-pki.md) ·
[Revisão](../../security/review-runner-pki-2026-10-27.md).
