# Imagem de preparação do runner — 2026-10-30

Build de desenvolvimento concluído, sem iniciar o Linux Lab. A imagem inclui o
modo de identidade, o probe /2 e o transporte que vincula o certificado cliente
à conexão TLS. O build não é um ensaio de ativação de PKI.

| Referência | Valor |
| --- | --- |
| Commit de fonte | `1c23ee49d6a62ed3dbd14b3c7968dfdd22479658` |
| Fonte selada, SHA256 do JSON canônico | `d7c788d66194c5b6d7d227745e8ca794d1ab7834893fb23550a662c381919c6c` |
| Build ID | `5ccbca482dd649b58f90b89d85c4d885` |
| Plano, SHA256 do JSON canônico | `51f44981f7ccba787295f16f8452e6c184ecf98837eb5cb5bc9d992ff057e675` |
| Recibo, SHA256 do JSON canônico | `dfa0b726b3c21ab35610bbd2af86c15c03ec45426ce81ca0b12e644f550d8e70` |
| Imagem nativa, manifest digest | `sha256:526267ad8a54df12ffe130724874bb79bcdbb6ecb61345afe3a1ddc1d3085be5` |
| Config digest | `sha256:3d7c58b711aa9b46d23cc37d8f80408319e3adc39334fb54b4200678ccdc47fa` |
| Base oficial fixada | `docker.io/library/python@sha256:aaf08c5490d52cd92bc27142a5215b1e47355a5eaf9adfad2a0fbc022d0b5490` |

Exportação:67 arquivos versionados, dos quais64 pertencem ao pacote Python. Foram
conferidos46 wheels por hash (21.223.287 bytes), sem instalação no host. O build
usou contexto privado/allowlist, base local por digest e rede `none` nas etapas
RUN; pip usou somente os wheels conferidos. Imagens históricas foram preservadas.

O checker executou como UID/GID10001 e confirmou os64 arquivos instalados,
43 versões de runtime e3 versões de build. Imports de probes/servidor e guard de
compatibilidade Uvicorn0.54.0 passaram. O cliente do build terminou com código0;
revisão posterior do recibo/fonte atual e perfil da imagem passou por inspeção
somente leitura, sem VOLUME implícito, portas expostas ou labels herdadas.

Após o build, consultas de metadata do projeto Linux observaram0 containers,
0 redes e0 consumidores dos volumes journal/postgres-data. Não houve startup de
runner/API/worker/DB/Wazuh, marcador, atualização da PKI ativa ou escrita de binding.
Não foi gerado candidato novo para substituir o candidato histórico expirado.

Limites: verificação local sob confiança no host/daemon; sem assinatura de
publicador. Build/imports e metadados não comprovam handshake, mounts ou isolamento
de um container do laboratório em execução. `identity_mode_runtime_verified`,
`activation_verified` e `normal_operation_permitted` permanecem falsos. Próximos
componentes: cliente isolado, captura limitada de resultado, gates/coordenador e
procedimento concreto com autorização específica antes de qualquer ensaio nativo.

Recibos, contexto e logs completos permanecem somente no armazenamento privado
local `.local`; não são incluídos no repositório ou enviados como evidências.
