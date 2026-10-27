# ADR 0018 — Candidato offline para rotação mTLS do runner

Data: 2026-10-26. Status: implementado e validado offline em 2026-10-27.

Escopo: inspecionar somente certificados públicos/configuração do runner e preparar
um conjunto candidato separado, com duas CAs novas e novos pares de chave/certificado.
Preservar runner_id/laboratory_id/asset_id, URL/IP e nomes de secrets; nunca recriar
identidade/journal para renovar certificados. Sem aplicar, trocar paths ativos,
consultar banco/Docker/SIEM ou iniciar runner/efeito. PKI do Indexer/manager/agente
Wazuh não entra neste incremento; o transporte do runner é compartilhado pelos overlays.

CLI host-only inspect → prepare → verify, com hashes revisados. Ler somente os
cinco arquivos públicos fixos da origem, sem chaves/ids.env/diário. Diretório próprio
0700, arquivos regulares limitados, sem symlinks/hardlinks/FIFO. Prepare exige hash
do snapshot público e cria destino exclusivo em área privada; nunca sobrescrever
ou limpar origem/candidato anterior. Falha não emite recibo de sucesso e pode
reter material incompleto, inclusive manifesto após erro final de durabilidade.
Presença do arquivo não comprova prontidão: reverificar explicitamente. Verificar novamente a origem antes de publicar o manifesto.

Sem nova dependência: OpenSSL3 já usado pelo laboratório. Comandos fixos sem shell,
ambiente saneado/sem OPENSSL_CONF de usuário/proxies/providers personalizados,
preservando configuração e política padrão do OpenSSL do sistema,
entrada/saída limitada e timeout. Inspeção valida estrutura/cadeia/purpose/SAN/CN
com material público copiado em temporários privados; pode ignorar tempo **só**
para inspecionar a cadeia expirada, mostrando validade/expiração separadas. Esse
resultado não aprova certificado para uso atual. Verify do candidato exige tempo
atual e pelo menos24h de validade restante nas folhas; roots7dias/folhas2dias.

Candidato valida assinaturas/cadeias, CAs distintas, EKU servidor/cliente, SAN de
IP fixo, CN com runner UUID e pares de chave por SPKI público. Não reutilizar chaves
públicas da origem ou entre funções. Nunca imprimir/hash de segredo privado;
manifesto inclui somente certificados/fingerprints/SPKI públicos e descritor/hash
compatível com linux_labs.descriptor. Chaves novas ficam só na pasta privada; modo
0444 de folhas é necessário para bind secrets lidos pelo UID10001, protegido pelo
pai0700, conforme a instalação existente. Chaves das CAs continuam0600.

Manifesto exclusivo/fsync com formato/ID/hashes/instante, criado apenas após
validações. Verify exige origem, candidato e SHA esperado independente; recalcula
material público/pares/validade e detecta drift. Hash não é assinatura nem custódia
externa. Recibo só afirma candidato offline verificado, nunca ativação ou mTLS de
laboratório. Usuário/root do host permanece fronteira de confiança.

Ativação futura exige escopo autorizado próprio, laboratório revogado/sem reserva,
tratamento de jobs ambíguos no runner original, mesma identidade/volume e revisão
explicitamente ligada ao novo descritor. Trocar server CA/client cert muda o hash
que invalida binding/preflight/scopes anteriores. Não editar aprovações históricas,
repetir start, apagar journal ou liberar reserva para contornar a rotação. Não
implementar apply automático neste incremento.

Testes: geração/verificação reais em temporários, invariância de IDs/origem, chaves
originais ausentes, drift/corrupção/pares errados, validade, SAN/EKU, arquivos/limites,
manifesto incompleto e falhas sem recibo. Handshake TLS em loopback com novo par e
recusa de confiança/cliente antigos, sem runner/app/job ou arquivos marcadores.
Teste não equivale a ensaio de laboratório autorizado. Nenhuma migração/UI/runtime
nova é necessária; registrar limitações e próximos passos reais.

Fontes oficiais:

- [OpenSSL x509](https://docs.openssl.org/3.5/man1/openssl-x509/)
- [OpenSSL verify](https://docs.openssl.org/3.5/man1/openssl-verify/)
- [Verification options](https://docs.openssl.org/3.5/man1/openssl-verification-options/)
- [Python SSL](https://docs.python.org/3.13/library/ssl.html)

OpenSSL local3.5.8; comandos devem funcionar também na linha3.0 da CI. Não usar
API privada Python de decode X509 nem parsing textual para substituir verificação
criptográfica; datas textuais servem só para inventário/limites junto ao verify.
