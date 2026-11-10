# Escopo para um único ensaio local de identidade

Este escopo exige autorização humana específica, vinculada ao plano privado e ao
seu hash de escopo. Não reutiliza autorizações dos ensaios Linux/Wazuh/diagnóstico
anteriores. Documentação, CI ou confirmação local por hash não são autorização.

## Precondições verificáveis

- Código executável da `main` corresponde à CI aprovada: quatro jobs Python e
  React concluídos com sucesso. Revisão de fontes também aprovada. Se houver um
  commit posterior somente de documentação, conferir igualdade de todos os
  arquivos executáveis/configuração/dependências com o commit testado.
- Nova revisão somente leitura: projeto `aegis-linux-lab` sem containers/redes ou
  consumidores globais dos dois volumes originais; nomes reservados livres;
  ausência de sobreposição observada do subnet em rotas e redes Docker.
- Imagem runner local e prova selada verificadas sem publicar recibo de build.
  Nenhum pull, build ou instalação faz parte do ensaio.
- Candidato PKI novo, separado da origem, válido e revalidado; IDs originais e URL
  fixos. Origem e candidato antigo expirado permanecem preservados.
- Plano novo e atual, com `tool_commit` igual à `main` limpa e escopo não consumido.
  Revalidar imediatamente antes da execução; nenhuma renovação silenciosa.
- Host com recursos disponíveis para os dois containers limitados. Não parar
  outros serviços nem alterar RAM/swap/sysctl/rede/configuração do host.

Cada ensaio requer pacote privado de revisão contendo candidato/manifestSHA,
validade e fingerprints públicos, IDs preservados, plano/planSHA/scopeSHA, commit
de fonte, resultado da CI e igualdade de código quando aplicável. Esse pacote
deve ser gerado antes da solicitação de autorização, sem registrar uma operação
fictícia ou declarar runtime verificado. Chaves e senhas não entram no pacote.

## Recursos e ações permitidos

Somente o projeto próprio `aegis-linux-lab` e os três papéis dedicados:

1. Uma bridge interna isolada `192.168.253.0/29`, sem IPv6 ou portas publicadas.
2. Um servidor identity-only em `192.168.253.2:8443`, com allowlist vazia e sem abrir
   runner normal, workspace ou diário.
3. Um cliente fixo em `192.168.253.3`, para quatro conexões TLS1.3 GET de identidade:
   material candidato; sem certificado cliente; CA servidor antiga pública;
   material candidato novamente.

Imagem runner fixada:
`sha256:526267ad8a54df12ffe130724874bb79bcdbb6ecb61345afe3a1ddc1d3085be5`.
Build `5ccbca482dd649b58f90b89d85c4d885`, recibo canônico
`dfa0b726b3c21ab35610bbd2af86c15c03ec45426ce81ca0b12e644f550d8e70`.
Isso é prova local de build/fonte, sem assinatura de publisher ou prova TLS nativa.

Containers UID/GID10001, rootfs RO, caps removidas, no-new-privileges, limite de
192MiB/0,5CPU/16PIDs cada, tmpfs16MiB, sem restart/healthcheck/TTY/portas publicadas
ou volumes anônimos. Servidor recebe somente chave/certificado de servidor e CA
cliente novos em três binds RO. Cliente recebe somente CA servidor/certificado/
chave cliente novos e CA servidor antiga **pública**, em quatro binds RO.

Os nomes/labels/IDs dos recursos são derivados do intent único. Não adotar recurso
preexistente ou executar comandos, scripts, paths ou URLs fornecidos livremente.

## Orçamento, evidência e encerramento

Uma tentativa, sem retry de create/start ou repetição para obter resultado melhor.
CLI usa lease230s; ações nunca ultrapassam begin+240s. Leituras/RPCs/cleanup são
limitados a begin+300s UTC/monotônico original. Finalização em ordem cliente →
servidor → bridge, por ownership, sem force ou remoção de volumes.

Gates/fatos normalizados persistidos antes de cada efeito; pedido, fences e
recibos privados0700/0600/O_EXCL/fsync. Inspecionar saída, perfis físicos e
membership exato antes de aceitar reply. Preservar todos os artefatos, volumes,
PKI antiga/candidato expirado e recibos históricos.

Se um controle TLS terminar em EOF/reset sem motivo verificável, registrar
inconclusivo. Não repetir para transformar esse resultado em sucesso. Se cleanup
não puder ser confirmado, reter dependências, registrar pendência e encerrar o
ensaio; recuperação posterior exige escopo **novo**, somente cleanup por até120s,
com revisão/autorização própria. Não renovar a autorização do ensaio original.

## Fora do escopo

Sem PostgreSQL, Redis, API, worker, Wazuh ou runner normal; sem SQL, diário,
marcador, campanha, alteração de binding, ativação PKI ou retomada operacional.
Não ler chaves antigas, alterar credenciais/contas, montar volumes originais,
publicar portas, acessar alvos externos/corporativos ou modificar redes existentes.
A aplicação Demo permanece em funcionamento.

Relatório proporcional às evidências: identidade/TLS não comprovam continuidade
do diário, ingestão SIEM ou detecção defensiva. Não registrar DETECTED por este
ensaio. Flags de ativação/binding/diário/marcador/operação normal permanecem falsas.

Comandos, formato dos registros e recuperação:
[procedimento de identidade](IDENTITY.md). Estado e resultados efetivamente
executados: [checkpoint do projeto](../../docs/PROGRESS.md).
