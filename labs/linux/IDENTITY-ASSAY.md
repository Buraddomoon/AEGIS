# Escopo para um único ensaio local de identidade

Este escopo exige autorização humana específica, vinculada ao plano privado e ao
seu hash de escopo. Não reutiliza autorizações dos ensaios Linux/Wazuh/diagnóstico
anteriores. Documentação, CI ou confirmação local por hash não são autorização.

O pacote apresentado em10/11 foi autorizado e consumido por uma tentativa que
encerrou com falha no cliente e cleanup confirmado. Ver o
[resultado preservado](../../docs/evidence/identity-assay-2026-11-10/README.md).
Os limites abaixo não concedem outra tentativa; eventual repetição exige novo
plano/pacote, revisão e autorização específica, sem alterar o histórico anterior.

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
`sha256:b5ae5340f417ef3fce7ce25f8ec07d2dd92545b3a34d6db1982ac37fb108c593`.
Build `d5ec67c458cd4553bafc4e9aeee6bb4a`, plano de build canônico
`7aeffb3551ffe321e58a458d1e00a7a253be12557b1fffd9a680dcd63194833e`, recibo canônico
`6b68d3e97c4150b4afd5dc6218c20f21aa7bf66f0bf28654b2c65bdf076fefac`.
Fonte executável `f0c95b2f6cdb62fb7da219cbe93a18807838758d`, com
[evidência de preparação](../../docs/evidence/identity-image-2026-11-10/README.md).
Imagem e recibo de30/10 permanecem preservados como histórico.
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
