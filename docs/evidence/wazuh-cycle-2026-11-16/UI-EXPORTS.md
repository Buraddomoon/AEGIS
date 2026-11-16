# Leitura da mesma execução real —#60,16/11/2026

**SAME_REAL_RUN_UI_VERIFIED**, sem segunda campanha ou marcador. A
[campanha#59](CAMPAIGN.md) é a run
`b338665e-2086-48a4-8601-db7f147dd087`, COMPLETED/DETECTED/CLEANED,
synthetic=false, um teste/regra própria100200 e zero técnicas ATT&CK avaliadas.

## Browser autenticado

Maestri Portal foi consultado, mas o terminal não tinha MAESTRI_SOCKET.
Puppeteer-core/Firefox headless já instalados fizeram a leitura local na porta18786.
Credencial da conta administrativa desta tentativa somente no stdin/memória;
nenhuma conta histórica foi usada. Após login, interceptação recusava qualquer
POST/PUT/PATCH/DELETE e destino fora de localhost18786. Resultado:

- Página da mesma run: **LINUX REAL**, Concluído, Detectado e Correlacionado.
- Comprovantes do executor/cleanup abertos, com aviso explícito de que não são
  evidência defensiva; `execution_receipt` visível.
- Modal da evidência defensiva aberto: origem Indexer, ID original
  `jWQD5qEBm7izxmUqYd4q`, regra100200, timestamp, SHA256 e `_index/_id/_source`.
- Zero erros JavaScript e zero requisições de mutação após o login.
  Nenhum clique em repetir campanha, start, aprovação ou mutação administrativa.
- Screenshot local inspecionado visualmente; navegador próprio encerrado.
  SHA256 `74546dc0c39ac2b90e8a91d033ac78611bf19a70281c506af047831c8f55bb5e`.

Imagem permanece no host em
`.local/wazuh-single-campaign/9f60b4c8d7154babaca1e6271b110683/native-state-operational/execution-ui.png`.
Não é um segundo ensaio nem autoriza replay. A UI apresenta ambiente5 do scope
aprovado; o lab atual encerrou revogado/ambiente6. O snapshot histórico foi preservado.

## JSON, HTML e PDF

GETs autenticados da **mesma run**, capturados antes da desativação das contas.
JSON/HTML lidos por parser; PDF real lido por pypdf:

| Artefato | Verificação |
|---|---|
| JSON | synthetic=false; planned/completed/valid/detected_tests=1; scope com technique_id=null |
| HTML | UUID da run, LABORATÓRIO REAL, DETECTED,100200, ID do alerta e distinção recibo/alerta |
| PDF | Mesmos UUID/estado/regra/ID/limitações reais;9páginas,61.970bytes |

PDF bytes SHA256
`0cd007163beea9912bfe6ad80ed1e9227540b9b7360921a49f01aa5242e3f366`;
HTML `1c17b7b44bae107e498b76a8efb36b0cb38a534050f31f90c3cba158d30538f9`;
JSON `99cacf1da280f4e0ff6b9653aee0a05894bb2dfb38ee59a914dbffd5d1d7d872`.
Export integra o alerta original e as limitações de instrumentação/escopo;
nunca trata o recibo como alerta nem mostra cobertura ATT&CK artificial.

O campo `integrity_sha256` do relatório é o hash da representação **exata de
`run` dentro dele**, não do envelope inteiro nem dos bytes do PDF. Conferido:
`0d0e1b010730faec0128ce826a7a6988d900dec2b2ef6733c9751301e656d7db`.
Comparação recursiva com o detalhe da API encontrou somente37timestamps de
colunas representados como UTC `Z` na API e `+00:00` no relatório; todos
representam os mesmos instantes. Nenhum outro campo difere. Payload original
do alerta/recibos permanece idêntico. Ambos os conteúdos/hashes foram preservados;
nada foi reescrito para igualar serializações. Hash não é assinatura.

## Denominadores e comparabilidade

Relatório da tentativa:1teste válido,1detectado. Coverage real agrega **duas**
runs: a histórica de22/10 e a nova;2testes válidos/2detectados, zero técnicas
avaliadas/historicamente avaliadas.706técnicas no catálogo não significam706
técnicas testadas. Uma run antiga permanece sem contexto de catálogo versionado.

Comparação pedida por leitura entre987bd48f e b338665e foi corretamente recusada
com409: **“Selecione execuções da mesma campanha.”** São campanhas distintas;
não foi criada outra run nem alterado histórico para forçar comparabilidade.
Nenhuma inferência causal de melhoria, cobertura empresarial ou eficácia geral.
Demo permaneceu synthetic=true/sem runs neste banco; todos os dados/métricas
antes/depois idênticos, excluindo somente o horário de consulta `snapshot_at`.

## Encerramento e validação

Contas exclusivas administrativa/operadora desativadas depois da leitura;
zero sessões novas restantes. Duas contas/sessões históricas preservadas.
Lab revogado, ambiente6/sem reserva, cleanup físico/workspace vazio, containers/
redes próprios encerrados e nove volumes originais sem consumidores.
Backups/PKI/journal/intents/evidências mantidos; nenhuma operação contínua liberada.

Recibo conjunto **CAMPAIGN_AND_EXPORTS_VERIFIED/CLEANED**, SHA256
`0ed4ddc74dedf1636949c5686b7dfd251ec1f9103933d7af8e1a2a6f84c7a30b`.
Browser/parsers, correlação dos dados reais e encerramento são evidência nativa,
distinta dos testes de fixture e da CI3429Python/9skips opcionais/91React da
fonte34c8093. Nenhuma alteração de código da aplicação para obter este resultado.
Conjunto#58→#59→#60 atende o objetivo da#7 dentro do único efeito autorizado.
