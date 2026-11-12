# Campanha Linux verificada e encerrada — 12/11/2026

Resultado: **single_linux_campaign_verified_and_closed**. Uma campanha real,
marcador benigno de43bytes, cleanup confirmado e resultado **INCONCLUSIVE**,
`synthetic=false`, sem SIEM/alerta defensivo. UI e relatórios conferidos por
leitura do mesmo UUID. Lab revogado e recursos próprios encerrados ao final.

## Escopo aprovado

Usuário respondeu **“pode”** ao
[escopo adicional fixado](CAMPAIGN-CATALOG-REQUEST-2026-11-12.md), SHA256
`3c6f96b1fa86d1c5773d5f66996ffdd5e3b264fdcd01b5fafc47e6cc1fd7aca3`,
tentativa `c657ef60-51c9-44b1-aa82-cbd75f87758e`. Prazo, imagens, fonte, helper,
PKI/IDs e ausência de consumidores reconferidos antes dos efeitos. Registro de
autorização privado criado antes do startup; hash não é assinatura. Pacote agora
consumido: não repetir efeito, alterar UUID ou limpar fences para reutilizá-lo.

A [tentativa anterior](CAMPAIGN-2026-11-12.md), sem campanha, foi preservada;
nenhuma de suas contas foi reativada. Schema original já era b7/33tabelas.
A inicialização geral/seed, migração original, reset de senhas e Wazuh não foram
executados nesta etapa. qasrc permaneceu idêntica por hash antes/depois do ensaio.

Aplicação: fonte `752ad29`, imagem em tag exclusiva
`aegis-linux-campaign:752ad29`, ID
`sha256:ba50a78c97556d562ad550fc05b4c76803f1c89c8e8bb886cc06fb7ca700a49a`.
Runner a893, PostgreSQL b0f9 e Redis3811, os mesmos IDs revisados na proposta.
Demo b8 e todas as imagens anteriores foram preservados; sem reimplantação Demo.
PKI atual `81826566e88e4c9ebc8b9aa09c8a8d02`, identidades originais e rede runner
isolated192.168.253.0/29; API somente loopback18785. Binding não foi recadastrado.

## Backup e registro restrito do catálogo

Cópia fria nova do PostgreSQL: **68.267.789bytes/1.476entradas**, origem
RO/nocopy/sem rede e inventários idênticos:
`2d7fb995eafb6fb80234e610adde5c6b2c7018fc8acc6ecff5560c0c71485990`.
Dump custom430.576bytes, SHA256
`e4ccbf1c8f3052d381f44b247cf9a9c65cbf6e2a3268c317047ba140a342ae74`.
Restore em clone isolado preservou todas as linhas/colunas, ACLs e verificadores.

O helper conferiu schema b7, ausência de reservas, lab revogado, tabelas de
versão vazias e projeção legada não vazia exatamente igual ao snapshot/licença
distribuídos. Primeiro no clone e depois no original, `catalog.store.initialize`
acrescentou **uma release, um ponteiro e auditoria**. As706técnicas existentes,
contas/senhas e todos os demais dados foram preservados, sem nova migração.
Release `b572391494ef2b9ec7b68095bef5ba16c7190da123497c1b814b9c5c0ce6b3e2`,
versão20.0, proveniência bundled; não é atualização externa de catálogo.

Recibo privado `.local/linux-campaign-next/catalog-result.json`, diretório
`.local/linux-schema-clones/0c2de0c7e9ea496db980b6d355e6bc73`. Backups e todos
os volumes novos foram retidos; helpers encerrados antes do startup integrado.

## Execução e evidências

- Run: `857891c8-a539-47e9-802d-bc8102a60863`.
- Job/execução: `3ed3e95f-590b-4d19-8062-4a29a554e097`.
- Scope hash: `63515c2eacf9970fbe54ff0f2fe95eef52db909a752146b98d50a22046ff4f17`.
- Solicitante operador e aprovador administrador distintos, duas contas novas
  exclusivas desta tentativa; aprovação nova consumida no start, duração60s.
- Preflight mTLS vigente, lab autorizado e dispatch durável antes da RPC.
- Efeito registrado em12/11 às14:18:42UTC. Somente `linux-file-marker/v1`,
  sem técnica ATT&CK atribuída. Conteúdo esperado de43bytes e SHA256 conferidos.
- Diário: exatamente um novo PREPARED→RUNNING→SUCCEEDED→CLEANED. Dois jobs
  históricos idênticos antes/depois; eventos anteriores preservados. Workspace
  `/work` vazio após cleanup. SQL passou de uma para duas runs/dispatches,
  incluindo a prova histórica; isso não significa três campanhas integradas.
- `COMPLETED`, resultado INCONCLUSIVE, synthetic=false, zero eventos/evidências
  defensivos. Recibo de execução não foi tratado como detecção.

Recibo de execução SHA256
`be37690c486722c60dbb40d14bbf0b9b4a417e1b6bf23d3e298598e2fcc75bf9`;
cleanup `cb6480c98ecd8db65d41d11f7f3c7a3724cd60e301a656f96af920804364f801`;
artefato `2d932980d706970dbe63a6f1d0e19521448f551e43a910e694dd0d6f3d491a47`.
Conteúdos/hashes, marcador e scope hash foram conferidos independentemente.

JSON e HTML foram consultados; PDF real de **8páginas/58.423bytes** lido com
parser independente, SHA256
`9f8962e27a5ede47e52b6011a08fe544d2dcba28a5f79db78a1b3210013b8403`.
Não foi gerada outra execução para obter relatório ou screenshot.

## Falha do verificador e revisão da UI sem novo efeito

Depois do sucesso físico/relatórios, a comparação do Demo falhou porque incluía
`snapshot_at`: o horário muda em cada consulta. As respostas preservadas foram
comparadas: **esse foi o único campo diferente**, todos os dados/métricas e o
contexto eram idênticos. O smoke foi corrigido em `07c409d` para excluir somente
esse horário; regressão também prova que uma mudança de métricas continua falhando.
O comando original e seu erro foram preservados, sem reescrever recibos/estados
para transformá-lo em sucesso. A validação suplementar atesta o resultado final.

O finally já havia desativado as contas. Para concluir a leitura da mesma run,
foi usada somente a conta administrativa **da própria tentativa atual**, com
sessão temporária em memória, sem reset de senha ou conta adicional. Contas
anteriores permaneceram inativas. API/DB/Redis foram iniciados só para leitura;
**worker e runner ficaram parados**. Navegador recusou métodos de mutação.

As primeiras consultas do Firefox não enviaram o cookie configurado no contexto
de uma página em branco, embora a sessão passasse na API. Após configurar cookie
no contexto do navegador, a UI real foi conferida: Linux real, Concluído,
Inconclusivo e recibo visível, **zero erros JavaScript e zero requisições de
mutação**. Captura somente local, inspecionada visualmente. Cada fase encerrou
sua sessão/conta própria e seus recursos no finally. Nenhuma campanha foi repetida.

## Encerramento e integridade

Verificação final em leitura sobre banco original e diário WAL-aware:

- b7/33tabelas; lab revogado, ambiente4→5, zero reservas.
- Duas contas desta tentativa inativas; zero sessões próprias. As duas sessões
  históricas preexistentes foram preservadas. Nenhuma conta histórica reativada
  ou senha alterada; as duas contas da tentativa anterior também continuam inativas.
- 30tabelas históricas conferidas com todas as colunas originais e mesmo
  inventário/hash das linhas anteriores. Novos registros de catálogo/campanha/
  auditoria/preflight/contas são adições explícitas; autorização do lab muda de
  versão como esperado. Scopes, approvals, receipts e cleanups antigos intactos.
- Diário íntegro com provas SQL de ambas as campanhas; revisão SHA256
  `bd3694b911c1cee44bc0c375976dbe7a58e8340163439e7cc5bfb91875e3a849`.
- Todos os containers/redes próprios encerrados, originais sem consumidores,
  backups/volumes novos e antigos retidos, PKI, IDs, imagens, journals e fences
  preservados. `normal_operation_permitted=false`; não há liberação contínua.

Recibo conjunto privado `.local/linux-campaign-next/final-receipt.json`, SHA256
`de5f6d5f677937cf0b689d74dde8fa5715c84cf541a671b39bb8d6e26b4a1925`.
Inspeção final `.local/linux-schema-clones/ffa9d2c365e74cae914a6b33641a94dd`.
Logs, dump, SQL, screenshot, PDF e credenciais permanecem no host, fora do Git.
Hash não é assinatura; esta prova é limitada a um marcador benigno próprio.
Sem eficácia de SIEM/EDR, cobertura empresarial, atualização externa ou novo ensaio.

## Código e testes

Fonte da aplicação/runner no ensaio:752ad29; correção final07c409d muda somente
verificador host e testes, sem diferença em apps/API/web/imagens/config/deps.
39testes focados passaram em37,69s (preparação/campanhas/schema), incluindo dump/
restore de fixture efetivo sem skip.127testes runner da preparação anterior têm
código inalterado; rodadas sobrepostas não são somadas. Ruff lint/format globais,
mypy e checks staged/release/diff aprovados. Aviso Starlette/httpx permanece.

CI integral da aplicação752ad29
[43234227462](https://github.com/Buraddomoon/AEGIS/actions/runs/43234227462)
SUCCESS:3198Python/9skips opcionais e91React, quatro partições conferidas.
CI do verificador final07c409d
[43237239816](https://github.com/Buraddomoon/AEGIS/actions/runs/43237239816)
**SUCCESS:3199Python/9skips opcionais e91React**, quatro partições e job React
conferidos. Nenhuma exclusão/filtro novo para obter green. A validação nativa
acima é separada da CI e das fixtures.

Escopo #5 e filhos #52/#53/#54 atendidos por preparação, autorização específica
e esta prova; encerrar após registrar checks/sincronização e aceite do conjunto.
Não iniciar outra entrega e não reutilizar este pacote consumido.
