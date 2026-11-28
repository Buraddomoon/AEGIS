# Tentativas anteriores ao efeito — #104

Registros preservados em 24/11/2026 no fuso America/Sao_Paulo (25/11 UTC nas
retomadas). Não são prova de recorrência nativa concluída.

O primeiro pacote `28de3e3f53ad79c39651feec2dd3f3d6013acf0ac63ff3b3ed71ca347fe2d65d`,
[workflow45514289124](https://github.com/Buraddomoon/AEGIS/actions/runs/45514289124),
expirou aguardando aprovação; a etapa de execução foi SKIPPED. Zero serviços Lab
iniciados e zero efeitos. A [proposta original](REQUEST-104-28de3e3f.md) permanece
histórica, sem renovar seus hashes ou sua validade.

Depois de apresentar o escopo de duas ocorrências em VM Linux nova, o usuário
autorizou explicitamente fazer o necessário para concluir a issue preservando
seu computador. Essa autorização foi registrada na #104 para os pacotes novos,
sem atribuir ao usuário revisão manual dos novos hashes. Cada pacote teve seu
próprio comentário operacional posterior, fence e janela; nenhum foi reexecutado.
As falhas abaixo aconteceram antes de qualquer run/dispatch/teste.

| Workflow | Pacote | Comentário de autorização | Resultado e correção |
|---|---|---|---|
| [45523490594](https://github.com/Buraddomoon/AEGIS/actions/runs/45523490594) | `404ede3bfe3f8254b78280cb464966e72ca32accf42d399e9657bddeb63819d3` | [7149310312](https://github.com/Buraddomoon/AEGIS/issues/104#issuecomment-7149310312) | Falha do cliente browser; stderr inicial insuficiente. `9af2139` acrescentou ambiente mínimo, smoke do browser antes de criar Lab e diagnóstico sanitizado. Não se atribui causa conclusiva ao HOME. |
| [45524591304](https://github.com/Buraddomoon/AEGIS/actions/runs/45524591304) | `c9aa9c2d2c60085a9aabf5d0e5d322fe1076e32623ac4175c40b8771cdb93dfc` | [7149448508](https://github.com/Buraddomoon/AEGIS/issues/104#issuecomment-7149448508) | Login tentou preencher antes de aparecer o formulário após consulta de sessão. `46d431d` aguarda o seletor, como o E2E existente, e captura diagnóstico antes de credenciais. |
| [45525430870](https://github.com/Buraddomoon/AEGIS/actions/runs/45525430870) | `981e7c8bdcedd6bec795f0fe8aca803faaefc7a4249a7f669b54ef03a3d03b17` | [7149551576](https://github.com/Buraddomoon/AEGIS/issues/104#issuecomment-7149551576) | Login e preparação API passaram; formulário aguardou campanha ausente da lista em cache. `5e4737a` tentou renovar o documento via goto, mas navegação por fragmento não faz reload. |
| [45526376777](https://github.com/Buraddomoon/AEGIS/actions/runs/45526376777) | `d5f77b4436af87834ab5f6b5570c6cd8b3a6b1f5bc46c15348dba7859638270e` | [7149702461](https://github.com/Buraddomoon/AEGIS/issues/104#issuecomment-7149702461) | Mesmo timeout do formulário, ainda antes do efeito. Retomada em27/11 acrescenta reload explícito e diagnóstico sanitizado; nova preparação fixa schema f3b compatível com a fonte atual, exclusivamente no banco novo. |

Nos quatro casos: `FAILED_QUARANTINED`, `cleanup_confirmed=true`,
`runs=dispatches=tests=cleanups=0`, duas contas próprias inativas, zero sessões,
`safe_to_stop=true` e workspace vazio. Recursos próprios encerrados; volumes novos
sem consumidores até descarte da VM efêmera. Nenhum original acessado, nenhum
serviço instalado/iniciado no Windows. A soma de efeitos dessas tentativas é zero.

SHA256 dos arquivos sanitizados baixados dos respectivos artefatos:

| Workflow | `summary.json` |
|---|---|
| 45523490594 | `34d28858a19c85cfdd03ed5ffc4e4de7e5be83e355a6d87768b6c1921f3b8b67` |
| 45524591304 | `32e8f647b45bd8c74ac6b44bbf1ead0841a9c44a9c16b559f444dbe87d8aa3b0` |
| 45525430870 | `10b3b7a8c4ed22a39b96860b17b81be7b147fb0a0fae62a94abf9d4d2fea609a` |
| 45526376777 | `bc0c31538049db1a173559477c0cfd6e4b0b1f4aa44b0b083ef0ef18842756ec` |

`disabled.json` idêntico nos quatro: SHA256
`736c95755fdf15aae0542dab4cac00ea59efb352725251bf47bacc8fad318380`.
`workspace.json` idêntico nos quatro: SHA256
`8295d45195b092ea9560d982e67d4cec61b0cca658161d1c6b2eda2629c86d37`.
Hashes atestam comparação de bytes, não assinatura.

Validações locais do harness: 34 testes de preparação passaram após cada uma das
duas últimas correções; a execução anterior com política totalizou56aprovações.
Sintaxe Node, Prettier e checks staged/release passaram. Um comando Prettier com
cwd incorreto não encontrou arquivo; o comando no diretório `apps/web` passou.
CI45524591055 e45525430828 foram canceladas por push posterior, não são verdes.
CI45526352523 da fonte5e4737a terminou SUCCESS. Os gates não foram relaxados.
As correções do harness não alteram o código da aplicação/runner; a retomada
sincronizou main por fast-forward de5e4737a para5e5feb9, preservando as entregas
publicadas durante a pausa. A nova prova usa essa fonte atual, não presume
equivalência das imagens antigas. O conector GitHub desconectado foi substituído
pelo acesso autenticado já existente, sem mudanças na conexão do usuário.
