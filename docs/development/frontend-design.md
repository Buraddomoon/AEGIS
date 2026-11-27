# Frontend AEGIS

A revisão visual de 27/11/2026 usa os padrões do memory-os como referência,
adaptados ao produto e à stack existente. Não migra o backend FastAPI, a
autenticação por sessão, as rotas da API ou os contratos de evidência para o
modelo Django/JWT da Agenda. Não acrescenta dependências.

As referências consultadas foram `Padrao-Cloudflare-Front`, o blueprint
`Chinalink-ControlLinkers/fundacao/12-arquitetura-base`, as decisões de
Control-linkers e Forms-Contrato e o plano Arquitetura 2027. O padrão de deploy
Cloudflare não implica identidade visual obrigatória nem implantação deste app.

## Paleta e hierarquia

As dez cores fornecidas pelo usuário são os únicos valores de origem em
[style.css](../../apps/web/src/style.css). Tons intermediários usam `color-mix`
entre elas ou transparência; não introduzem novas cores de marca.

| Token | Cor | Uso |
| --- | --- | --- |
| Obsidian | `#0B1018` | Fundo, navegação e campos |
| Graphite | `#151D29` | Cards, painéis e modais |
| Steel Blue | `#263C59` | Bordas e elementos secundários |
| Frost Blue | `#789BC8` | Ação principal, links e foco |
| Silver | `#D5DFEB` | Texto principal e logotipo |
| Offensive Red | `#E05252` | Falhas e operações ofensivas |
| Defensive Blue | `#528BE8` | Execução/coleta e estados defensivos |
| Purple Operations | `#9B7BDF` | Validação, incerteza e identificação sintética |
| Detection Green | `#42BE85` | Detecção, conclusão e estados ativos confirmados |
| Warning Amber | `#D8AE54` | Aprovação pendente, alerta e observação sem alerta |

A direção visual segue a predominância escura solicitada (80/15/5 como
orientação de composição, sem alegar uma porcentagem de pixels medida).
Botões e navegação usam Frost, reservando as cores operacionais a indicadores
pequenos. A legenda e o texto acompanham as cores: verde em "Concluído" indica
conclusão, nunca infere o veredicto "Detectado".

Silver sobre Graphite tem contraste de aproximadamente 12,57:1 e Frost 5,91:1.
Offensive Red sobre Graphite tem 4,44:1, insuficiente para texto pequeno;
os badges de falha usam texto Silver e ponto vermelho. Os valores de origem
não foram alterados para simular uma paleta diferente. Isto não equivale a uma
certificação de acessibilidade de todas as superfícies históricas.

## Componentes e interação

- [App](../../apps/web/src/App.tsx) mantém sessão, roteamento e shell. Login,
  visão geral, marca e busca de páginas têm componentes próprios.
- React Query mantém estado de servidor; `useState` mantém formulários e estado
  local. Controles HTML nativos, modais `dialog` e ícones Lucide permanecem.
- A busca de páginas abre pelo botão ou `Ctrl K` / `Cmd K`, aceita termos sem
  acentos e abre o primeiro resultado com Enter. Escape fecha o modal.
- Em telas pequenas, o menu tem backdrop, fechamento explícito/Escape,
  contenção de foco e conteúdo de fundo inerte. Fecha também ao selecionar a
  página atual. O perfil permanece visível, com navegação rolável separadamente.
- "Pular para o conteúdo" e foco no conteúdo após navegação atendem teclado.
  Respeita a preferência existente por movimento reduzido.
- Login permite revelar/ocultar senha sem submeter o formulário. Uma visita
  inicial sem sessão não anuncia uma expiração; revogação de sessão conhecida
  continua anunciada, inclusive com várias respostas concorrentes.
- A visão geral preserva o recorte Demo e os denominadores da API. Erros de
  integração são exibidos, sem serem traduzidos em disponibilidade do worker.
  A distribuição inclui resultados de falha, sem alterar veredictos, e o gráfico
  de evolução oferece uma descrição textual dos valores.

## Verificação

Componentes, tipagem e build:

```sh
npm --prefix apps/web test
npm --prefix apps/web run lint
npm --prefix apps/web run format:check
npm --prefix apps/web run build
```

[workspace.test.tsx](../../apps/web/src/workspace.test.tsx) cobre os novos
comportamentos de acesso/busca/sessão e a apresentação honesta de erros e contagens.
[workspace-e2e.mjs](../../apps/web/workspace-e2e.mjs) verifica em Firefox o
teclado/foco, login, busca e as onze páginas principais a 1440, 768 e 390 pixels.
Recebe um JSON com `username`, `password`, `origin` por stdin, somente de uma
instância Demo descartável em loopback. Capturas ficam em `.local`, fora do Git.

O percurso integrado existente continua em [e2e.py](../../scripts/e2e.py), com
API, worker, PostgreSQL e Redis em schema próprio. Não executar contra o histórico
original para reproduzir uma revisão visual. Nenhum desses testes autoriza ou
comprova operação de laboratório Linux/Wazuh, SIEM real ou implantação permanente.

Rodada local de 27/11/2026: build/tipagem/formatação aprovados; 185 testes React e
21 testes de segurança do glob passaram. O E2E integrado existente passou com
5 runs/20 testes sintéticos, 5 exports PDF, 2 relatórios automáticos e zero erros
JavaScript. Após os ajustes finais de foco/sessão, o E2E de workspace passou nas
11 páginas e 3 larguras, incluindo busca, menu móvel e login. Estas são evidências
locais complementares, não uma declaração de aprovação da CI remota.

A prévia de revisão usa API e worker próprios em loopback18786, schema
descartável e Redis13; o Demo original em18780 não foi implantado ou migrado.
Quatro campanhas sintéticas e11testes concluídos foram criados pelos endpoints
normais, com aprovação e worker, sem fabricar resultados ou modificar históricos.
Credenciais e capturas permanecem somente em `.local/frontend-preview`.
