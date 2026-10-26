# Verificação de entrega do código 0.2.0

O código atual oferece o MVP Demo e incrementos limitados Linux/Wazuh/Sigma e
recuperação. Os números 0.3–0.5 do roadmap organizam evolução funcional; não são
releases publicadas. Esta consolidação não cria tag, GitHub Release, artefato
público ou implantação externa. O repositório permanece privado/main.

## Verificações reproduzíveis

Na configuração de desenvolvimento documentada:

```bash
make lint
make test
make build
make audit
make release-check
```

Para alterações de interface/fluxo, execute também `make e2e` com Firefox local.
Esse comando cria API/worker/schema descartável, só com simulações Demo, e
atualiza capturas. Não o execute em paralelo com outra rodada que compartilhe
contadores Redis de teste. Não repetir ensaios Linux/Wazuh para uma screenshot.

`make release-check` não acessa banco, Docker, browser ou rede. Lê **o índice Git**,
verifica padrões de credenciais/paths, igualdade das versões Python/React/lock e
dependências declaradas na raiz do lock npm. Confere destinos relativos dos links
inline Markdown, incluindo imagens, e cabeçalho/dimensões PNG em docs/images.

O JSON identifica HEAD e divergências entre índice/HEAD/arquivos rastreados no
diretório. Arquivos não rastreados e ignorados, como `.env`/`.local`, não são
lidos. Adicione somente os arquivos revisados ao índice antes de validar uma
entrega. O relatório não contém valores de possíveis credenciais encontradas.

Limites: padrões não garantem ausência de segredos; links externos/âncoras e toda
a gramática Markdown não são validados; cabeçalhos PNG não provam conteúdo nem
procedência. Não interpretar passed como testes aprovados, instalação executada,
segurança completa ou autorização de laboratório. Não há publicação automática.

## Evidências e estado

| Escopo | Referência verificável |
|---|---|
| Versões de entrega | pyproject.toml, apps/web/package.json e package-lock.json: 0.2.0 |
| Instalação Demo | Docker build/Compose/smoke já executados nos marcos anteriores; nesta consolidação, configuração nova temporária e Compose renderizado sem subir serviços |
| Interface e fluxo completo | [E2E Firefox de 2026-10-26](../evidence/coverage-reports-2026-10-26/README.md), 4 runs / 16 testes sintéticos; 12 capturas Demo |
| Galeria | [Arquivos e origem das 13 capturas](../images/README.md), incluindo uma histórica Linux |
| Linux real | [Escopo do laboratório](../../labs/linux/README.md); ensaio encerrado, recibo sem SIEM é INCONCLUSIVE |
| Wazuh real | [Um ensaio fechado](../evidence/wazuh-2026-10-22/README.md), 4.14.9/regra 100200, um marcador, zero técnicas ATT&CK |
| Cópia cifrada | [Restore real offline](../evidence/encrypted-backups-2026-10-26/README.md), 32 tabelas / 3.169 linhas; origem intacta |
| Testes, checks e CI desta consolidação | [Registro de progresso](../PROGRESS.md), com commit/rodada e limitações |

O gerador de configuração agora recusa arquivos inseguros, vazios/exemplos,
links/FIFO e escritores concorrentes. Configuração válida é preservada; histórico
sem senha do papel runtime recebe apenas esse segredo. Testes usam diretórios
privados descartáveis. O render Compose de configuração nova confirmou os cinco
serviços, API 127.0.0.1:18780, DB/Redis não publicados, papéis SQL separados e
nenhum runner/coletor SIEM habilitado. Isso não substitui um novo ensaio de boot.

A CI principal executa dependências/testes/bancos/build/auditoria quando há código.
O workflow source-review verifica documentação/metadados em job sem instalação de
dependências ou serviços, timeout 2 min, permissões read e cancelamento de duplicados.
Commits apenas documentais não repetem toda a suíte remota.

## O que permanece fora do aceite

- Custódia externa e chave fora do host, adiada pelo usuário. Sem upload/serviço pago.
- Recuperação operacional entre hosts, configuração/secrets/imagens, cutover e RPO/RTO.
- Rotação PKI/binding e retenção dos laboratórios reais; novas simulações só sob novo escopo.
- Backend/pipeline Sigma compatíveis e conversão/implantação demonstradas; não inferir eficácia.
- Windows, PDF, outros provedores, MFA/SSO e multi-workspace.

Versões de dependências seguem os locks atuais; nenhuma atualização foi feita
nesta etapa. O advisory DiskCache revisado permanece visível na auditoria. Ver
[aceite](../product/acceptance-criteria.md) e [roadmap](../product/roadmap.md).

## Registrar o próximo checkpoint

Verifique staged/segredos, execute o check pertinente, commit granular e push
`origin main`. Registre testes realmente executados e a CI do commit correto;
CI de commit anterior não comprova código novo. Preserve árvore/histórico e
informe último hash/mensagem/quantidade/sincronização. Não use branches, PRs,
force push ou mudança de visibilidade para preparar a entrega.
