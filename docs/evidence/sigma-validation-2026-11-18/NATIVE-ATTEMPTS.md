# Retomada autorizada da #17/#89 — tentativas encerradas

Operações em18/11/2026, reconferidas em23/11/2026. **INCONCLUSIVE / CLEANED**.
O usuário autorizou a retomada após o bloqueio inicial: “autorizo, pode fazer”.
As mensagens posteriores de continuação mantêm o escopo da #17; não foram usadas
para ampliar a autorização para escrita administrativa na ACL.

Fonte `04e9c01ec2a43145a3f1931a1a0a88d2e95511b2`:
`feat(sigma): add isolated two-phase native query probe (Refs #89)`.
Novo `scripts/sigma_index_probe.py`, com quatro testes em
`tests/test_sigma_index_probe.py`. A coleta precede a revisão física e as queries;
falha de metadata impede a fase de busca. O resultado abaixo não é DETECTED nem
aceite das #87/#88/#89.

## Preparação e certificado

Preflight inicial interrompido antes de criar containers: o certificado original
do Indexer venceu em18/11 às19:50:08UTC. Um leaf temporário separado foi emitido
com a CA válida e a mesma chave, DN e SAN, sem alterar arquivos originais. CA e
chaves nunca foram montadas em conjunto no leitor; só o Indexer recebeu seu par.
O certificado foi selecionado apenas no novo pacote, não na implantação normal.

Leaf DER SHA-256:
`308741cd8e71f4fb91ec4e983e8a99ebfa41a59d53ab54764fea22d1eb5957c8`.
Validade18/11/2026 20:21:03–19/11/2026 20:21:03UTC; está expirado e não pode ser
reutilizado. A CA retida vence23/11/2026 19:50:08UTC; nova operação precisa de
cadeia vigente e pacote novo. Datas atuais não revalidam autorizações consumidas.

Versões positiva/negativa foram importadas/exportadas por API em um schema
PostgreSQL descartável, com UUIDs, conteúdo efetivamente salvo, hashes e artefatos
do conversor fixados. Schema removido; snapshots retidos host-only. Nenhuma regra,
versão ou conta do Demo ou do banco original de Lab foi modificada.

## Tentativas e limites

| Pacote | Horário UTC18/11 | Resultado |
| --- | --- | --- |
| `e9e9013fb83f44de82116f1a95db0188` | 20:23:03.844181–20:23:07.371544 | Containers criados, mas nenhum iniciado. Observador esperava tmpfs em Mounts; Docker o registrou em HostConfig.Tmpfs. INCONCLUSIVE/CLEANED. |
| `db01d45a84734cc0b3451f1a3571933a` | 20:24:41.380512–20:24:58.945020 | Indexer iniciado, TLS/principal/negativas de Security verificados; mapping retornou403. Queries não iniciadas. INCONCLUSIVE/CLEANED. |

Escopos canônicos SHA-256:

- `e9e9013f…`: `c6a96db945f5cdbf626c24d414d0fb1b3b0f71af07402a92b1450abc852c806f`.
- `db01d45a…`: `5886e870e67f9adf9feb86b0ae675ff41b06557f516140f8ad4a5cca1126536b`.

Operadores host-only SHA-256 dos bytes:

- `e9e9013f…`: `679b9a32f693b6ba52f7b18b08b346585ffd675c171214744b1241b60248236c`.
- `db01d45a…`: `5cf867f6fd4bd263ba8c00df05120b40cd37672371f3c1873ea6f7f79853b3ca`.

Cada tentativa tem intent/estado exclusivos;56e82eventos, respectivamente, com
sequência e hashchain reconferidos. Nenhuma foi apagada ou repetida. Escopos foram
registrados na issue antes dos efeitos:
[primeiro](https://github.com/Buraddomoon/AEGIS/issues/89#issuecomment-6990544927),
[continuação após diagnóstico/cleanup](https://github.com/Buraddomoon/AEGIS/issues/89#issuecomment-6990585548).

Imagem Indexer local4.14.9:
`sha256:9c43f316f0a4a15951b8667c0a0f97fc945a9e1ac55035b1be22c95d2b9a04e3`.
Leitores pela imagem retida da #16:
`sha256:8787f04a88472296e175f67cdd0153ac34dbea69459a1e27eb3e73bcae188956`,
com código/probes atuais montadosRO; sem build/pull. Rede própria interna isolada
192.168.253.16/29, sem portas publicadas. Indexer1536MiB/heap512MiB e leitores256MiB
cada, swap adicional zero. Gate2560MiB incluindo reserva512MiB; na tentativa que
iniciou o Indexer, mínimo observado4.848.656.384bytes disponíveis.

## Bloqueio efetivamente observado

O leitor esperou prontidão HTTP503→401 sem credenciais. A verificação de CA/SNI/IP/
fingerprint passou; depois, as leituras autenticadas conferiram `aegis_reader`,
role esperada e negativas de acesso à API Security e ao índice de segurança.
A próxima operação falhou:

```json
{
  "status": "inconclusive",
  "error_type": "HTTPStatusError",
  "http_status": 403,
  "path": "/wazuh-alerts-4.x-2026.11.16/_mapping"
}
```

Não foi coletado mapping. Settings/aliases e as duas consultas Sigma não foram
executados; não se presume seu resultado. Nenhum cursor de consulta Sigma foi
criado. O supervisor registrou a saída não zero do leitor e interrompeu o ensaio;
isso não foi OOM nem falha de detecção. Diagnósticos públicos não contêm corpos
de erro do Indexer, senhas ou tokens.

O escopo prévio dizia **não alterar mapping/ACL para obter aprovação**. Não foram
usadas credenciais administrativas nem feita escrita na configuração Security.
A [proposta mínima de ACL e reversão](../../operations/sigma-metadata-acl-proposal.md)
foi apresentada e autorizada especificamente em23/11, após o usuário escolher
“Autorizar ajuste mínimo e reversão”. O relato acima permanece referente às
tentativas encerradas de18/11; o novo pacote e seu resultado terão registro próprio.

## Encerramento e verificação

Nas duas tentativas: zero containers/redes próprios restantes, nove volumes
preservados/zero consumidores, metadata dos volumes e todos os inputs fonte/
configuração/PKI examinados preservados. Em23/11, a verificação independente
reconferiu sequência/hashchain, hashes dos inputs e zero consumidores dos nove
volumes. Não há igualdade física alegada do volume Indexer: seu startup pode
escrever estado/logs normais.

Zero novos marcadores, runs ou veredictos; sem manager/agente/runner/observador,
banco/API/worker de Lab, ingestão, migração, conta/binding/approval ou implantação.
Demo e qasrc preservados. Pacotes/certificado temporário destas tentativas encerrados;
sem reativação ou operação contínua.

## Testes e CI

67testes locais passaram em19,62s: exportação de versões por API em schema
descartável mais `tests/test_sigma_index_probe.py`, `test_sigma_index.py` e
`test_sigma_validation.py`, com PG/Redis15 em sequência. Credenciais selecionadas
somente no processo; nenhuma alteração em `.env`, contas ou grants. Lint completo
aprovado: Ruff, formatação367Python, mypy, TypeScript/Prettier. A rodada anterior
de37testes de probe/index/TLS é sobreposta, não somável.

[CI04e9c01 /44389850009](https://github.com/Buraddomoon/AEGIS/actions/runs/44389850009)
**SUCCESS**, quatro grupos Python e React conferidos:3847passed/9skips existentes
(962+931+1030+924;2+2+1+4skips),115React/17arquivos. Não se confundem testes em
fixture, CI verde e resultado nativo INCONCLUSIVE. Os commits posteriores deste
relato são documentais; fonte executável preservada.

**#17 e filhos permanecem abertos.** Próxima execução depende da manutenção de ACL
explicitamente autorizada, PKI vigente, pacote/intent novos e revisão física;
o erro403 não autoriza contornar ou enfraquecer os gates.
