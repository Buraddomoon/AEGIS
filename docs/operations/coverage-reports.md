# Cobertura por período/release e exportação

Em **Cobertura de detecção**, escolha ambiente, catálogo e período, depois
**Aplicar recorte**. Alterar campos mantém os indicadores anteriores identificados
como último recorte aplicado e bloqueia comparações/exportação até aplicar.
Falha de atualização ou divergência de referência bloqueia ações e oculta a
comparação cacheada; não usar dados antigos como se fossem uma consulta nova.

Datas na interface usam o fuso do navegador. A API exige RFC3339 com offset e
normaliza UTC: início inclusivo, fim exclusivo, ambos comparados com a **data da
solicitação** (`CampaignRun.created_at`). Não é período de ingestão, conclusão
ou início do processo. Deixar um campo vazio remove somente aquele limite.

| Seleção | Interpretação |
|---|---|
| Todas | Histórico das releases e legado; referência atual para técnicas ativas |
| Atual | Resolve a release vigente no snapshot; apenas runs que registraram seu ID |
| Release histórica | Filtra o ID exato e usa seu documento imutável para técnicas ativas |
| Legado | Scopes sem identidade registrada; versão desconhecida, sem preenchimento retroativo |

O catálogo de referência e os IDs encontrados nos resultados são contagens
distintas. No legado, `catalogued_techniques`/`evaluated_techniques` são `null`;
os IDs históricos continuam visíveis, sem alegar uma versão de catálogo conhecida.
Atualizar metadados não reclassifica veredictos nem confirma detecção.

## Denominadores e snapshot

`total_runs` e `run_states` incluem todos os estados no recorte; resultados e
taxa usam somente pais e filhos COMPLETED. Testes válidos são DETECTED +
OBSERVED_NOT_ALERTED + NO_TELEMETRY. INCONCLUSIVE/EXECUTION_FAILED ficam fora da
taxa. Na ausência de testes válidos, `detected_percentage=null`, nunca zero
por inferência. `unversioned_runs` informa o contexto desconhecido.

Uma transação analítica própria **REPEATABLE READ READ ONLY** lê catálogo,
membros e resultados de forma coerente. Não muda o isolamento da sessão de
autenticação. Timeout SQL15s e máximo5000runs por recorte; exceder o limite
retorna422 e pede redução do período/release, sem truncar métricas silenciosamente.
Não é medição ou promessa de escala. Nenhuma simulação/coleta externa é iniciada.

## Exportar

**Exportar recorte HTML/JSON** entrega seleção canônica, referência resolvida,
denominadores, estados, timestamp do snapshot e membros com run/scope/result IDs
e hashes. A UI envia o hash esperado do recorte; mudança da referência de
catálogo retorna409, exigindo recarga. Novos dados do mesmo recorte podem entrar
no snapshot da exportação: ela é datada e não promete reproduzir uma consulta
anterior ao vivo. Hash de escopo não é token de autorização.

**Comparar execuções** usa opções paginadas de todas as runs concluídas do
recorte, com proteção contra páginas incompletas/misturadas; o segundo lado é
da mesma campanha. Não comparar uma run consigo mesma. Exportação comparativa
HTML/JSON inclui os dois relatórios técnicos completos, evidências/hashes,
diferenças de regras/vínculos/testes/ambiente, resumo e denominadores por lado.

Equivalência exige pais e filhos COMPLETED, manifesto de testes correspondente,
ValidationResult presente, hashes de scope consistentes, mesmo scope e contexto
de catálogo/vínculos registrado. Campo desconhecido não prova igualdade.
Resultados parciais/falhos podem ser inspecionados pela API, mas não sustentam
delta comparável. Delta em pontos percentuais só existe quando os dois
denominadores são válidos e o par é comparável; calcula as frações antes de
arredondar. Mudança de taxa/resultado não demonstra causalidade, comprometimento
ou proteção empresarial. Relatório misto identifica a presença de dados sintéticos.

HTML é autocontido e escapado, sem JavaScript ou recursos externos. Relatórios
individuais existentes mantêm formato e integridade. Exportação é uma projeção,
sem tabela artificial de relatórios nem implantação de regra. Qualquer papel
autenticado consulta/exporta no workspace único; exports têm limite30/min/usuário
e auditoria com tipo/formato/hash, sem senha/token ou payload bruto no log.

## API e verificação do arquivo

```text
GET /api/v1/coverage?mode=demo&catalog_release=current
GET /api/v1/coverage?requested_from=2026-10-01T00:00:00Z&requested_before=2026-11-01T00:00:00Z
GET /api/v1/coverage/runs?catalog_release=legacy&limit=100&offset=0
GET /api/v1/coverage/report?format=json&expected_scope_sha256=SHA256_DO_RECORTE
GET /api/v1/coverage/compare?before=UUID_ANTES&after=UUID_DEPOIS
GET /api/v1/coverage/compare/report?before=UUID_ANTES&after=UUID_DEPOIS&format=html
GET /api/v1/reports?mode=demo&catalog_release=all&limit=100&offset=0
```

Envie os mesmos filtros ao preview/export; `expected_scope_sha256` não substitui
os filtros. Em offsets positivos de timestamp, encode `+` como `%2B`. `all` é o
padrão de catálogo e `demo` o padrão de ambiente, inclusive na lista de relatórios;
relatórios individuais por ID continuam consultáveis independentemente desse filtro.
Release inexistente404, input inválido/limite422, referência alterada409.

`integrity_sha256` dos novos relatórios cobre todo o documento, retirando apenas
esse próprio campo. Serialização determinística AEGIS em UTF8, chaves ordenadas,
sem espaços, Unicode preservado; não é assinatura nem declaração de JSON JCS.
Verificação local com Python, sem acessar a API:

```python
import hashlib, json
from pathlib import Path
payload = json.loads(Path("relatorio.json").read_text(encoding="utf-8"))
expected = payload.pop("integrity_sha256")
encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
assert hashlib.sha256(encoded).hexdigest() == expected
```

Conservar o arquivo original e as evidências. Hash detecta alteração de conteúdo;
não comprova assinatura/origem ou impede um administrador do banco de alterá-lo.
[ADR0015](../architecture/decisions/0015-scoped-coverage-reports.md).
