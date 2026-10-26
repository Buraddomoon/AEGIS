# Revisão local da consolidação de entrega — 2026-10-26

Inspeção do código e testes pelo agente responsável; não é revisão independente,
pentest ou garantia de ausência de vulnerabilidades. Escopo: init_env, scanners,
workflow documental e descrição do estado atual. API/worker/runner sem alteração.

| Achado | Correção e evidência |
|---|---|
| Gerador seguia symlink e aceitava arquivo público ou configuração com valores vazios/exemplos | Abertura por FD com NOFOLLOW/NONBLOCK, regular/owner/nlink/modo 0600, limite 64 KiB, lock não bloqueante, recusa sem echo/overwrite; 15 casos |
| Histórico sem newline podia concatenar o segredo runtime à linha anterior | Separador explícito, segredo independente aleatório e caso de preservação/idempotência |
| Revisão staged não oferecia inventário de todo o conteúdo rastreado | --all lê o índice completo, nomes NUL-delimitados; 6 casos com conteúdo staged diferente do worktree e nomes com newline |
| Entrega não verificava divergência de versão/lock ou links para arquivos ausentes | Ferramenta offline sobre o índice, com erros sem conteúdo sensível; 9 casos em Git real descartável |
| Documentação operacional conservava estado de Wazuh anterior ao ensaio | Estado atual limitado ao único ensaio 4.14.9 fechado; histórico e autorizações não reescritos |

Uma configuração válida não é modificada pelo gerador; rejeições não corrigem
permissões nem apagam arquivos. Falhas de criação podem deixar arquivo incompleto
que exige revisão local; não há recuperação automática que substitua segredos.
Flock é cooperativo e não protege contra root ou adversário com o mesmo usuário.
O diretório do projeto é confiável; a validação não substitui gestão de configuração
nem valida integralmente toda a gramática dotenv ou a semântica das conexões.

O scanner procura padrões específicos, não todas as formas de segredo. O checker
usa o índice Git, não conteúdo ignorado/não rastreado. Links inline/targets e headers
PNG são validações parciais; revisão humana continua necessária. Não executa links,
comandos de documentos, browser, restore ou downloads.

Workflow documental só usa checkout fixado e Python stdlib, permissões contents:
read, timeout 2 min e concurrency com cancelamento. A CI principal permanece com
PostgreSQL/Redis, lint/testes/build/auditoria; não foi substituída pelo check rápido.
Nenhuma dependência nova ou serviço pago habilitado.

744 testes Python e 53 React locais, lint/build/audit e CI passaram. O advisory
DiskCache/PYSEC-2026-2447 permanece revisado e visível; caminho atual não utiliza o
cache. O aviso TestClient/httpx continua documentado. Fontes:
[evidência desta rodada](../evidence/source-delivery-2026-10-26/README.md) e
[baseline de advisories](dependency-advisories.json).

Custódia externa de backup foi adiada. Não houve upload, novo ensaio real,
rotacionamento de credenciais, mudança de schema ou exposição externa. Os controles
e limites dos ADRs anteriores continuam aplicáveis.
