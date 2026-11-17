# Instalação Demo nova e percurso completo — #73, 16/11/2026

[#72](https://github.com/Buraddomoon/AEGIS/issues/72) concluída antes dos efeitos.
Fonte fixada `590b0ea` (apenas Markdown após a fonte executável `a8db6da`).
Código0.2.0, sem branches/tag Git/release ou laboratório real. O ensaio é Demo
sintético; nenhuma contagem abaixo mede proteção defensiva de uma organização.

## Instalação em ambiente descartável

A fonte foi exportada por `git archive HEAD` para diretório novo privado, sem
copiar `.env`, `.local`, dados ou configuração do Demo ativo. O gerador
`python3 scripts/init_env.py`, executado nessa cópia, criou `.env`0600 com três
segredos novos. Origem alterada somente nessa cópia para `http://localhost:18786`.
Não se usou `.env.example`, reset da fonte ou credencial padrão.

Antes do build, o Demo existente foi inventariado e a referência
`aegis-preserved:issue12-20261116-b8abe5e44af4` foi conferida contra seu ID
`sha256:b8abe5e44af4bad90d2e302a045f38fb9cf268932be5ea0493fc72f078657a23`.
Essa tag retém a imagem; a tag original não foi reutilizada pelo build.

Compose padrão, com projeto exclusivo `aegis-issue12` e este override:

```yaml
services:
  migrate:
    image: aegis-issue12:590b0ea
  api:
    image: aegis-issue12:590b0ea
    ports: !override ['127.0.0.1:18786:8080']
  worker:
    image: aegis-issue12:590b0ea
```

O comando base foi `docker compose --env-file <cópia>/.env -p aegis-issue12
-f <cópia>/docker-compose.yml -f <override>`. Antes dos efeitos, o render JSON
confirmou exatamente db/redis/migrate/api/worker, somente porta loopback18786,
sem portas PG/Redis, runner, coletor SIEM ou configuração Linux/Wazuh. Filtros
por label confirmaram ausência prévia de containers/redes/volumes desse projeto.

Comandos realmente executados sobre esse projeto novo:

1. `build --pull=false migrate`: build Docker/frontend/locks concluído, imagem
   local `sha256:1c7da571dfd19586a1f274c091d0e69c7b2cf55354d6656cf40f49629ef190c5`.
2. `up -d --no-build --pull never --wait --wait-timeout 150`: migração/seed/grant
   runtime concluídos; health ready retornou database=true/redis=true.
3. SQL antes do bootstrap: schema `b7f3c2d91a06`,33tabelas,0usuários/0runs.
4. `run --rm --no-deps -T migrate python -m aegis.cli bootstrap`: conta nova com
   senha aleatória por stdin, sem persistir senha. O CLI solicitou confirmação.
5. API/worker inspecionados: mesma imagem nova, UID10001, read-only, cap_dropALL,
   no-new-privileges e nenhum socket Docker. Credencial runtime distinta da migração.
6. `node e2e.mjs` no frontend dessa cópia, Firefox real, conta do bootstrap e
   origem18786; sem mocks. Dependências locais de navegador vieram do node_modules
   existente, cujo lock é o mesmo. A SPA/API/worker utilizados são os da imagem nova.

## Resultado no Compose

**PASS**,5runs/20testesDemo/2snapshotsREADY/4PDFs/14capturas/0errosJavaScript.
A consulta SQL final confirmou5runs,20filhos,2READY e0filhos não sintéticos.

O percurso existente `apps/web/e2e.mjs` verificou login, proveniência ATT&CK,
campanha/escopo/aprovação/worker, evidência synthetic=true, resultados e taxa1/3,
repetição com nova aprovação, comparação delta0, recorte2runs/6válidos, filtros
legado/período vazio, agendamento aprovado com duas ocorrências/cadência real60s,
snapshots inicial/comparativo e preservação após revisão/versão/retirada Sigma.
Também abriu páginas auxiliares e verificou390px sem overflow global, inclusive
layout do relatório automático. Não se reduziram cadência, guardas ou timeouts.

Inspeção visual das capturas reais `execution.png`, `scheduled-reports.png` e
`mobile.png`: classificações/denominadores e avisos sintéticos legíveis; layout
móvel empilhado, tabelas com rolagem interna. As14capturas ficam privadas em
`.local/issue12/screenshots-compose`; nenhuma imagem histórica foi substituída.
Isso é revisão do percurso coberto, sem alegação de teste exaustivo de toda UI.

GETs autenticados complementares, por outra conta nova do mesmo CLI, validaram
**5HTMLs200**: execução, recorte, comparação e ambos os snapshots, com MIME HTML
correto e aviso sintético. As credenciais ficaram somente em memória/stdin;
HTMLs e logs ficam privados, sem publicar payloads de runtime. JSONs e os quatro
PDFs foram exercitados pelos botões reais do E2E. HTML complementar foi validado
pela API, distinguindo-o dos cliques de JSON/PDF.

Parser independente pypdf leu os quatro PDFs baixados no Compose e confirmou
aviso sintético em **todas** as páginas:

| Documento | Páginas | Bytes | SHA256 dos bytes |
|---|---:|---:|---|
| Execução | 13 | 67135 | `165adb0700101fcba1efca733c683053f0350e30e21271b0bbeb18d466b0d05d` |
| Recorte | 4 | 51777 | `7ba8f6ef7d6ae9fb39922be03acfddbcee436d3b4c833fbf55bc357be125d728` |
| Comparação | 27 | 93521 | `c416320ffd58df3d768bf4088904484e1014d310827aa96e9d62c6ffcbd04f19` |
| Snapshot comparativo | 28 | 96127 | `6baef1fa9a4ea3523319e95e26e01dd298a69831e9776df5b7d9e7a424ae4dc1` |

Hashes não são assinaturas. Arquivos privados retidos em `.local/issue12/compose-pdfs`.

## Cleanup e preservação

`down --volumes --remove-orphans` foi aplicado **somente ao projeto novo**, em
finally. Conferência por labels:0containers/0redes/0volumes remanescentes.
A imagem nova foi retida em tag exclusiva; nenhum prune ou remoção de terceiros.

O inventário completo do Demo fonte permaneceu idêntico antes/depois:33tabelas/
3399linhas e hashes de todas as linhas, schema b7, cinco objetos de container
(inclui migrate parado), IDs/imagens/mounts/estados, imagem default e hash do
`.env` deste checkout. Inventários completos/logs/harnesses ficam em
`.local/issue12`, sem dump ou credencial em Git. Nenhum volume Linux/Wazuh,
qasrc, PKI, journal, candidato, intent ou fence foi alterado.

## Reprodução e limites

Para uma instalação nova comum, seguir [README](../../../README.md#executar-localmente)
e [operação local](../../operations/deployment.md): clone novo, `make up`,
`make bootstrap`, percurso Demo. Para coexistir com outra instalação, usar projeto,
imagem e porta exclusivos como acima, configuração própria e volume novo;
nunca aplicar o cleanup deste exemplo ao projeto existente. Antes de build,
preservar a imagem atual em tag dedicada. Não iniciar laboratórios reais.

Este ensaio usa caches de build/dependências já presentes e acesso às fontes de
pacotes; não é teste air-gapped ou em outro host/arquitetura. Os bancos/segredos
novos não foram derivados de backup. O Demo persistente continua na imagem b8,
sem atualização/migração ou reinício por esta entrega. A imagem atual foi testada
somente no ambiente temporário, depois encerrado. Sem nova release publicada.

## Caminho documentado de desenvolvimento

Após encerrar o Compose, executado `make -C .local/issue12/install e2e`, com
`AEGIS_E2E_SCREENSHOTS` apontando para diretório privado separado e wrapper
passando em memória as credenciais dos PG/Redis locais existentes. A cópia usa
`.venv`/`node_modules` locais já instalados; os inputs executáveis correspondem
à fonte fixada. O gerador/configuração e o build Docker anteriores são a prova
da instalação nova; esta rodada adicional verifica o harness de desenvolvimento.

Build Vite aprovado (2,79s); **PASS**,5runs/20testesDemo/2snapshots/4PDFs/
14capturas/0errosJavaScript. É outra rodada em schema próprio, não20testes novos
adicionados à contagem do Compose. O finally removeu API/worker e schema E2E;
conferência final:0schemas `aegis_e2e_%`, nenhuma porta18784/18786 escutando.
Capturas/artefatos do Compose foram preservados separadamente antes desta rodada.
Nenhum erro ou correção de código foi necessário nos dois percursos da #73.

Retomada em17/11 às12:25UTC: inventário completo da fonte reconferido, ainda
idêntico ao anterior aos ensaios de16/11. O encerramento documental ocorre em17/11;
as execuções acima continuam datadas16/11, sem atribuir testes novos à retomada.
