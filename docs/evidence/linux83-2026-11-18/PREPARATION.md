# Preparação concreta da #83 — 18/11/2026

Escopo exclusivo #83, dependência #82 fechada e pai #15 aberto. Pedido de retomada
recebido após encerramento da preparação anterior; não há autorização histórica
reutilizada. [Proposta concreta a aprovar](../../../labs/linux/LINUX83-REQUEST-2026-11-18.md)
e [procedimento](../../operations/linux83-assay.md).

## Fonte e validação

Commit `1dcff254b7af0e699676cdfcbfd1508e9f747cec`,
`feat(linux): prepare closed native assay profiles and isolated packages (Refs #83)`,
enviado a origin/main. Coordenador/cliente/helper existentes compartilhados, com
dois perfis fechados novos, bancos/owners/namespaces próprios e revisões fixadas;
defaults históricos Atomic preservados. Programas/revisões da #82 não mudaram.
Não se adicionaram alvos ou comandos livres à API.

Testes locais efetivos: `pytest tests/test_atomic_assay.py tests/test_linux83_assay.py -q`
64passed em1,48s; `pytest tests/test_linux_campaigns.py -q`73passed em132,42s,
PG/schema descartável e Redis15, testes locais sequenciais. Incluem autorização
ausente/divergente, fence consumido, perfil/envelope/banco incorretos, revisão
alterada, recuperação/recolhimento e controlador API/worker dos três perfis com
start perdido sem replay. `make lint` passou; Ruff/format357arquivos reconferidos.
Uma rodada anterior de120passed inclui57testes de programas e sobrepõe outros
conjuntos; não somar rodadas como testes distintos. Aviso Starlette/httpx conhecido.

[CI integral44317530894](https://github.com/Buraddomoon/AEGIS/actions/runs/44317530894)
SUCCESS na fonte exata acima; cinco jobs e resumos dos logs conferidos:

| Job | Passed | Skipped | Selecionados |
| --- | ---: | ---: | ---: |
| Python0 | 937 | 2 | 939 |
| Python1 | 869 | 2 | 871 |
| Python2 | 1003 | 1 | 1004 |
| Python3 | 924 | 4 | 928 |
| Total Python | 3733 | 9 | 3742 |
| React | 98 | 0 | 98 |

Nove skips opcionais existentes: grupo0projeção de imagem/ausência DemoAPI;
grupo1ferramentasPG/ausência DemoDB; grupo2ausência de rede Demo; grupo3quatro
inspeções Wazuh sem objetos próprios. Nenhum recurso criado para passar esses
gates, nenhum filtro/exclusão/relaxamento ou mudança em SHARDS/PINNED/timeout.
Lint/tipos/build/auditorias do workflow aprovados; não representam ausência de
qualquer vulnerabilidade. [Revisão da fonte44317530758](https://github.com/Buraddomoon/AEGIS/actions/runs/44317530758)
também SUCCESS. Consolidação posterior só Markdown; inputs executáveis idênticos.

## Builds próprios e propostas offline

Exportação conferida de84blobs de Git;48wheels/30.384.557bytes com hashes/locks
fixados, sem instalar pacotes no host. Base Python oficial imutável já local e
base própria da aplicação retidas, sem pull/push ou substituir tags históricas.
RUNs do build sem rede, checks frescos de fonte/pacote instalado/versões/imports
e assets do helper aprovados. Novos IDs:

- Runner: `sha256:8b173422b000caa26b95b1c2ecd557fae14ef4e49a108f1588115067d48e46d0`,
  contexto/build `ebc43ab5a9964efcb54f9b84cfdb1726`.
- Aplicação: `sha256:b25b2bc0fdc4483c0cd940fa4dc4d2b66ae2d53c643166e979a6b2782003c062`,
  build `bc9b13a62eee4d0f9e27b5eebddff9a2`.

Receitas/propostas `0a85302e48bc4ecb9f854ba3881f89c0` e
`22431af466174de6ab37ae9261d1c672` foram criadas e verificadas pelo coordenador,
com hashes/IDs/imagens/janelas na proposta pública. Compose somente renderizado.
PKIs separadas conferidas offline com OpenSSL, propósito cliente/servidor,
CA e IP192.168.253.2. Folhas até20/11/2026; não é handshake nativo.
Preflight RO de redes/rotas sem sobreposição; ausência de containers/redes/volumes
dos projetos novos confirmada por labels. Nenhum original montado ou consultado.

Cada projeto poderá criar banco c8/36tabelas e três volumes novos, após aprovação;
sem bootstrap/seed/migração já executados em ambiente nativo. Duas tentativas
independentes/sequenciais, com seis volumes finais retidos e nenhum replay.
Na verificação, **ambos sem authorization.json/attempt.json**.

RAM inicial2819MiB abaixo do piso; depois3574MiB disponível, sem alterar host,
swap/sysctl ou parar outros projetos. Piso3072MiB mantido e rechecado antes de
cada início. Um recheck negativo não é autorização para diminuir o piso.

## Pendente

Aprovação humana dos dois hashes da proposta, não existente nesta preparação.
Nenhuma campanha/Lab iniciados, nenhum efeito executado e nenhum ensaio real
declarado. Resultado nativo esperado INCONCLUSIVE por ausência explícita de
coletor/regra defensiva; recibo/stdout não serão eventos ou alertas. Nenhuma
imagem foi implantada em Demo/originais, nenhuma PKI original/volume/binding/
conta antiga alterados. Provas privadas/segredos/logs ficam locais protegidos.

O pedido de início da issue não foi convertido em autorização de um pacote
inexistente no momento do pedido. Agora os pacotes são concretos e revisáveis;
operação aguarda aprovação específica, vigência e gates. #83 permanece aberta,
sem aceite nativo; pai #15 não é fechado nesta sessão de preparação.
