# ADR 0027 — Conferência da imagem do runner antes do ensaio

Data: 2026-10-28. Status: ferramentas fixadas e checker implementado/testado em
arquivos temporários; preparação de dependências/base/build real ainda pendentes.

A imagem histórica do Compose tem três labels herdadas. Não adulterar seu config,
remover imagens históricas ou relaxar a validação de cinco labels de ownership.
A nova imagem deve partir da base oficial Python identificada por digest e usar
somente fonte conferida do ADR0026. Build de desenvolvimento não autoriza Lab.

`requirements-image-build.lock` fixa wheels de pip26.2.2/setuptools84.2.1/wheel0.48.0
por SHA256, consultados no PyPI oficial em2026-10-28. Compatíveis com Python3.13,
licenças MIT. Estas ferramentas pertencem ao build, não ao núcleo/API ou lock de
runtime. A auditoria passa a incluir esse lock, sem ignorar achados novos nem
apagar a ressalva conhecida de DiskCache. Hash não substitui assinatura/atestado.

O fluxo a compor prepara wheels com hash antes do build e instala sem índice/rede,
sem build isolation que resolva versões novas implicitamente. Fonte própria é
instalada sem compilação de bytecode, preservando conferência de todos os .py.
Não incluir workspace/secrets, credenciais do Docker ou configurações pip locais
no contexto. Base/receita/contexto/dependências e resultado precisam de recibo.
Nenhum desses efeitos de build foi executado por este ADR/checker.

`runner_image_assert.py` usa stdlib para comparar pacote instalado inteiro com
hashes/tamanhos esperados: recusa extras, faltantes, fonte alterada, symlinks,
hardlinks e bytecode. Confere versões exatas de todos os locks e do projeto.
Entrypoint de check usa somente paths fixos /review e site-packages, sem SQL/rede.
Depois do confronto de fonte/versões, importa sqlalchemy/psycopg e os dois probes,
sem settings/modelos carregados incidentalmente. Saída é resumo/hashes/contagens,
sem código ou segredo. Inputs privados do builder têm limites e leitura nofollow.

Checker positivo comprova esses arquivos/versões/imports naquela imagem; não
comprova sozinho origem da base, ID exportado, daemon, namespace, mount original,
autenticação, autorização ou comportamento em runtime. Seus flags de proveniência/
Lab/autorização continuam falsos. Testes locais usam árvores e versões em fixtures;
imports reais na imagem só serão aceitos após executar o build/check efetivamente.

Fontes oficiais:

- [pip26.2.2 e wheel SHA](https://pypi.org/project/pip/26.2.2/).
- [setuptools84.2.1](https://pypi.org/project/setuptools/84.2.1/).
- [wheel0.48.0](https://pypi.org/project/wheel/0.48.0/).
- [pip secure installs](https://pip.pypa.io/en/stable/topics/secure-installs/).
- [pip install e no-build-isolation](https://pip.pypa.io/en/stable/cli/pip_install/).

## Identificação da base oficial implementada

`runner_image_registry.python_base` consulta somente auth.docker.io e
registry-1.docker.io/library/python, GET/TLS/trust_envfalse/sem redirects, tag fixa
3.13-slim, escopo anônimo pull e token apenas em memória. Não recebe usuário,
registry, URL ou CA livres. Prazo absoluto30s para todo fluxo incluindo corpo,
timeoutsHTTP10s, metadata<=1MiB/resposta e recusa compressão/JSON duplicado.

Confronta Docker-Content-Digest com bytes recebidos do índice/manifesto selecionado;
Linux/amd64 deve ser único. Recusa URIs externas em config/layers, digests/media
incompatíveis, mais de32layers ou256MiB comprimidos. Retorna reference por digest
da plataforma e imageID esperado do config, nunca token. Não baixa layers, não
constrói ou inicia container e não verifica assinatura/atestado. Disponibilidade
local/Python real/proveniência continuam pendentes até pull/conferência/build.

Consulta real somente de metadata em2026-10-28T20:47:47Z identificou43.069.135bytes
comprimidos; recibo privado .local/pki-milestone/python-base-2efd55f3d063461b817a8a8dd3a78755.json.
Isso não constitui autorização de laboratório. Testes usam MockTransport e deadline
real curto; acesso externo somente na consulta explícita host-only registrada.

Fontes oficiais: [Registry token auth](https://docs.docker.com/reference/api/registry/auth/)
e [Distribution HTTP API V2](https://distribution.github.io/distribution/spec/api/).
