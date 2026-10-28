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

## Cache de wheels implementado

`runner_image_wheels` vincula source-ID/SHA conferido ao runtime.lock do tar e ao
build.lock obtido do Git HEAD/main limpo. CLI não recebe URL, path, comando ou
versão livres. Inputs precisam de pins/hashes exatos e perfis sem sobreposição.

Downloader é apenas python-I-mpipdownload do venv, PyPI fixo, onlybinary/requirehashes/
nodeps/isolated/nocache/noinput/keyringdisabled. Ambiente mínimo, configurações pip e
.netrc apontam para /dev/null; não herda proxies, tokens ou credenciais. Não instala
pacotes nem executa sdists. Deadline120s/log4MiB e kill/reap do filho próprio,
umask077 e diretório0700 por operação. Resíduos de falha não são apagados/reutilizados.

Depois do download, validar arquivos regulares0600/link único, nomes/versões de
wheel e SHA dos locks; limites por arquivo32MiB e total128MiB são verificados no
cache após o pip, não cota de disco durante transferência. Contagem precisa ser
exata. Artefatos/plan/receipt são exclusivos com fsync; reload exige SHA independente,
relê locks e hashes de todas as wheels e recusa extras/alterações/links. Recibos
não afirmam instalação/build/proveniência de imagem ou autorização de Lab.

Testes usam bytes sintéticos com nome de wheel para provar o contrato de hash,
sem afirmar que constituem pacote instalável. Child real local cobre transporte/
deadline/overflow/reap, nunca pip/rede no pytest. CLI é exercitada com repo Git
main descartável e fonte/locks próprios. Build/imports reais ainda separados.

## IDs nativos e config digest são contratos separados

Consulta/build de desenvolvimento local identificou Docker29.8.1/API1.56 com store
containerd: imageinspect.Id referencia manifesto/índice. Não confundir com digest
do config OCI. Registry receipt passa a /2 com `config_digest`; a antiga /1 e seus
recibos permanecem intactos, sem serem aceitos como contrato /2 por conversão cega.

`runner_image_base` só inspeciona a referência oficial fixa por digest. Exige
RepoDigests correspondente, Linux/amd64, root base e ausência de VOLUME/EXPOSE/
ONBUILD/labels. Perfil containerd exige Id e Descriptor.digest iguais ao manifesto
da plataforma e mediaType correto; perfil legacy separado aceita Id=config_digest
somente sem Descriptor. Não aceitar mistura arbitrária, tag ou terceiro digest.
Checker/runtime/imports continuam separados e todos os flags de build/proveniência/
autorização permanecem falsos. Campos extras de receipt, inclusive tokens, recusam.

Pull explícito somente da base Python43MB foi feito como preparação de build de
desenvolvimento, sem create/start/exec de containers. A primeira comparação falhou
por assumir configID; falha e intent preservados. Nova consulta /2 e inspeção nativa
conferiram o manifesto aaf08c5490d52cd92bc27142a5215b1e47355a5eaf9adfad2a0fbc022d0b5490
separadamente do config bdfc738a8a869292ec1b01f1b8e620db533e09d1fe68fe980a7118b22dae9cec.
Isso não é dispensa de verificação nem ensaio autorizado.

Fontes: [Docker containerd store](https://docs.docker.com/engine/storage/containerd/),
[Moby imageinspect](https://github.com/moby/moby/blob/master/daemon/containerd/image_inspect.go)
e [Engine29 release notes](https://docs.docker.com/engine/release-notes/29/).
