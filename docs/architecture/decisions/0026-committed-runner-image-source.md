# ADR 0026 — Contexto privado da fonte versionada do runner

Data: 2026-10-28. Status: exportação/verificação de fonte implementadas e testadas;
build da imagem e comprovação de proveniência continuam separados e pendentes.

A imagem antiga não contém os novos probes. Não usar hash de Dockerfile ou imageID
como prova de que código atual foi instalado, nem mandar o workspace inteiro para
o builder. Preparar um snapshot verificável é pré-requisito do build revisado.

`runner_activation_image_source` é host-only: exige main limpa/HEAD SHA1 explícito,
lê somente blobs do commit e nunca `.env`, arquivos ignorados ou estado de trabalho
como conteúdo. Git local tem ambiente mínimo, sem config global/sistema, hooks,
fsmonitor, replace refs ou recursão em submódulos. Não faz fetch/push/build/pull,
chamada de banco ou Docker. O repositório Git local e seu binário são confiáveis;
não é parser de repositórios enviados por API ou sandbox para Git não confiável.

Allowlist: módulos Python de apps/api/aegis, requirements.lock, pyproject.toml e
labs/linux/Dockerfile. Exigir módulos usados pelos probes; recusar symlinks,
submódulos, executáveis, paths ocultos/inesperados e nomes fora do perfil. Limites:
256 arquivos,1MiB por blob,4MiB de fonte,8MiB de tar; tamanhos são conferidos antes
de solicitar conteúdo, com ID nativo do blob e SHA256 no manifesto. Saída dos
comandos Git confiáveis é capturada com timeout e limite conferido na resposta;
não anunciar sandbox ou limite de memória para um Git/repositório hostil.

Tar USTAR determinístico usa somente arquivos regulares,0644/uidgid0/mtime0, sem
extração em disco. Artefatos privados0700/0600, O_EXCL/O_NOFOLLOW/fsync e verificação
após escrita. Recusar árvore suja ou mudança de commit durante exportação. Falha
conserva resíduos, sem sobrescrita/exclusão automática. Verificação requer SHA de
origem independente e confere manifesto/hash/contexto/tipos/paths/limites; hashes
locais não são assinaturas e não autenticam remetente.

CLI `prepare` só usa o repositório/root fixos; `verify` recebe ID UUIDhex, nunca
path/destino/comando de build livre. Não imprimir conteúdo de arquivos. O Dockerfile
exportado ainda usa a configuração normal do projeto: snapshot não o transforma
em receita offline/pinada, não instala dependências e não comprova build/imports.
Imagem construída deve ser validada separadamente contra fonte/lock/receita/base e
ID imutável, sem labels herdadas incompatíveis com ownership. Recibos sempre
image_built=false/image_provenance_verified=false/effects_authorized=false.

Testes criam repositórios Git descartáveis somente em main, sem remoto. Cobrem
contexto determinístico, ignorados intactos, dirty/staged/untracked/detached,
links/executáveis/paths/limites, mudança de HEAD, tar especial, permissões/fsync,
SHA independente e CLI. Nenhum build ou laboratório real decorre dessa preparação.

## Conferência de imports no build de identidade

O checker instalado agora importa identity_probe/server além dos probes de SQL/
diário e exige require_compatibility do transporte TLS. Não instancia Runner nem
settings, não abre chaves/volumes e não escuta em portas. Módulos aegis.config/
models carregados por efeito colateral bloqueiam o build. Guard de versão é o
mesmo do boot, não uma exceção para empacotamento. Teste em processo separado
confere imports reais com audit hook que recusa rede, processos, mkdir e secrets.
Erro de compatibilidade produz diagnóstico estático sem texto da exceção.
Recibos antigos não são reescritos; fonte nova ainda exige novo build selado.
