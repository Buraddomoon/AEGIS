# Revisão do catálogo ATT&CK — 2026-10-23

Escopo: downloader/cache/normalizador, publicação transacional, scopes/worker,
leitura pela API/UI e compatibilidade de recuperação. Sem novo ensaio real,
acesso ao SIEM, execução Atomic, dependência ou backend Sigma novo.

Revisão especializada somente leitura examinou o código e retornou dois
achados médios, corrigidos e testados:

1. O prazo do transporte original não abrangia abertura/headers. Downloader
   agora usa AsyncClient e asyncio.timeout integral, incluindo headers e corpo,
   no orçamento comum de75s. Testes cancelam headers e streaming lentos,
   conferem fechamento do corpo e ausência de continuação do download seguinte.
2. O plano incluía TestDefinition, mas o lock de publicação não cercava uma
   edição concorrente. A tabela agora participa do LOCK NOWAIT; teste com
   outro escritor confirma recusa e estado anterior intacto.

A revisão final conferiu ambas as correções e a recusa de scopes sem contexto
antes de prepare/dispatch, sem novo bloqueador concreto. Essa inspeção não
executou testes, Docker, rede ou arquivos privados; resultados executados são
registrados separadamente no [marco](../evidence/attack-catalog-2026-10-23/README.md).

Controles verificados: destinos HTTPS fixos/commit completo, trust_env=false,
TLS validado, sem redirect/compressão, limites antes/durante o download e parse,
permissões/ownership/links no cache, nomes exclusivos e rehash/renormalização.
Publicado somente sob credencial SQL administrativa, administrador ativo,
plano/destino/estado conferidos e transação. Runtime sem INSERT/UPDATE/DELETE/
TRUNCATE no catálogo; releases com trigger de imutabilidade. Mutações web do
catálogo não existem; leitura exige sessão. Históricos desconhecidos não viram
contexto aprovado, cobertura atual ou evidência nova.

Limites: commit/hash não são assinatura, normalizador cobre um perfil parcial
de STIX, autoridade SQL de implantação pode alterar controles e arquivo privado
não substitui armazenamento criptografado. Atualização requer plano sem runs/
reservas/agendamentos retomáveis; não faz rollback de release nem altera
automaticamente regras/testes. Backup antigo precisa de imagem/schema compatíveis.
Outros controles existentes e advisory transitivo revisado permanecem; não se
declara ausência de vulnerabilidades ou maturidade operacional geral.
