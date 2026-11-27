# Conexões defensivas — #26

Fonte `b3b00a5` publicada em `origin/main`. #111/#112/#113 implementadas e validadas
offline, com aceite conjunto atendido em27/11. [Provas e limitações](../evidence/defensive-profiles-2026-11-27/README.md).

Catálogo host-only opt-in, referências privadas, perfis conhecidos/hash, revisão,
diagnóstico de um `GET /` e desativação. API não recebe URL/caminho/credencial e
não retorna corpo/versão sensível. Drift invalida revisão/escopo anterior; não há
fallback para ambiente quando catálogo opt-in falha. Rotação de senha exige
incrementar revisão. Nenhuma migração nova ou reescrita de histórico.

CI integral [46007425372](https://github.com/Buraddomoon/AEGIS/actions/runs/46007425372)
SUCCESS na fonteb3b00a5:4255Python/9skips existentes e177React/21glob; quatro
partições Python e React conferidos. Runs intermediárias canceladas por avanço
da fonte não são workflows verdes.

Local74contratos/TLS e95integrações passaram; React177/21glob e componente final9.
Ruff/mypy/TS/format/build/Compose quiet aprovados. Firefox/API/TLS loopback final
`acceptance-iscku_zq` VERIFIED:1440/390px, zero erros JS, uma requisição, vínculo
removido, schema/API/TLS próprios encerrados. Falhas anteriores preservadas.

Sem implantação, ensaio SIEM nativo ou operação Lab. Demo b8 anterior preservado.
Não iniciar laboratórios, reutilizar autorizações antigas ou continuar para outra
entrega. Entrega encerrada; registrar commits/sincronização nas issues e parar.
