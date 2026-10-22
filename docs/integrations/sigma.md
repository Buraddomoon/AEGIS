# Sigma / pySigma

Fonte: [pySigma oficial](https://github.com/SigmaHQ/pySigma). AEGIS utiliza SigmaCollection.from_dicts da versão 2.0.1, após SafeLoader, limite de 64 KiB, complexidade limitada, profundidade máxima32 e bloqueio de âncoras/aliases. Um documento/regra por importação; UUID obrigatório. Tags `attack.tNNNN(.NNN)` precisam existir no catálogo.

Nova importação do mesmo UUID cria versão imutável; conteúdo idêntico é idempotente. UI apresenta YAML, técnicas, hash e comparação visual entre versão anterior/atual. Não há tradução, execução de consultas ou implantação automática. O snapshot de execução registra versões do inventário para contextualizar comparações; isso não significa que essas regras foram implantadas.

Sintaxe válida não comprova semântica, cobertura ou compatibilidade Wazuh. Conversão futura exige backend/pipeline oficialmente compatíveis e prova num laboratório autorizado. Associação revisada regra/teste é operacional como metadado de planejamento, com versões fixas, retirada e histórico. [Operação e API](../operations/rule-test-reviews.md). Análise estática parcial está disponível abaixo; semântica completa, conversão e implantação continuam no roadmap.

Dependência pySigma é LGPL-2.1-only e permanece biblioteca separada, sem código copiado/modificado. Regras importadas mantêm licença de seus autores. DiskCache 5.6.3 é uma dependência transitiva com advisory conhecido sem patch; AEGIS não importa nem usa seu caminho de cache. A auditoria mantém a ocorrência visível e testa essa premissa; habilitar plugins/cache exige nova revisão.

## Análise estática de versões

Em **Regras → Análise estática**, selecione uma versão salva. A API
`GET /api/v1/rules/{rule_id}/versions/{version_id}/analysis` exige sessão,
aceita viewer e limita a 60 consultas por usuário/minuto (Redis; indisponibilidade
retorna503). Não recebe comandos, destinos, plugins, consultas ou pipelines.
Confere SHA-256 antes do parser; divergência retorna409. Conteúdo legado inválido
ou além do orçamento de análise retorna422, sem exceção bruta.

Analisador `sigma-static/1`, pySigma2.0.1: resolve condições com o parser oficial
e aplica cinco checks AEGIS explícitos: referências inválidas, seleções não
referenciadas, campo com all sem contains, curingas consecutivos e caracteres
de controle. Os últimos checks sugerem revisão; valores intencionais podem gerar
achados. Não são uma avaliação completa da semântica. Se uma condição não for
resolvida, o check de seleção não referenciada é marcado como não executado.
Limites adicionais: 32 condições, 2048 caracteres por condição, 128 seleções;
limites YAML de importação continuam aplicáveis. Antes do parser, importação e
análise compartilham preflight: até 6 modificadores sem repetição por campo,
estimativa conservadora máxima de 256 KiB por valor expandido, 1 MiB total e
4096 variantes. Encodings, base64offset e windash entram na estimativa; não é
medida de RAM total. Regras legítimas com cadeias maiores podem ser recusadas. Presença de filter,
correlation ou action é recusada antes do dispatch; detection precisa ser objeto,
pois esta versão só aceita regras individuais.
Versões antigas fora dessa política permanecem armazenadas, mas análise retorna422.
A política depende dos modificadores da versão pySigma fixada e exige revisão
antes de upgrades; não executar payload grande para testar o limite.

Resposta identifica rule_id, rule_version_id, número/hash da versão, versões do
analisador/pySigma, checks executados/omitidos, fatos e achados ordenados.
Fatos são campos **declarados**, logsource, seleções e condições; não representam
campos disponíveis no SIEM. Prioridade LOW/HIGH refere-se à revisão da regra,
não a risco de negócio. `no_findings_in_selected_checks` não significa regra
correta, compatível ou eficaz. Conteúdo histórico não é alterado; uma análise é
calculada sob a versão atual identificada do analisador, sem persistir cache nem
reescrever escopos, vínculos, aprovações, relatórios ou veredictos.

A UI consulta a versão exata e confere identidade/hash da resposta. Consulta
pendente de outra versão não pode aparecer sob a seleção atual. Falha de consulta
não é apresentada como análise sem achados.

### Conversão e compatibilidade

Estado atual: `not_configured`, backend/pipeline null, conversão/implantação false.
A [documentação oficial de backends](https://sigmahq.io/docs/digging-deeper/backends)
lista OpenSearch; [pipelines](https://sigmahq.io/docs/digging-deeper/pipelines)
tratam mapeamentos de campos/fontes. Isso não comprova compatibilidade com o schema
Wazuh, emissão de regra XML ou implantação no manager. Nenhum backend foi instalado
ou executado nesta etapa. Revisão de um pipeline e validação de sua saída são
pré-requisitos futuros; execução contra laboratório exige seu escopo autorizado.

Decisão e descoberta de importação transitiva:
[ADR0008](../architecture/decisions/0008-sigma-static-analysis.md). Não importar
`sigma.validators.core`: seu inicializador descobre módulos e carrega loaders de
dados com DiskCache. AEGIS usa diretamente o parser/modelo e checks locais, sem
copiar validadores upstream ou enfraquecer a regressão de ausência de DiskCache.
