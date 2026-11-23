# Revisão administrativa ATT&CK — checkpoint #19

Escopo: somente #19/#92/#93/#94. Provas e limitações em
[aceite da revisão administrativa](../evidence/attack-admin-2026-11-23/README.md).
Não usar o PROGRESS inteiro nem o chat para retomar esta unidade.

- #92: API administrativa opt-in de inventário/diff/impacto de planos privados,
  candidatos e hashes revalidados. SQL READ ONLY, limites e cache privado; sem
  download/upload/publicação web ou atualização no startup.
- #93: revisão na matriz para administrador, destino/versão/proveniência/licença,
  antes/depois e testes/escopos afetados, bloqueadores e instrução local exata.
  Drift, erro, paginação/recarga e respostas tardias descartam confirmação.
- #94: CLI real e Firefox sobre API/worker/PG descartáveis, com candidato oficial
 20.0 preexistente, sem fabricar versão nova. JSON/HTML/PDF anteriores idênticos,
  releases preservadas, plano antigo409 e novo plano já aplicado. Correção móvel
  conferida visualmente e por geometria de botões.
- Fonte funcional `57f2bba`, API `a0d39e2`, UI `5509192`.97Python locais pertinentes,
 125React/18arquivos,21casos do glob; lint/tipos/formatação/build aprovados.
- Schema temporário removido, processos próprios encerrados e cache original
  preservado. Demo anterior ready200, API/worker na imagem b8abe5e44af4,
  sem implantação desta feature nem operação Linux/Wazuh. Versão do produto0.2.0.

Configuração e procedimento: [guia MITRE](../integrations/mitre-attack.md).
Roteiro reproduzível e distinção entre fixtures e candidato oficial:
[testes](testing.md). Nenhuma autorização operacional de laboratório é concedida
por este checkpoint.

CI integral[45199031895/attempts/2](https://github.com/Buraddomoon/AEGIS/actions/runs/45199031895/attempts/2)
SUCCESS na fonte57f2bba: quatro partições Python,3877passed/9skips opcionais
existentes,125React/18arquivos e21casos do glob. A primeira tentativa falhou por
contenção SQLite em fixture Linux; a falha e a rechecagem local separada2/2 estão
preservadas nas provas. Nenhum gate/timeout/filtro ou arquivo do Journal mudou.
Os520inputs não Markdown continuam idênticos à fonte testada após a consolidação
documental. Critérios conjuntos da #19 atendidos; entrega encerrada em23/11.
**Parar sem iniciar outra entrega ou implantação.**
